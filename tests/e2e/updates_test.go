package e2e_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What the PostgreSQL store enforces, held in memory: roots and catalogs only
// move forward, a catalog names only packages it was given, and a package is
// handed only to an agent asked to run a version the newest catalog names it
// for, by an assignment or by its tenant's rollout.
type publishedUpdates struct {
	mutex    sync.Mutex
	agents   *registeredAgents
	roots    []agentupdate.AcceptedRoot
	packages map[string][]byte
	catalogs []agentupdate.AcceptedCatalog
	assigned map[string]string
	rollouts *startedRollouts
}

func newPublishedUpdates(agents *registeredAgents) *publishedUpdates {
	return &publishedUpdates{agents: agents, packages: map[string][]byte{}, assigned: map[string]string{}}
}

func (p *publishedUpdates) state(id string) (string, agent.State, bool) {
	p.agents.mutex.Lock()
	defer p.agents.mutex.Unlock()
	held, known := p.agents.held[id]
	if !known {
		return "", "", false
	}
	state, _ := agent.FromWire(held.GetState())
	return held.GetTenantId(), state, true
}

func (p *publishedUpdates) Roots(_ context.Context, after uint64) ([][]byte, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var served [][]byte
	for _, root := range p.roots {
		if root.Root.Version() > after {
			served = append(served, root.Root.Served())
		}
	}
	return served, nil
}

func (p *publishedUpdates) PublishRoot(_ context.Context, accepted agentupdate.AcceptedRoot) (*updatev1.PublishedRoot, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.roots) > 0 && p.roots[len(p.roots)-1].Root.Version() >= accepted.Root.Version() {
		return nil, agentupdate.ErrStale
	}
	p.roots = append(p.roots, accepted)
	return accepted.Record, nil
}

func (p *publishedUpdates) PublishPackage(_ context.Context, accepted agentupdate.AcceptedPackage) (*updatev1.PublishedPackage, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.packages[hex.EncodeToString(accepted.Record.GetSha256())] = accepted.Content
	return accepted.Record, nil
}

func (p *publishedUpdates) PublishCatalog(_ context.Context, accepted agentupdate.AcceptedCatalog) (*updatev1.PublishedCatalog, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.catalogs) > 0 && p.catalogs[len(p.catalogs)-1].Catalog.Version() >= accepted.Catalog.Version() {
		return nil, agentupdate.ErrStale
	}
	for _, named := range accepted.Packages {
		if content, given := p.packages[hex.EncodeToString(named.Sha256)]; !given || uint64(len(content)) != named.Size {
			return nil, fmt.Errorf("%w: %x", agentupdate.ErrNoPackage, named.Sha256)
		}
	}
	p.catalogs = append(p.catalogs, accepted)
	return accepted.Record, nil
}

func (p *publishedUpdates) newest() *agentupdate.Catalog {
	if len(p.catalogs) == 0 {
		return nil
	}
	return p.catalogs[len(p.catalogs)-1].Catalog
}

func (p *publishedUpdates) Assign(_ context.Context, accepted agentupdate.AcceptedAssignment) (*updatev1.Assigned, error) {
	for _, id := range accepted.AgentIDs {
		if tenant, _, known := p.state(id); !known || tenant != accepted.TenantID {
			return nil, fmt.Errorf("%w: %s", agentupdate.ErrUnregistered, id)
		}
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if accepted.Version != "" && (p.newest() == nil || !p.newest().Names(accepted.Version)) {
		return nil, fmt.Errorf("%w: %s", agentupdate.ErrUncataloged, accepted.Version)
	}
	for _, id := range accepted.AgentIDs {
		if accepted.Version == "" {
			delete(p.assigned, id)
		} else {
			p.assigned[id] = accepted.Version
		}
	}
	return accepted.Record, nil
}

func (p *publishedUpdates) names(version string) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.newest() != nil && p.newest().Names(version)
}

func (p *publishedUpdates) assignedTo(agentID string) string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.assigned[agentID]
}

// What an agent is asked to run: its assignment, or else what its tenant's
// rollout asks of it.
func (p *publishedUpdates) wanted(tenant, agentID string) string {
	var (
		rollout *updatev1.RolloutRecord
		member  bool
	)
	if p.rollouts != nil {
		rollout, member = p.rollouts.inForce(tenant, agentID)
	}
	return agentupdate.Wanted(p.assignedTo(agentID), rollout, member, agentID)
}

func (p *publishedUpdates) Served(ctx context.Context, agentID string, after uint64) (agentupdate.Served, error) {
	tenant, state, known := p.state(agentID)
	if !known {
		return agentupdate.Served{}, agent.ErrUnknown
	}
	roots, err := p.Roots(ctx, after)
	if err != nil {
		return agentupdate.Served{}, err
	}
	version := p.wanted(tenant, agentID)
	p.mutex.Lock()
	defer p.mutex.Unlock()
	served := agentupdate.Served{State: state, Roots: roots, Version: version}
	if newest := p.newest(); newest != nil {
		served.Catalog = newest.Served()
	}
	return served, nil
}

func (p *publishedUpdates) Package(_ context.Context, agentID string, digest []byte) (agentupdate.ServedPackage, error) {
	tenant, state, known := p.state(agentID)
	if !known {
		return agentupdate.ServedPackage{}, agent.ErrUnknown
	}
	if !state.Admits() {
		return agentupdate.ServedPackage{State: state}, nil
	}
	version := p.wanted(tenant, agentID)
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if newest := p.newest(); newest != nil && newest.Names(version) {
		for _, release := range newest.Releases() {
			if bytes.Equal(release.GetPayload().GetSha256(), digest) {
				return agentupdate.ServedPackage{State: state, Content: p.packages[hex.EncodeToString(digest)]}, nil
			}
		}
	}
	return agentupdate.ServedPackage{}, agentupdate.ErrUnknown
}

func updateSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an update key: %v", err)
	}
	return key
}

func updateRootSigned(t *testing.T, version uint64, owner *ecdsa.PrivateKey, signers ...*ecdsa.PrivateKey) *updatev1.Envelope {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&owner.PublicKey)
	if err != nil {
		t.Fatalf("encode an update key: %v", err)
	}
	id := agentupdate.KeyID(der)
	signing := make([]crypto.Signer, 0, len(signers))
	for _, key := range signers {
		signing = append(signing, key)
	}
	envelope, err := agentupdate.Sign(&updatev1.Root{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(time.Now().Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(time.Now().Add(30 * 24 * time.Hour)),
		Keys:          []*updatev1.Key{{Keyid: id, PublicKey: der}},
		Root:          &updatev1.Role{Keyids: []string{id}, Threshold: 1},
		Catalog:       &updatev1.Role{Keyids: []string{id}, Threshold: 1},
	}, agentupdate.RootPayloadType, signing...)
	if err != nil {
		t.Fatalf("sign root %d: %v", version, err)
	}
	return envelope
}

// The root the control plane is configured with and every agent is provisioned
// with, as the bytes of its envelope.
func firstUpdateRoot(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key := updateSigningKey(t)
	served, err := agentupdate.Encode(updateRootSigned(t, 1, key, key))
	if err != nil {
		t.Fatalf("encode the first update root: %v", err)
	}
	return key, served
}

func releaseCatalog(t *testing.T, version uint64, key *ecdsa.PrivateKey, releases ...*updatev1.Release) *updatev1.Envelope {
	t.Helper()
	envelope, err := agentupdate.Sign(&updatev1.Catalog{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(time.Now().Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(time.Now().Add(7 * 24 * time.Hour)),
		Releases:      releases,
	}, agentupdate.CatalogPayloadType, key)
	if err != nil {
		t.Fatalf("sign catalog %d: %v", version, err)
	}
	return envelope
}

func releaseOfPackage(version string, content []byte) *updatev1.Release {
	sum := sha256.Sum256(content)
	return &updatev1.Release{
		Version:       version,
		Platform:      &updatev1.Platform{Os: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB},
		Payload:       &updatev1.Payload{Sha256: sum[:], Size: uint64(len(content))},
		Source:        &updatev1.Source{Repository: "github.com/dynasmon/Seagull-agent-v2", Revision: strings.Repeat("ab", 20)},
		Compatibility: &updatev1.Compatibility{StateGeneration: 1},
	}
}

func (c *controlPlane) give(t *testing.T, client *http.Client, token string, content []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://"+c.address+control.UpdatePackagesPath, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", control.PackageContentType)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("give the package: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func (c *controlPlane) agentGet(t *testing.T, client *http.Client, path, tag string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+c.renewalAddress+path, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if tag != "" {
		request.Header.Set("If-None-Match", tag)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("ask %s: %v", path, err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return response, body
}

func expect(t *testing.T, response *http.Response, body []byte, status int, what string) {
	t.Helper()
	if response.StatusCode != status {
		t.Fatalf("%s was answered %d: %s", what, response.StatusCode, body)
	}
}

// Over real mutual TLS: an operator rotates the update root, gives the
// platform two packages, publishes a catalog naming both and assigns the later
// version to one agent; that agent, starting from the root it was provisioned
// with, verifies the chain and the catalog and downloads exactly the bytes the
// catalog names for the release it is to run and the one it would go back to,
// while an agent assigned nothing is handed nothing.
func TestAnAgentIsOfferedAndHandedAReleaseAnOperatorAuthorizedOverRealMutualTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	token := plane.open(t, operator).GetToken()
	plane.register(t, operator, token, "e2e-agent-90")
	plane.register(t, operator, token, "e2e-agent-91")
	key, requestPEM := keyAndRequest(t, "e2e-agent-90")
	assigned := plane.agentClient(t, key, plane.issue(t, operator, token, "e2e-agent-90", requestPEM))
	otherKey, otherRequest := keyAndRequest(t, "e2e-agent-91")
	unassigned := plane.agentClient(t, otherKey, plane.issue(t, operator, token, "e2e-agent-91", otherRequest))

	response, body := plane.agentGet(t, assigned, control.UpdatePath, "")
	expect(t, response, body, http.StatusOK, "asking before anything was published")
	var offer updatev1.Offer
	if err := proto.Unmarshal(body, &offer); err != nil || len(offer.GetRoots()) != 1 || offer.GetCatalog() != nil || offer.GetVersion() != "" {
		t.Fatalf("before anything was published the agent was offered %v: %v", &offer, err)
	}

	rotated := updateSigningKey(t)
	response, body = plane.send(t, operator, http.MethodPost, control.UpdateRootsPath, token,
		&updatev1.RootPublication{Root: updateRootSigned(t, 2, rotated, plane.updateKey, rotated)})
	expect(t, response, body, http.StatusCreated, "publishing root 2")
	running, content := []byte("!<arch>\ndebian-binary   the package of v0.1.0"), []byte("!<arch>\ndebian-binary   the package of v0.2.0")
	for _, given := range [][]byte{running, content} {
		if response := plane.give(t, operator, token, given); response.StatusCode != http.StatusCreated {
			t.Fatalf("giving a package was answered %d", response.StatusCode)
		}
	}
	response, body = plane.send(t, operator, http.MethodPost, control.UpdateCatalogsPath, token,
		&updatev1.CatalogPublication{Catalog: releaseCatalog(t, 1, rotated, releaseOfPackage("v0.1.0", running), releaseOfPackage("v0.2.0", content))})
	expect(t, response, body, http.StatusCreated, "publishing catalog 1")
	response, body = plane.send(t, operator, http.MethodPost, control.UpdateAssignmentsPath, token,
		&updatev1.Assignment{TenantId: "default", AgentIds: []string{"e2e-agent-90"}, Version: "v0.2.0"})
	expect(t, response, body, http.StatusOK, "assigning v0.2.0")

	response, body = plane.agentGet(t, assigned, control.UpdatePath, "")
	expect(t, response, body, http.StatusOK, "asking after the assignment")
	offered := response.Header.Get("ETag")
	if err := proto.Unmarshal(body, &offer); err != nil {
		t.Fatalf("read the offer: %v", err)
	}
	provisioned, err := agentupdate.Anchor(plane.updateRoot, time.Now())
	if err != nil {
		t.Fatalf("read the provisioned root: %v", err)
	}
	var after [][]byte
	for _, root := range offer.GetRoots()[1:] {
		encoded, err := agentupdate.Encode(root)
		if err != nil {
			t.Fatal(err)
		}
		after = append(after, encoded)
	}
	newest, err := provisioned.Walk(after, time.Now())
	if err != nil || newest.Version() != 2 {
		t.Fatalf("the agent could not walk the chain it was offered: %v", err)
	}
	catalog, err := newest.Catalog(offer.GetCatalog(), time.Now())
	if err != nil || offer.GetVersion() != "v0.2.0" || !catalog.Names("v0.2.0") {
		t.Fatalf("the agent could not verify the catalog it was offered for %q: %v", offer.GetVersion(), err)
	}
	for _, release := range catalog.Releases() {
		digest := hex.EncodeToString(release.GetPayload().GetSha256())
		response, body = plane.agentGet(t, assigned, "/v1/agents/update/packages/"+digest, "")
		expect(t, response, body, http.StatusOK, "downloading the package of "+release.GetVersion())
		if sum := sha256.Sum256(body); !bytes.Equal(sum[:], release.GetPayload().GetSha256()) {
			t.Fatalf("the bytes downloaded are not the package the catalog names for %s", release.GetVersion())
		}
		if response, body := plane.agentGet(t, unassigned, "/v1/agents/update/packages/"+digest, ""); response.StatusCode != http.StatusNotFound ||
			refusalCode(t, body) != control.CodeUnknownPackage {
			t.Fatalf("an agent assigned nothing was answered %d", response.StatusCode)
		}
	}

	if again, _ := plane.agentGet(t, assigned, control.UpdatePath, offered); again.StatusCode != http.StatusNotModified {
		t.Fatalf("asking again with the tag of an unchanged offer was answered %d", again.StatusCode)
	}
}

func TestAnOperatorKeyCannotAskWhetherToUpdate(t *testing.T) {
	plane := startControlAPI(t, nil)
	operator := plane.caller(t, "e2e-admin")
	request, err := http.NewRequest(http.MethodGet, "https://"+plane.renewalAddress+control.UpdatePath, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if response, err := operator.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatalf("an operator certificate reached the agent listener and was answered %d", response.StatusCode)
	}
}

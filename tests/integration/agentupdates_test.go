//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// Roots and catalogs belong to the whole platform rather than to a tenant, so
// every test here starts after whatever the shared database already holds.
type updateAuthority struct {
	key *ecdsa.PrivateKey
	id  string
	der []byte
}

func newUpdateAuthority(t *testing.T) updateAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an update key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode an update key: %v", err)
	}
	return updateAuthority{key: key, id: agentupdate.KeyID(der), der: der}
}

func (a updateAuthority) sign(t *testing.T, message proto.Message, payloadType string) *updatev1.Envelope {
	t.Helper()
	envelope, err := agentupdate.Sign(message, payloadType, crypto.Signer(a.key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return envelope
}

func (a updateAuthority) root(t *testing.T, version uint64) *updatev1.Envelope {
	t.Helper()
	now := time.Now().UTC()
	return a.sign(t, &updatev1.Root{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(now.Add(30 * 24 * time.Hour)),
		Keys:          []*updatev1.Key{{Keyid: a.id, PublicKey: a.der}},
		Root:          &updatev1.Role{Keyids: []string{a.id}, Threshold: 1},
		Catalog:       &updatev1.Role{Keyids: []string{a.id}, Threshold: 1},
	}, agentupdate.RootPayloadType)
}

func (a updateAuthority) anchor(t *testing.T, version uint64) *agentupdate.Root {
	t.Helper()
	served, err := agentupdate.Encode(a.root(t, version))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := agentupdate.Anchor(served, time.Now())
	if err != nil {
		t.Fatalf("anchor root %d: %v", version, err)
	}
	return anchor
}

func (a updateAuthority) catalog(t *testing.T, under *agentupdate.Root, version uint64, releases ...*updatev1.Release) agentupdate.AcceptedCatalog {
	t.Helper()
	now := time.Now().UTC()
	envelope := a.sign(t, &updatev1.Catalog{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(now.Add(7 * 24 * time.Hour)),
		Releases:      releases,
	}, agentupdate.CatalogPayloadType)
	accepted, err := agentupdate.AcceptCatalog(&updatev1.CatalogPublication{Catalog: envelope}, under, "it-admin", now)
	if err != nil {
		t.Fatalf("accept catalog %d: %v", version, err)
	}
	return accepted
}

func randomPackage(t *testing.T) agentupdate.AcceptedPackage {
	t.Helper()
	content := make([]byte, 4096)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("draw a package: %v", err)
	}
	accepted, err := agentupdate.AcceptPackage(content, "it-admin", time.Now())
	if err != nil {
		t.Fatalf("accept a package: %v", err)
	}
	return accepted
}

func releaseFor(version string, given agentupdate.AcceptedPackage) *updatev1.Release {
	return &updatev1.Release{
		Version:       version,
		Platform:      &updatev1.Platform{Os: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB},
		Payload:       &updatev1.Payload{Sha256: given.Record.GetSha256(), Size: given.Record.GetSize()},
		Source:        &updatev1.Source{Repository: "github.com/dynasmon/Seagull-agent-v2", Revision: strings.Repeat("ef", 20)},
		Compatibility: &updatev1.Compatibility{StateGeneration: 1},
	}
}

func payloadVersion(t *testing.T, served []byte, into interface {
	proto.Message
	GetVersion() uint64
}) uint64 {
	t.Helper()
	var envelope updatev1.Envelope
	if err := proto.Unmarshal(served, &envelope); err != nil {
		t.Fatalf("decode a stored envelope: %v", err)
	}
	if err := proto.Unmarshal(envelope.GetPayload(), into); err != nil {
		t.Fatalf("decode a stored payload: %v", err)
	}
	return into.GetVersion()
}

func newestRootVersion(t *testing.T, ctx context.Context, updates *postgres.AgentUpdates) uint64 {
	t.Helper()
	roots, err := updates.Roots(ctx, 0)
	if err != nil {
		t.Fatalf("read the stored roots: %v", err)
	}
	if len(roots) == 0 {
		return 1
	}
	return payloadVersion(t, roots[len(roots)-1], &updatev1.Root{})
}

func newestCatalogVersion(t *testing.T, ctx context.Context, updates *postgres.AgentUpdates, agentID string) uint64 {
	t.Helper()
	served, err := updates.Served(ctx, agentID, 0)
	if err != nil {
		t.Fatalf("read the newest catalog: %v", err)
	}
	if len(served.Catalog) == 0 {
		return 0
	}
	return payloadVersion(t, served.Catalog, &updatev1.Catalog{})
}

func TestARootIsRecordedOnlyAsTheNextOfTheChainOnPostgresql(t *testing.T) {
	updates := migratedAlertStore(t, alertStoreAddress(t)).AgentUpdates()
	authority := newUpdateAuthority(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	held := newestRootVersion(t, ctx, updates)
	anchor := authority.anchor(t, held)
	accepted, err := agentupdate.AcceptRoot(&updatev1.RootPublication{Root: authority.root(t, held+1)}, anchor, "it-admin", time.Now())
	if err != nil {
		t.Fatalf("accept root %d: %v", held+1, err)
	}

	var (
		wins   sync.WaitGroup
		mu     sync.Mutex
		stored int
		stale  int
	)
	for range 4 {
		wins.Go(func() {
			_, err := updates.PublishRoot(ctx, accepted)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				stored++
			case errors.Is(err, agentupdate.ErrStale):
				stale++
			default:
				t.Errorf("publish root %d: %v", held+1, err)
			}
		})
	}
	wins.Wait()
	if stored != 1 || stale != 3 {
		t.Fatalf("four publications of one root stored %d and found %d stale", stored, stale)
	}

	after, err := updates.Roots(ctx, held)
	if err != nil || len(after) != 1 || !bytes.Equal(after[0], accepted.Root.Served()) {
		t.Fatalf("the roots after %d are %d, %v", held, len(after), err)
	}
}

func TestACatalogIsRecordedOnlyWithEveryPackageItNamesOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	updates := store.AgentUpdates()
	authority := newUpdateAuthority(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	anchor := authority.anchor(t, 1)
	reader := registeredIn(t, ctx, store, isolated(t))
	version := newestCatalogVersion(t, ctx, updates, reader) + 1
	given := randomPackage(t)
	catalog := authority.catalog(t, anchor, version, releaseFor("v0.2.0", given))

	if _, err := updates.PublishCatalog(ctx, catalog); !errors.Is(err, agentupdate.ErrNoPackage) {
		t.Fatalf("a catalog naming a package nobody gave was recorded: %v", err)
	}
	first, err := updates.PublishPackage(ctx, given)
	if err != nil {
		t.Fatalf("give the package: %v", err)
	}
	again := given
	again.Record = proto.Clone(given.Record).(*updatev1.PublishedPackage)
	again.Record.PublishedBy = "it-someone-else"
	if second, err := updates.PublishPackage(ctx, again); err != nil || second.GetPublishedBy() != first.GetPublishedBy() {
		t.Fatalf("a package given twice was recorded as %v, %v", second, err)
	}

	if _, err := updates.PublishCatalog(ctx, catalog); err != nil {
		t.Fatalf("record catalog %d: %v", version, err)
	}
	if _, err := updates.PublishCatalog(ctx, catalog); !errors.Is(err, agentupdate.ErrStale) {
		t.Fatalf("catalog %d was recorded twice: %v", version, err)
	}
	served, err := updates.Served(ctx, reader, 0)
	if err != nil || !bytes.Equal(served.Catalog, catalog.Catalog.Served()) {
		t.Fatalf("the newest catalog is not the one recorded: %v", err)
	}
}

func TestAnAgentIsHandedOnlyThePackageOfTheVersionItWasAssignedOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	updates := store.AgentUpdates()
	authority := newUpdateAuthority(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, elsewhere := isolated(t), isolated(t)
	assigned, outsider := registeredIn(t, ctx, store, tenant), registeredIn(t, ctx, store, elsewhere)
	current, later := randomPackage(t), randomPackage(t)
	for _, given := range []agentupdate.AcceptedPackage{current, later} {
		if _, err := updates.PublishPackage(ctx, given); err != nil {
			t.Fatalf("give a package: %v", err)
		}
	}
	version := newestCatalogVersion(t, ctx, updates, assigned) + 1
	if _, err := updates.PublishCatalog(ctx, authority.catalog(t, authority.anchor(t, 1), version,
		releaseFor("v0.2.0", current), releaseFor("v0.3.0", later))); err != nil {
		t.Fatalf("record catalog %d: %v", version, err)
	}

	assign := func(version string, agents ...string) error {
		accepted, err := agentupdate.AcceptAssignment(&updatev1.Assignment{TenantId: tenant, AgentIds: agents, Version: version}, "it-admin", time.Now())
		if err != nil {
			t.Fatalf("accept the assignment: %v", err)
		}
		_, err = updates.Assign(ctx, accepted)
		return err
	}
	if err := assign("v0.4.0", assigned); !errors.Is(err, agentupdate.ErrUncataloged) {
		t.Fatalf("a version the catalog does not name was assigned: %v", err)
	}
	if err := assign("v0.2.0", assigned, outsider); !errors.Is(err, agentupdate.ErrUnregistered) {
		t.Fatalf("an agent of another tenant was assigned: %v", err)
	}
	if err := assign("v0.2.0", assigned); err != nil {
		t.Fatalf("assign v0.2.0: %v", err)
	}

	served, err := updates.Served(ctx, assigned, 0)
	if err != nil || served.Version != "v0.2.0" || served.State != agent.Pending {
		t.Fatalf("the agent is offered %q as %s: %v", served.Version, served.State, err)
	}
	handed, err := updates.Package(ctx, assigned, current.Record.GetSha256())
	if err != nil || !bytes.Equal(handed.Content, current.Content) {
		t.Fatalf("the package of v0.2.0 was not handed over: %v", err)
	}
	if _, err := updates.Package(ctx, assigned, later.Record.GetSha256()); !errors.Is(err, agentupdate.ErrUnknown) {
		t.Fatalf("the package of a version the agent was not assigned was handed over: %v", err)
	}
	if _, err := updates.Package(ctx, outsider, current.Record.GetSha256()); !errors.Is(err, agentupdate.ErrUnknown) {
		t.Fatalf("a package was handed to an agent assigned nothing: %v", err)
	}
	if _, err := updates.Package(ctx, "it-nobody-registered", current.Record.GetSha256()); !errors.Is(err, agent.ErrUnknown) {
		t.Fatalf("an unregistered agent was answered %v", err)
	}

	if err := assign("", assigned); err != nil {
		t.Fatalf("withdraw the assignment: %v", err)
	}
	if served, err := updates.Served(ctx, assigned, 0); err != nil || served.Version != "" {
		t.Fatalf("a withdrawn assignment is still offered as %q: %v", served.Version, err)
	}
	if err := assign("v0.3.0", assigned); err != nil {
		t.Fatalf("assign v0.3.0: %v", err)
	}
	if _, err := store.Agents().Move(ctx, assigned, []string{tenant}, agent.Move{
		To: agent.Disabled, Note: "the machine is rebuilt", Actor: "it-admin", At: time.Now(),
	}); err != nil {
		t.Fatalf("disable the agent: %v", err)
	}
	if handed, err := updates.Package(ctx, assigned, later.Record.GetSha256()); err != nil || handed.State != agent.Disabled || handed.Content != nil {
		t.Fatalf("a disabled agent was handed %d bytes as %s: %v", len(handed.Content), handed.State, err)
	}
	if _, err := updates.Served(ctx, "it-nobody-registered", 0); !errors.Is(err, agent.ErrUnknown) {
		t.Fatalf("an unregistered agent was offered %v", err)
	}
}

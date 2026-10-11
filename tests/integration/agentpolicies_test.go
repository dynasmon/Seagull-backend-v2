//go:build integration

package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

type policySigner struct {
	key     *ecdsa.PrivateKey
	signers *agentpolicy.Signers
}

func newPolicySigner(t *testing.T) policySigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a policy signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the policy signer: %v", err)
	}
	signers, err := agentpolicy.ParseSigners(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("read the policy signer: %v", err)
	}
	return policySigner{key: key, signers: signers}
}

func (s policySigner) accepted(t *testing.T, tenant string, revision uint64, targets ...string) agentpolicy.Accepted {
	t.Helper()
	now := time.Now().UTC()
	envelope, err := agentpolicy.Sign(&policyv1.Policy{
		SchemaVersion: agentpolicy.SchemaVersion,
		PolicyId:      "it-servers",
		Revision:      revision,
		Targets:       &policyv1.Targets{AgentIds: targets},
		IssuedAt:      timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt:     timestamppb.New(now.Add(24 * time.Hour)),
		Settings:      &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_INFO},
	}, s.key)
	if err != nil {
		t.Fatalf("sign revision %d: %v", revision, err)
	}
	accepted, err := agentpolicy.Accept(&policyv1.Publication{TenantId: tenant, Policy: envelope}, s.signers, "it-admin", now)
	if err != nil {
		t.Fatalf("accept revision %d: %v", revision, err)
	}
	return accepted
}

func registeredIn(t *testing.T, ctx context.Context, store *postgres.Store, tenant string) string {
	t.Helper()
	id := agentIdentifier(t)
	if _, err := store.Agents().Register(ctx, &agentv1.Registration{AgentId: id, TenantId: tenant}, "it-admin", time.Now()); err != nil {
		t.Fatalf("register %s into %s: %v", id, tenant, err)
	}
	return id
}

// An agent is handed the highest revision of its own tenant that names it,
// byte for byte as it was recorded, whichever policy that revision belongs to
// and whatever was published for anybody else since.
func TestAnAgentIsHandedTheNewestRevisionOfItsTenantNamingItOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	policies := store.AgentPolicies()
	signer := newPolicySigner(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, elsewhere := isolated(t), isolated(t)
	first, second := registeredIn(t, ctx, store, tenant), registeredIn(t, ctx, store, tenant)
	outsider := registeredIn(t, ctx, store, elsewhere)

	published := map[uint64]agentpolicy.Accepted{}
	for revision, targets := range map[uint64][]string{1: {first}, 2: {first, second}, 3: {second}} {
		published[revision] = signer.accepted(t, tenant, revision, targets...)
	}
	for _, revision := range []uint64{1, 2, 3} {
		if _, err := policies.Publish(ctx, published[revision]); err != nil {
			t.Fatalf("publish revision %d: %v", revision, err)
		}
	}

	for agentID, revision := range map[string]uint64{first: 2, second: 3} {
		served, err := policies.Served(ctx, agentID)
		if err != nil {
			t.Fatalf("serve %s: %v", agentID, err)
		}
		if served.Revision != revision || !slices.Equal(served.Envelope, published[revision].Served) ||
			served.Digest != published[revision].Record.GetDigestSha256() || served.State != agent.Pending {
			t.Fatalf("%s was handed revision %d as %s, and revision %d names it last", agentID, served.Revision, served.State, revision)
		}
	}

	served, err := policies.Served(ctx, outsider)
	if err != nil || served.Named() {
		t.Fatalf("an agent of another tenant was handed %v, %v", served, err)
	}
	if _, err := policies.Served(ctx, "it-nobody-registered"); !errors.Is(err, agent.ErrUnknown) {
		t.Fatalf("an unregistered agent was answered %v", err)
	}

	if _, err := store.Agents().Move(ctx, first, []string{tenant}, agent.Move{
		To: agent.Disabled, Note: "the machine is rebuilt", Actor: "it-admin", At: time.Now(),
	}); err != nil {
		t.Fatalf("disable %s: %v", first, err)
	}
	if served, err := policies.Served(ctx, first); err != nil || served.State != agent.Disabled {
		t.Fatalf("a disabled agent is served as %v, %v", served.State, err)
	}
}

func TestATenantsRevisionsOnlyIncreaseOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	policies := store.AgentPolicies()
	signer := newPolicySigner(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, elsewhere := isolated(t), isolated(t)
	named, outsider := registeredIn(t, ctx, store, tenant), registeredIn(t, ctx, store, elsewhere)

	if _, err := policies.Publish(ctx, signer.accepted(t, tenant, 5, named)); err != nil {
		t.Fatalf("publish revision 5: %v", err)
	}
	for _, revision := range []uint64{5, 4, 1} {
		if _, err := policies.Publish(ctx, signer.accepted(t, tenant, revision, named)); !errors.Is(err, agentpolicy.ErrStale) {
			t.Fatalf("revision %d after revision 5 was answered %v", revision, err)
		}
	}
	if _, err := policies.Publish(ctx, signer.accepted(t, elsewhere, 1, outsider)); err != nil {
		t.Fatalf("another tenant's first revision was refused: %v", err)
	}

	var (
		wait     sync.WaitGroup
		mutex    sync.Mutex
		recorded int
	)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := policies.Publish(ctx, signer.accepted(t, tenant, 6, named))
			mutex.Lock()
			defer mutex.Unlock()
			switch {
			case err == nil:
				recorded++
			case !errors.Is(err, agentpolicy.ErrStale):
				t.Errorf("a racing publication was answered %v", err)
			}
		}()
	}
	wait.Wait()
	if recorded != 1 {
		t.Fatalf("revision 6 was recorded %d times by racing publications", recorded)
	}
}

func TestAPolicyNamingAnAgentOutsideItsTenantRecordsNothingOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	policies := store.AgentPolicies()
	signer := newPolicySigner(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, elsewhere := isolated(t), isolated(t)
	named, outsider := registeredIn(t, ctx, store, tenant), registeredIn(t, ctx, store, elsewhere)

	_, err := policies.Publish(ctx, signer.accepted(t, tenant, 1, named, outsider, "it-nobody-registered"))
	if !errors.Is(err, agentpolicy.ErrUnregistered) || !strings.Contains(err.Error(), outsider) || !strings.Contains(err.Error(), "it-nobody-registered") {
		t.Fatalf("a policy naming agents outside its tenant was answered %v", err)
	}
	page, err := policies.Page(ctx, &policyv1.Query{}, []string{tenant})
	if err != nil || len(page.GetPolicies()) != 0 {
		t.Fatalf("a refused policy left %v, %v", page.GetPolicies(), err)
	}
	if served, err := policies.Served(ctx, named); err != nil || served.Named() {
		t.Fatalf("a refused policy is handed out: %v, %v", served, err)
	}
}

func TestPoliciesArePagedWithinTheScopeOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	policies := store.AgentPolicies()
	signer := newPolicySigner(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, elsewhere := isolated(t), isolated(t)
	first, second := registeredIn(t, ctx, store, tenant), registeredIn(t, ctx, store, tenant)
	outsider := registeredIn(t, ctx, store, elsewhere)
	var third agentpolicy.Accepted
	for revision := range uint64(5) {
		targets := []string{first}
		if revision%2 == 0 {
			targets = append(targets, second)
		}
		accepted := signer.accepted(t, tenant, revision+1, targets...)
		if revision+1 == 3 {
			third = accepted
		}
		if _, err := policies.Publish(ctx, accepted); err != nil {
			t.Fatalf("publish revision %d: %v", revision+1, err)
		}
	}
	if _, err := policies.Publish(ctx, signer.accepted(t, elsewhere, 1, outsider)); err != nil {
		t.Fatalf("publish into the other tenant: %v", err)
	}

	var revisions []uint64
	for cursor := ""; ; {
		page, err := policies.Page(ctx, &policyv1.Query{Limit: 2, Cursor: cursor}, []string{tenant})
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		for _, one := range page.GetPolicies() {
			if one.GetTenantId() != tenant || one.GetPolicy() != nil {
				t.Fatalf("a page carried %v", one)
			}
			revisions = append(revisions, one.GetRevision())
		}
		if cursor = page.GetNextCursor(); cursor == "" {
			break
		}
	}
	if !slices.Equal(revisions, []uint64{5, 4, 3, 2, 1}) {
		t.Fatalf("the tenant's revisions were paged as %v", revisions)
	}

	naming, err := policies.Page(ctx, &policyv1.Query{AgentId: second}, []string{tenant})
	if err != nil || len(naming.GetPolicies()) != 3 {
		t.Fatalf("the policies naming %s were listed as %v, %v", second, naming.GetPolicies(), err)
	}
	beyond, err := policies.Page(ctx, &policyv1.Query{TenantIds: []string{elsewhere}}, []string{tenant})
	if err != nil || len(beyond.GetPolicies()) != 0 {
		t.Fatalf("naming a tenant beyond the scope listed %v, %v", beyond.GetPolicies(), err)
	}

	described, err := policies.Policy(ctx, tenant, 3, []string{tenant})
	if err != nil || !proto.Equal(described.GetPolicy(), third.Record.GetPolicy()) {
		t.Fatalf("revision 3 was described as %v, %v", described, err)
	}
	for _, asked := range []struct {
		tenant   string
		revision uint64
		scope    []string
	}{{tenant, 3, []string{elsewhere}}, {tenant, 9, []string{tenant}}, {elsewhere, 3, []string{tenant, elsewhere}}} {
		if _, err := policies.Policy(ctx, asked.tenant, asked.revision, asked.scope); !errors.Is(err, agentpolicy.ErrUnknown) {
			t.Fatalf("revision %d of %s within %v was answered %v", asked.revision, asked.tenant, asked.scope, err)
		}
	}
	if _, err := policies.Page(ctx, &policyv1.Query{Cursor: "not-a-cursor"}, []string{tenant}); !errors.Is(err, agentpolicy.ErrCursor) {
		t.Fatalf("a cursor the store never issued was answered %v", err)
	}
}

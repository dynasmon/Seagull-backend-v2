//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func agentIdentifier(t *testing.T) string {
	t.Helper()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("draw an identifier: %v", err)
	}
	return "it-agent-" + hex.EncodeToString(suffix)
}

func agentFingerprint(t *testing.T) string {
	t.Helper()
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("draw a fingerprint: %v", err)
	}
	return hex.EncodeToString(digest)
}

func certificateFor(t *testing.T, agentID string, at time.Time) *agentv1.Identity {
	t.Helper()
	return &agentv1.Identity{
		Subject:           agentID,
		Serial:            strings.ToLower(hex.EncodeToString([]byte{0x0a, 0x1b, 0x2c, 0x3d})),
		FingerprintSha256: agentFingerprint(t),
		IssuedAt:          timestamppb.New(at),
		ExpiresAt:         timestamppb.New(at.Add(90 * 24 * time.Hour)),
	}
}

// The whole administrative life of an agent against a real PostgreSQL: it is
// registered pending, the certificate it will present is bound to it, it is
// revoked, and every step is on the trail with the person who made it.
func TestAnAgentIsRegisteredBoundAndRevokedOnPostgresql(t *testing.T) {
	address := alertStoreAddress(t)
	store := migratedAlertStore(t, address)
	registry := store.Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	agentID := agentIdentifier(t)
	at := time.Now().UTC().Truncate(time.Millisecond)

	registered, err := registry.Register(ctx, &agentv1.Registration{
		AgentId:      agentID,
		TenantId:     "default",
		Platform:     &agentv1.Platform{Os: "linux", Architecture: "amd64", Hostname: agentID + ".internal"},
		AgentVersion: "2.0.0",
		Note:         "an integration sensor",
	}, "it-operator", at)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got, _ := agent.FromWire(registered.GetState()); got != agent.Pending {
		t.Fatalf("a registered agent is %s", got)
	}

	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"},
		"it-operator", at); !errors.Is(err, agent.ErrRegistered) {
		t.Fatalf("the same agent was registered twice: %v", err)
	}

	bound, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		Identity: certificateFor(t, agentID, at), Actor: "it-authority", At: at.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if got, _ := agent.FromWire(bound.GetState()); got != agent.Active {
		t.Fatalf("a bound agent is %s", got)
	}
	if bound.GetIdentity().GetFingerprintSha256() == "" {
		t.Fatal("the certificate identity was not stored")
	}

	revoked, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		To: agent.Revoked, Note: "the key leaked", Actor: "it-operator", At: at.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.GetRevision() != 3 {
		t.Fatalf("the agent is at revision %d", revoked.GetRevision())
	}

	history, err := registry.History(ctx, agentID, []string{"default"})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(history.GetTransitions()) != 3 {
		t.Fatalf("the trail carries %d lines", len(history.GetTransitions()))
	}
	for _, line := range history.GetTransitions() {
		if line.GetActor() == "" {
			t.Fatalf("a lifecycle change is not attributable: %v", line)
		}
	}
}

func TestAnAgentIsNeverReachedOutsideItsTenant(t *testing.T) {
	address := alertStoreAddress(t)
	registry := migratedAlertStore(t, address).Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	agentID := agentIdentifier(t)
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"},
		"it-operator", time.Now().UTC()); err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := registry.Agent(ctx, agentID, []string{"another-tenant"}); !errors.Is(err, agent.ErrUnknown) {
		t.Fatalf("an agent was read from outside its tenant: %v", err)
	}
	if _, err := registry.Move(ctx, agentID, []string{"another-tenant"}, agent.Move{
		To: agent.Decommissioned, Note: "not mine", Actor: "outsider", At: time.Now().UTC(),
	}); !errors.Is(err, agent.ErrUnknown) {
		t.Fatalf("an agent was retired from outside its tenant: %v", err)
	}
}

// A certificate belongs to one agent. Binding one that is already somebody
// else's is refused by the store rather than recorded, because a fingerprint
// shared by two agents is a revocation nobody can act on.
func TestACertificateIsNeverBoundToTwoAgents(t *testing.T) {
	address := alertStoreAddress(t)
	registry := migratedAlertStore(t, address).Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Now().UTC()
	first, second := agentIdentifier(t), agentIdentifier(t)
	for _, agentID := range []string{first, second} {
		if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"},
			"it-operator", at); err != nil {
			t.Fatalf("register %s: %v", agentID, err)
		}
	}

	held := certificateFor(t, first, at)
	if _, err := registry.Move(ctx, first, []string{"default"}, agent.Move{
		Identity: held, Actor: "it-authority", At: at,
	}); err != nil {
		t.Fatalf("bind the first: %v", err)
	}

	stolen := &agentv1.Identity{
		Subject:           second,
		Serial:            held.GetSerial(),
		FingerprintSha256: held.GetFingerprintSha256(),
		IssuedAt:          held.GetIssuedAt(),
		ExpiresAt:         held.GetExpiresAt(),
	}
	if _, err := registry.Move(ctx, second, []string{"default"}, agent.Move{
		Identity: stolen, Actor: "it-authority", At: at,
	}); !errors.Is(err, agent.ErrMalformedIdentity) {
		t.Fatalf("one certificate was bound to two agents: %v", err)
	}
}

// The registry is written first and the log after it. A decision the backbone
// never took is outstanding until it is carried, which is what stops a
// revocation disappearing when the broker is down.
func TestADecisionStaysOutstandingUntilTheDataPlaneIsTold(t *testing.T) {
	address := alertStoreAddress(t)
	registry := migratedAlertStore(t, address).Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	agentID := agentIdentifier(t)
	at := time.Now().UTC()
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"},
		"it-operator", at); err != nil {
		t.Fatalf("register: %v", err)
	}

	waiting, err := registry.Outstanding(ctx, 500)
	if err != nil {
		t.Fatalf("read what is outstanding: %v", err)
	}
	if !names(waiting, agentID) {
		t.Fatal("a registration the data plane was never told about is not outstanding")
	}

	if err := registry.Announced(ctx, agentID, 1); err != nil {
		t.Fatalf("record the announcement: %v", err)
	}
	waiting, err = registry.Outstanding(ctx, 500)
	if err != nil {
		t.Fatalf("read what is outstanding: %v", err)
	}
	if names(waiting, agentID) {
		t.Fatal("an announced decision is still outstanding")
	}

	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		To: agent.Revoked, Note: "the host was rebuilt", Actor: "it-operator", At: at.Add(time.Minute),
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	waiting, err = registry.Outstanding(ctx, 500)
	if err != nil {
		t.Fatalf("read what is outstanding: %v", err)
	}
	if !names(waiting, agentID) {
		t.Fatal("a revocation the data plane was never told about is not outstanding")
	}
}

func names(records []*agentv1.Admission, agentID string) bool {
	for _, record := range records {
		if record.GetAgentId() == agentID {
			return true
		}
	}
	return false
}

func TestTheRegistryPagesByIdentifierWithinTheScope(t *testing.T) {
	address := alertStoreAddress(t)
	registry := migratedAlertStore(t, address).Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Now().UTC()
	for range 3 {
		if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentIdentifier(t), TenantId: "default"},
			"it-operator", at); err != nil {
			t.Fatalf("register: %v", err)
		}
	}

	page, err := registry.Page(ctx, &agentv1.Query{Limit: 2}, []string{"default"})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(page.GetAgents()) != 2 || page.GetNextCursor() == "" {
		t.Fatalf("a page of two carried %d agents and cursor %q", len(page.GetAgents()), page.GetNextCursor())
	}
	for index := 1; index < len(page.GetAgents()); index++ {
		if page.GetAgents()[index-1].GetAgentId() >= page.GetAgents()[index].GetAgentId() {
			t.Fatal("a page is not ordered by identifier")
		}
	}

	next, err := registry.Page(ctx, &agentv1.Query{Limit: 2, Cursor: page.GetNextCursor()}, []string{"default"})
	if err != nil {
		t.Fatalf("read the next page: %v", err)
	}
	for _, one := range next.GetAgents() {
		if one.GetAgentId() <= page.GetAgents()[1].GetAgentId() {
			t.Fatal("the cursor stepped backwards")
		}
	}

	if _, err := registry.Page(ctx, &agentv1.Query{Cursor: "not-a-cursor!"}, []string{"default"}); !errors.Is(err, agent.ErrCursor) {
		t.Fatalf("an invented cursor was accepted: %v", err)
	}
}

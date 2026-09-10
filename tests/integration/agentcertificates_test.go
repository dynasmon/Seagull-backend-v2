//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Renewal replaces which certificate the registry holds, and the one it replaced
// stays on the trail: after a rotation, which key a machine was using at a past
// moment is still answerable.
func TestARenewedCertificateSupersedesTheOneItReplacedOnPostgresql(t *testing.T) {
	address := alertStoreAddress(t)
	store := migratedAlertStore(t, address)
	registry := store.Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	agentID := agentIdentifier(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"}, "it-admin", at); err != nil {
		t.Fatalf("register: %v", err)
	}

	first := certificateFor(t, agentID, at)
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		Identity: first, Actor: "it-admin", At: at, Authority: "Integration Agent CA",
	}); err != nil {
		t.Fatalf("bind the first certificate: %v", err)
	}

	second := certificateFor(t, agentID, at.Add(time.Hour))
	if _, err := registry.Renew(ctx, agentID, agent.Move{
		Identity: second, Actor: agentID, At: at.Add(time.Hour), Authority: "Integration Agent CA",
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	trail, err := registry.Certificates(ctx, agentID, []string{"default"})
	if err != nil {
		t.Fatalf("read the certificate trail: %v", err)
	}
	if len(trail.GetCertificates()) != 2 {
		t.Fatalf("two certificates were bound and the trail holds %d", len(trail.GetCertificates()))
	}
	if trail.GetCertificates()[0].GetIdentity().GetFingerprintSha256() != second.GetFingerprintSha256() {
		t.Fatal("the trail does not lead with the certificate that is current")
	}
	if trail.GetCertificates()[0].GetSupersededAt() != nil {
		t.Fatal("the current certificate is recorded as superseded")
	}
	if trail.GetCertificates()[1].GetSupersededAt() == nil {
		t.Fatal("the certificate a renewal replaced is not recorded as superseded")
	}
	if trail.GetCertificates()[1].GetIssuedBy() != "it-admin" || trail.GetCertificates()[0].GetIssuedBy() != agentID {
		t.Fatalf("the trail attributes the certificates to %q and %q",
			trail.GetCertificates()[1].GetIssuedBy(), trail.GetCertificates()[0].GetIssuedBy())
	}

	held, err := registry.Agent(ctx, agentID, []string{"default"})
	if err != nil {
		t.Fatalf("read the agent: %v", err)
	}
	if held.GetIdentity().GetFingerprintSha256() != second.GetFingerprintSha256() {
		t.Fatal("the registry did not follow the renewal")
	}
}

func TestAnAgentThePlatformStoppedHonouringDoesNotRenewOnPostgresql(t *testing.T) {
	address := alertStoreAddress(t)
	store := migratedAlertStore(t, address)
	registry := store.Agents()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	agentID := agentIdentifier(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"}, "it-admin", at); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		Identity: certificateFor(t, agentID, at), Actor: "it-admin", At: at,
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		To: agent.Disabled, Note: "the machine is being rebuilt", Actor: "it-admin", At: at,
	}); err != nil {
		t.Fatalf("disable: %v", err)
	}

	_, err := registry.Renew(ctx, agentID, agent.Move{
		Identity: certificateFor(t, agentID, at.Add(time.Hour)), Actor: agentID, At: at.Add(time.Hour),
	})
	if !errors.Is(err, agent.ErrIllegalMove) {
		t.Fatalf("a disabled agent renewing was answered with %v", err)
	}

	// An operator may still hand it a certificate: re-issuing is how a machine
	// that lost its key comes back, and it stays disabled until somebody says so.
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{
		Identity: certificateFor(t, agentID, at.Add(time.Hour)), Actor: "it-admin", At: at.Add(time.Hour),
	}); err != nil {
		t.Fatalf("re-issue to a disabled agent: %v", err)
	}
	held, err := registry.Agent(ctx, agentID, []string{"default"})
	if err != nil {
		t.Fatalf("read the agent: %v", err)
	}
	if got, _ := agent.FromWire(held.GetState()); got != agent.Disabled {
		t.Fatalf("re-issuing to a disabled agent left it %s", got)
	}
}

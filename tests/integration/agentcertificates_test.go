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
		PresentedFingerprint: first.GetFingerprintSha256(),
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

// A renewal the registry granted and whose answer was lost is asked again with
// the certificate it replaced and the same request: the registry remembers what
// the bound certificate answered across the transaction that bound it, so it
// answers that renewal again, however often, and refuses any other request
// presented with the replaced certificate.
func TestARenewalWhoseAnswerWasLostIsAnsweredWhenAskedAgainOnPostgresql(t *testing.T) {
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
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{Identity: first, Actor: "it-admin", At: at}); err != nil {
		t.Fatalf("bind the first certificate: %v", err)
	}

	request := agentFingerprint(t)
	renew := func(identity *agentv1.Identity, asked string, after time.Duration) error {
		_, err := registry.Renew(ctx, agentID, agent.Move{
			Identity: identity, Actor: agentID, At: at.Add(after),
			PresentedFingerprint: first.GetFingerprintSha256(), Request: asked,
		})
		return err
	}
	if err := renew(certificateFor(t, agentID, at.Add(time.Hour)), request, time.Hour); err != nil {
		t.Fatalf("renew: %v", err)
	}
	for attempt := 2; attempt <= 3; attempt++ {
		again := certificateFor(t, agentID, at.Add(time.Duration(attempt)*time.Hour))
		if err := renew(again, request, time.Duration(attempt)*time.Hour); err != nil {
			t.Fatalf("the renewal asked again for the %d time was answered with %v", attempt, err)
		}
		held, err := registry.Agent(ctx, agentID, []string{"default"})
		if err != nil || held.GetIdentity().GetFingerprintSha256() != again.GetFingerprintSha256() {
			t.Fatalf("answering the renewal again left the agent bound to %v: %v", held.GetIdentity(), err)
		}
	}
	if err := renew(certificateFor(t, agentID, at.Add(4*time.Hour)), agentFingerprint(t), 4*time.Hour); !errors.Is(err, agent.ErrCertificateReplaced) {
		t.Fatalf("another request presented with the replaced certificate was answered with %v", err)
	}

	trail, err := registry.Certificates(ctx, agentID, []string{"default"})
	if err != nil {
		t.Fatalf("read the certificate trail: %v", err)
	}
	if len(trail.GetCertificates()) != 4 {
		t.Fatalf("a certificate and three answers to one renewal left %d certificates on the trail", len(trail.GetCertificates()))
	}
	for index, one := range trail.GetCertificates() {
		if superseded := one.GetSupersededAt() != nil; superseded != (index > 0) {
			t.Errorf("certificate %d of the trail is superseded %t", index, superseded)
		}
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

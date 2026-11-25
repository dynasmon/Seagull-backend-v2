//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Every decision a store of the test's own holds is the test's, so publishing
// them all is what the announcer would do between two of its steps.
func publishedAll(t *testing.T, registry *postgres.Agents) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for {
		waiting, err := registry.Unpublished(ctx, postgres.MaxPageSize)
		if err != nil {
			t.Fatalf("read what is unpublished: %v", err)
		}
		if len(waiting) == 0 {
			return
		}
		for _, one := range waiting {
			if err := registry.Published(ctx, one); err != nil {
				t.Fatalf("record a decision published: %v", err)
			}
		}
	}
}

func unpublishedOf(t *testing.T, registry *postgres.Agents, agentID string) []agentfinding.Replaced {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	waiting, err := registry.Unpublished(ctx, postgres.MaxPageSize)
	if err != nil {
		t.Fatalf("read what is unpublished: %v", err)
	}
	var mine []agentfinding.Replaced
	for _, one := range waiting {
		if one.AgentID == agentID {
			mine = append(mine, one)
		}
	}
	return mine
}

func renewedOnce(t *testing.T, registry *postgres.Agents, at time.Time) (string, *agentv1.Identity, *agentv1.Identity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	agentID := agentIdentifier(t)
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"}, "it-admin", at); err != nil {
		t.Fatalf("register: %v", err)
	}
	first := certificateFor(t, agentID, at)
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{Identity: first, Actor: "it-admin", At: at}); err != nil {
		t.Fatalf("bind the first certificate: %v", err)
	}
	second := certificateFor(t, agentID, at)
	if _, err := registry.Renew(ctx, agentID, agent.Move{Identity: second, Actor: agentID, At: at, PresentedFingerprint: first.GetFingerprintSha256()}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	return agentID, first, second
}

func TestARenewalRefusedAsAlreadyReplacedIsOneEpisodeUntilAnotherCertificateIsBoundOnPostgresql(t *testing.T) {
	store, _ := ownRelationalStore(t, alertStoreAddress(t))
	registry := store.Agents()
	publishedAll(t, registry)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Millisecond)
	agentID, first, second := renewedOnce(t, registry, at)
	asking := func(presented string, after time.Duration) error {
		return registry.Renewable(ctx, agentID, agent.Move{Actor: agentID, At: at.Add(after), PresentedFingerprint: presented, Request: agentFingerprint(t)})
	}

	for after := time.Minute; after <= 2*time.Minute; after += time.Minute {
		if err := asking(first.GetFingerprintSha256(), after); !errors.Is(err, agent.ErrCertificateReplaced) {
			t.Fatalf("asked before signing, the replaced certificate was answered %v", err)
		}
	}
	if err := asking(second.GetFingerprintSha256(), 3*time.Minute); err != nil {
		t.Fatalf("asked before signing, the certificate in force was answered %v", err)
	}
	mine := unpublishedOf(t, registry, agentID)
	if len(mine) != 1 || mine[0].InForce != second.GetFingerprintSha256() || mine[0].TenantID != "default" || mine[0].Observations != 2 ||
		!mine[0].OpenedAt.Equal(at.Add(time.Minute)) || !mine[0].LastObservedAt.Equal(at.Add(2*time.Minute)) ||
		mine[0].Closure != agentv1.Finding_CLOSURE_UNSPECIFIED || mine[0].Revision != 2 {
		t.Fatalf("two refusals under one certificate in force were kept as %+v", mine)
	}
	if err := registry.Published(ctx, mine[0]); err != nil {
		t.Fatal(err)
	}
	if left := unpublishedOf(t, registry, agentID); len(left) != 0 {
		t.Fatalf("a published decision is still unpublished: %+v", left)
	}

	third := certificateFor(t, agentID, at)
	if _, err := registry.Renew(ctx, agentID, agent.Move{Identity: third, Actor: agentID, At: at.Add(3 * time.Minute), PresentedFingerprint: first.GetFingerprintSha256()}); !errors.Is(err, agent.ErrCertificateReplaced) {
		t.Fatalf("a renewal signed for a replaced certificate was bound: %v", err)
	}
	if mine := unpublishedOf(t, registry, agentID); len(mine) != 1 || mine[0].Observations != 3 || mine[0].Revision != 3 {
		t.Fatalf("a replaced certificate refused when binding was kept as %+v", mine)
	}

	fourth := certificateFor(t, agentID, at)
	if _, err := registry.Renew(ctx, agentID, agent.Move{Identity: fourth, Actor: agentID, At: at.Add(4 * time.Minute), PresentedFingerprint: second.GetFingerprintSha256()}); err != nil {
		t.Fatalf("renew with the certificate in force: %v", err)
	}
	ended := unpublishedOf(t, registry, agentID)
	if len(ended) != 1 || ended[0].Closure != agentv1.Finding_CLOSURE_REBOUND || !ended[0].ClosedAt.Equal(at.Add(4*time.Minute)) || ended[0].Observations != 3 {
		t.Fatalf("binding another certificate left the episode %+v", ended)
	}

	if err := asking(first.GetFingerprintSha256(), 5*time.Minute); !errors.Is(err, agent.ErrCertificateReplaced) {
		t.Fatalf("the replaced certificate was answered %v", err)
	}
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{To: agent.Disabled, Note: "copied", Actor: "it-admin", At: at.Add(6 * time.Minute)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := asking(first.GetFingerprintSha256(), 7*time.Minute); !errors.Is(err, agent.ErrIllegalMove) {
		t.Fatalf("a disabled agent asking to renew was answered %v", err)
	}
	both := unpublishedOf(t, registry, agentID)
	byForce := map[string]agentfinding.Replaced{}
	for _, one := range both {
		byForce[one.InForce] = one
	}
	if len(both) != 2 || byForce[second.GetFingerprintSha256()].Closure != agentv1.Finding_CLOSURE_REBOUND ||
		byForce[fourth.GetFingerprintSha256()].Closure != agentv1.Finding_CLOSURE_NOT_ADMITTED ||
		!byForce[fourth.GetFingerprintSha256()].ClosedAt.Equal(at.Add(6*time.Minute)) || byForce[fourth.GetFingerprintSha256()].Observations != 1 {
		t.Fatalf("a refusal under another certificate and a disabling left %+v", both)
	}

	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{To: agent.Active, Note: "answered", Actor: "it-admin", At: at.Add(8 * time.Minute)}); err != nil {
		t.Fatalf("enable again: %v", err)
	}
	if err := asking(first.GetFingerprintSha256(), 9*time.Minute); !errors.Is(err, agent.ErrCertificateReplaced) {
		t.Fatalf("once the agent was admitted again, the replaced certificate was answered %v", err)
	}
	reopened := map[string]agentfinding.Replaced{}
	for _, one := range unpublishedOf(t, registry, agentID) {
		reopened[one.InForce] = one
	}
	again := reopened[fourth.GetFingerprintSha256()]
	if len(reopened) != 2 || again.Closure != agentv1.Finding_CLOSURE_UNSPECIFIED || !again.ClosedAt.IsZero() ||
		!again.OpenedAt.Equal(at.Add(5*time.Minute)) || !again.LastObservedAt.Equal(at.Add(9*time.Minute)) || again.Observations != 2 ||
		reopened[second.GetFingerprintSha256()].Closure != agentv1.Finding_CLOSURE_REBOUND {
		t.Fatalf("a refusal under the certificate of an episode that had closed left %+v", reopened)
	}
	publishedAll(t, registry)
}

func TestAReplacedCertificateLeftOpenIsDecidedAgainAndAClosedOneIsNotOnPostgresql(t *testing.T) {
	store, _ := ownRelationalStore(t, alertStoreAddress(t))
	registry := store.Agents()
	publishedAll(t, registry)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Millisecond)
	agentID, first, _ := renewedOnce(t, registry, at)
	if err := registry.Renewable(ctx, agentID, agent.Move{Actor: agentID, At: at, PresentedFingerprint: first.GetFingerprintSha256()}); !errors.Is(err, agent.ErrCertificateReplaced) {
		t.Fatalf("the replaced certificate was answered %v", err)
	}
	publishedAll(t, registry)

	if err := registry.DecideAgain(ctx, at, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if mine := unpublishedOf(t, registry, agentID); len(mine) != 0 {
		t.Fatalf("a decision as old as the bound was decided again: %+v", mine)
	}
	if err := registry.DecideAgain(ctx, at.Add(time.Millisecond), at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	mine := unpublishedOf(t, registry, agentID)
	if len(mine) != 1 || !mine[0].DecidedAt.Equal(at.Add(2*time.Second)) || mine[0].Revision != 2 || mine[0].Observations != 1 {
		t.Fatalf("an open episode decided again is %+v", mine)
	}
	publishedAll(t, registry)

	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{To: agent.Disabled, Note: "copied", Actor: "it-admin", At: at.Add(3 * time.Second)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	publishedAll(t, registry)
	if err := registry.DecideAgain(ctx, at.Add(time.Hour), at.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if mine := unpublishedOf(t, registry, agentID); len(mine) != 0 {
		t.Fatalf("a closed episode was decided again: %+v", mine)
	}
}

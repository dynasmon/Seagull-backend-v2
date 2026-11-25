//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func toldOf(t *testing.T, registry *postgres.Agents, agentID string) *agentv1.Admission {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	told, err := registry.Admission(ctx, agentID)
	if err != nil {
		t.Fatalf("read what the data plane is told of %s: %v", agentID, err)
	}
	return told
}

// Every binding says which certificate it replaced and when, a renewal the one
// it was presented with, so a renewal asked again after a lost answer tolerates
// the certificate the agent still holds; a move that binds nothing keeps it.
func TestTheRegistryTellsTheDataPlaneWhichCertificateAnAgentIsAdmittedOnOnPostgresql(t *testing.T) {
	registry := migratedAlertStore(t, alertStoreAddress(t)).Agents()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Millisecond)
	agentID := agentIdentifier(t)
	if _, err := registry.Register(ctx, &agentv1.Registration{AgentId: agentID, TenantId: "default"}, "it-admin", at); err != nil {
		t.Fatalf("register: %v", err)
	}
	if told := toldOf(t, registry, agentID); told.GetFingerprintSha256() != "" || told.GetReplacedFingerprintSha256() != "" {
		t.Fatalf("a pending agent is told as bound: %v", told)
	}

	first := certificateFor(t, agentID, at)
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{Identity: first, Actor: "it-admin", At: at}); err != nil {
		t.Fatalf("bind the first certificate: %v", err)
	}
	told := toldOf(t, registry, agentID)
	if told.GetFingerprintSha256() != first.GetFingerprintSha256() || !told.GetIssuedAt().AsTime().Equal(at) || told.GetReplacedFingerprintSha256() != "" {
		t.Fatalf("the first certificate was told as %v", told)
	}

	second := certificateFor(t, agentID, at.Add(time.Minute))
	request := agentFingerprint(t)
	if _, err := registry.Renew(ctx, agentID, agent.Move{Identity: second, Actor: agentID, At: at.Add(time.Minute),
		PresentedFingerprint: first.GetFingerprintSha256(), Request: request}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	told = toldOf(t, registry, agentID)
	if told.GetFingerprintSha256() != second.GetFingerprintSha256() || told.GetReplacedFingerprintSha256() != first.GetFingerprintSha256() ||
		!told.GetReplacedAt().AsTime().Equal(at.Add(time.Minute)) {
		t.Fatalf("the renewal was told as %v", told)
	}

	third := certificateFor(t, agentID, at.Add(2*time.Minute))
	if _, err := registry.Renew(ctx, agentID, agent.Move{Identity: third, Actor: agentID, At: at.Add(2 * time.Minute),
		PresentedFingerprint: first.GetFingerprintSha256(), Request: request}); err != nil {
		t.Fatalf("renew again after a lost answer: %v", err)
	}
	if told := toldOf(t, registry, agentID); told.GetFingerprintSha256() != third.GetFingerprintSha256() ||
		told.GetReplacedFingerprintSha256() != first.GetFingerprintSha256() || !told.GetReplacedAt().AsTime().Equal(at.Add(2*time.Minute)) {
		t.Fatalf("a renewal asked again was told as %v, and it tolerates what the agent still holds", told)
	}

	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{To: agent.Disabled, Note: "copied", Actor: "it-admin", At: at.Add(3 * time.Minute)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	told = toldOf(t, registry, agentID)
	if told.GetState() != agentv1.State_STATE_DISABLED || told.GetFingerprintSha256() != third.GetFingerprintSha256() ||
		told.GetReplacedFingerprintSha256() != first.GetFingerprintSha256() || !told.GetReplacedAt().AsTime().Equal(at.Add(2*time.Minute)) {
		t.Fatalf("a move that binds nothing changed the certificate told: %v", told)
	}
	state, binding, err := registry.Binding(ctx, agentID)
	if err != nil || state != agent.Disabled || binding.Fingerprint != third.GetFingerprintSha256() || binding.Replaced != first.GetFingerprintSha256() {
		t.Fatalf("the agent listener reads %s bound to %+v (%v)", state, binding, err)
	}

	fourth := certificateFor(t, agentID, at.Add(4*time.Minute))
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{Identity: fourth, Actor: "it-admin", At: at.Add(4 * time.Minute)}); err != nil {
		t.Fatalf("an operator binds another certificate: %v", err)
	}
	if told := toldOf(t, registry, agentID); told.GetFingerprintSha256() != fourth.GetFingerprintSha256() ||
		told.GetReplacedFingerprintSha256() != third.GetFingerprintSha256() {
		t.Fatalf("a certificate an operator bound was told as %v, and it replaced the one in force", told)
	}
	if _, _, err := registry.Binding(ctx, agentIdentifier(t)); !errors.Is(err, agent.ErrUnknown) {
		t.Fatalf("an agent nobody registered is bound to something: %v", err)
	}
}

// What the log holds in an older shape was told the decision already: it is
// written again apart from what is outstanding, and once only. Whether the agent
// is outstanding is read off its own row, since the shared store holds every
// earlier run's decisions (BE-103).
func TestARecordTheLogHoldsInAnOlderShapeIsWrittenAgainOnPostgresql(t *testing.T) {
	address := alertStoreAddress(t)
	store, database := ownRelationalStore(t, address)
	registry := store.Agents()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Millisecond)
	agentID, _, second := renewedOnce(t, registry, at)

	side, err := pgx.Connect(ctx, "postgres://"+storeUser+":seagull@"+address+"/"+database+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect beside the store: %v", err)
	}
	defer func() { _ = side.Close(context.Background()) }()
	outstanding := func() bool {
		var waiting bool
		if err := side.QueryRow(ctx, "SELECT published_revision < revision FROM agents WHERE agent_id = $1", agentID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		return waiting
	}
	if !outstanding() || unwritten(t, registry, agentID) != nil {
		t.Fatal("a renewal nobody published is not outstanding, or is written again as a record held in an older shape")
	}
	if err := registry.Announced(ctx, agentID, 3); err != nil {
		t.Fatal(err)
	}
	if outstanding() || unwritten(t, registry, agentID) != nil {
		t.Fatal("a decision published in the shape this build writes is still waiting")
	}

	if _, err := side.Exec(ctx, "UPDATE agents SET published_format = 0 WHERE agent_id = $1", agentID); err != nil {
		t.Fatalf("make the record one an older build published: %v", err)
	}
	older := unwritten(t, registry, agentID)
	if outstanding() || older == nil || older.GetRevision() != 3 || older.GetFingerprintSha256() != second.GetFingerprintSha256() {
		t.Fatalf("a record held in an older shape is outstanding %t and written again as %v", outstanding(), older)
	}
	if err := registry.Announced(ctx, agentID, older.GetRevision()); err != nil {
		t.Fatal(err)
	}
	if again := unwritten(t, registry, agentID); again != nil {
		t.Fatalf("a record written again is still waiting to be: %v", again)
	}
}

func unwritten(t *testing.T, registry *postgres.Agents, agentID string) *agentv1.Admission {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	older, err := registry.Unwritten(ctx, postgres.MaxPageSize)
	if err != nil {
		t.Fatalf("read what is held in an older shape: %v", err)
	}
	for _, one := range older {
		if one.GetAgentId() == agentID {
			return one
		}
	}
	return nil
}

// A refusal on a route of the agent listener other than renewal is one episode
// with the renewal's refusals while one certificate is in force, and says the
// route it was refused on last; a refusal decided under a binding that has since
// moved records nothing.
func TestAReplacedCertificateRefusedOnTheAgentListenerIsAnEpisodeOfTheCertificateInForceOnPostgresql(t *testing.T) {
	store, _ := ownRelationalStore(t, alertStoreAddress(t))
	registry := store.Agents()
	publishedAll(t, registry)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Millisecond)
	agentID, first, second := renewedOnce(t, registry, at)

	if err := registry.ReplacedUsed(ctx, agentID, second.GetFingerprintSha256(), "GET /v1/agents/policy", at.Add(time.Minute)); err != nil {
		t.Fatalf("record a refusal of the policy route: %v", err)
	}
	if err := registry.ReplacedUsed(ctx, agentID, second.GetFingerprintSha256(), "GET /v1/agents/update", at.Add(2*time.Minute)); err != nil {
		t.Fatalf("record a refusal of the update route: %v", err)
	}
	if err := registry.ReplacedUsed(ctx, agentID, first.GetFingerprintSha256(), "GET /v1/descriptor", at.Add(3*time.Minute)); err != nil {
		t.Fatalf("record a refusal decided under a binding that moved: %v", err)
	}
	mine := unpublishedOf(t, registry, agentID)
	if len(mine) != 1 || mine[0].InForce != second.GetFingerprintSha256() || mine[0].Observations != 2 || mine[0].Route != "GET /v1/agents/update" ||
		!mine[0].OpenedAt.Equal(at.Add(time.Minute)) || !mine[0].LastObservedAt.Equal(at.Add(2*time.Minute)) {
		t.Fatalf("two refusals on the agent listener were kept as %+v", mine)
	}

	if err := registry.Renewable(ctx, agentID, agent.Move{Actor: agentID, At: at.Add(4 * time.Minute), PresentedFingerprint: first.GetFingerprintSha256()}); !errors.Is(err, agent.ErrCertificateReplaced) {
		t.Fatalf("the replaced certificate asked to renew was answered %v", err)
	}
	if mine := unpublishedOf(t, registry, agentID); len(mine) != 1 || mine[0].Observations != 3 || mine[0].Route != "" {
		t.Fatalf("a renewal refused in the same episode left it %+v", mine)
	}

	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{To: agent.Disabled, Note: "copied", Actor: "it-admin", At: at.Add(5 * time.Minute)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	publishedAll(t, registry)
	if err := registry.ReplacedUsed(ctx, agentID, second.GetFingerprintSha256(), "GET /v1/agents/policy", at.Add(6*time.Minute)); err != nil {
		t.Fatalf("record a refusal of an agent no longer admitted: %v", err)
	}
	if mine := unpublishedOf(t, registry, agentID); len(mine) != 0 {
		t.Fatalf("a refusal of an agent no longer admitted reopened its episode: %+v", mine)
	}
	publishedAll(t, registry)
}

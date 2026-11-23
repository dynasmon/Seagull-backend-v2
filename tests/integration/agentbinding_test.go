//go:build integration

package integration_test

import (
	"context"
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

	fourth := certificateFor(t, agentID, at.Add(4*time.Minute))
	if _, err := registry.Move(ctx, agentID, []string{"default"}, agent.Move{Identity: fourth, Actor: "it-admin", At: at.Add(4 * time.Minute)}); err != nil {
		t.Fatalf("an operator binds another certificate: %v", err)
	}
	if told := toldOf(t, registry, agentID); told.GetFingerprintSha256() != fourth.GetFingerprintSha256() ||
		told.GetReplacedFingerprintSha256() != third.GetFingerprintSha256() {
		t.Fatalf("a certificate an operator bound was told as %v, and it replaced the one in force", told)
	}
}

// What the log holds in an older shape was told the decision already: it is
// written again apart from what is outstanding, and once only. Whether the agent
// is outstanding is read off its own row, since the shared store holds every
// earlier run's decisions (BE-103).
func TestARecordTheLogHoldsInAnOlderShapeIsWrittenAgainOnPostgresql(t *testing.T) {
	address := alertStoreAddress(t)
	registry := migratedAlertStore(t, address).Agents()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Millisecond)
	agentID, _, second := renewedOnce(t, registry, at)

	side, err := pgx.Connect(ctx, "postgres://"+storeUser+":seagull@"+address+"/"+storeDatabase+"?sslmode=disable")
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
	for {
		older, err := registry.Unwritten(ctx, postgres.MaxPageSize)
		if err != nil {
			t.Fatalf("read what is held in an older shape: %v", err)
		}
		for _, one := range older {
			if one.GetAgentId() == agentID {
				return one
			}
		}
		if len(older) < postgres.MaxPageSize {
			return nil
		}
		for _, one := range older {
			if err := registry.Announced(ctx, one.GetAgentId(), one.GetRevision()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

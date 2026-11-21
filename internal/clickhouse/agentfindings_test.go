package clickhouse

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfindingstore"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// NewAgentFindingStore runs the same check, so this drift never reaches a
// deployment.
func TestTheAgentFindingAdapterInsertsIntoTheColumnsTheSchemaCreates(t *testing.T) {
	if err := agentFindingsAgreeWithSchema(); err != nil {
		t.Fatalf("the agent finding adapter and the embedded schema disagree: %v", err)
	}
	if fields := reflect.TypeFor[agentfindingstore.Row]().NumField(); fields != len(agentFindingColumns) {
		t.Errorf("a finding row carries %d fields and %s takes %d columns", fields, agentFindingsTable, len(agentFindingColumns))
	}
}

// Where a finding stands is its newest decision, by the platform's clock, and a
// partition by any instant would keep a row per finding that no merge reconciles.
func TestAFindingIsKeptAsItsNewestDecision(t *testing.T) {
	created := 0
	for _, applied := range migrations {
		for _, statement := range applied.statements {
			lowered := strings.ToLower(statement)
			if !strings.Contains(lowered, "create table if not exists "+agentFindingsTable) {
				continue
			}
			created++
			if !strings.Contains(lowered, "replacingmergetree(decided_at)") || !strings.Contains(lowered, "order by (tenant_id, agent_id, finding_id)") {
				t.Errorf("%s keeps a finding otherwise than as its newest decision:\n%s", applied, statement)
			}
			if strings.Contains(lowered, "partition by") {
				t.Errorf("%s partitions %s", applied, agentFindingsTable)
			}
		}
	}
	if created != 1 {
		t.Errorf("%s is created by %d migrations", agentFindingsTable, created)
	}
}

func TestAFindingCursorNamesTheMillisecondAndTheFindingItWasIssuedAt(t *testing.T) {
	at := time.Date(2026, time.November, 21, 12, 0, 0, 123_000_000, time.UTC)
	id := agentfinding.ID("default", "web-01", agentv1.Finding_KIND_SILENCE, "boot", "41")
	millis, decoded, err := decodeFindingCursor(encodeFindingCursor(at, id))
	if err != nil || millis != at.UnixMilli() || decoded != id {
		t.Fatalf("the cursor came back as %d %q (%v)", millis, decoded, err)
	}
	for _, invented := range []string{"not-a-cursor!", encodeFindingCursor(at, "short"), "MTIz"} {
		if _, _, err := decodeFindingCursor(invented); !errors.Is(err, agentfinding.ErrCursor) {
			t.Errorf("the cursor %q was read as %v", invented, err)
		}
	}
}

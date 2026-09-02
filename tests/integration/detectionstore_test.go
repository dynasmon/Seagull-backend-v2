//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstore"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func migratedDetectionStore(t *testing.T, address string) *clickhouse.DetectionStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := clickhouse.NewMigrator(storeSettings(address))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewDetectionStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the detection store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

func madeDetection(owner, id string, at time.Time) *detectionv1.Detection {
	return &detectionv1.Detection{
		DetectionId:   id,
		SchemaVersion: 1,
		Rule: &detectionv1.Rule{
			Id:       "ssh.failed_password_from_outside",
			Revision: 3,
			Name:     "Failed SSH password from outside the estate",
			Source:   &detectionv1.Source{Catalogue: "sigma", Identifier: "5013fd8a"},
		},
		RulesetId: "3538ec98f5ce3e22e8e65f47cd0344ee",
		Severity:  detectionv1.Severity_SEVERITY_HIGH,
		Technique: &detectionv1.Technique{
			Tactic: "credential_access", Id: "T1110.001", Name: "Brute Force: Password Guessing",
		},
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin: &eventv1.Origin{
			TenantId: owner,
			AgentId:  "web-01",
			Host:     &eventv1.Host{Hostname: "web-01.acme.example", Ip: "10.0.0.5", Os: "linux", Architecture: "amd64"},
		},
		SourceEventIds: []string{"aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"},
		EventTime:      timestamppb.New(at),
		DetectedTime:   timestamppb.New(at.Add(time.Second)),
		Evidence: []*detectionv1.Evidence{
			{Field: "authentication.outcome", Operator: "equals", Held: "failure"},
			{Field: "authentication.network.source.ip", Operator: "starts_with", Negated: true, Absent: true},
		},
		Aggregation: &detectionv1.Aggregation{
			Count:          23,
			Threshold:      20,
			Window:         durationpb.New(time.Minute),
			FirstEventTime: timestamppb.New(at.Add(-time.Minute)),
			Saturated:      true,
			Group: []*detectionv1.Grouping{
				{Field: "authentication.network.source.ip", Value: "203.0.113.10"},
				{Field: "origin.agent_id", Value: "web-01"},
			},
		},
	}
}

// Everything a detection carries survives the round trip, evidence included.
// The evidence is the reason the record exists, so a store that kept the finding
// and lost why it was made would be keeping the useless half.
func TestTheStoreKeepsEveryFieldADetectionCarries(t *testing.T) {
	address := storeAddress(t)
	store := migratedDetectionStore(t, address)
	owner := tenant(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Date(2026, time.August, 26, 10, 30, 0, 0, time.UTC)
	made := madeDetection(owner, "bc84b318fe13e6f6ad86d64da0730a07", at)

	if err := store.Store(ctx, []detectionstore.Row{detectionstore.Project(made)}); err != nil {
		t.Fatalf("write the detection: %v", err)
	}

	var (
		detectionID, ruleID, ruleName, catalogue, rulesetID string
		severity, tactic, techniqueID, eventClass, agentID  string
		hostname                                            string
		revision, schemaVersion                             uint32
		sourceEvents, evidenceField, evidenceHeld           []string
		evidenceNegated, evidenceAbsent                     []bool
		eventTime, detectedTime, firstEventTime             time.Time
		count, threshold, window                            uint32
		saturated                                           bool
		groupField, groupValue                              []string
		groupAbsent                                         []bool
	)
	err := inspector(t, address).QueryRow(ctx, `
		SELECT detection_id, schema_version, rule_id, rule_revision, rule_name,
		       rule_source_catalogue, ruleset_id, severity, technique_tactic, technique_id,
		       event_class, agent_id, host_hostname, source_event_ids,
		       event_time, detected_time,
		       evidence_field, evidence_negated, evidence_held, evidence_absent,
		       aggregation_count, aggregation_threshold, aggregation_window_seconds,
		       aggregation_first_event_time, aggregation_saturated,
		       aggregation_group_field, aggregation_group_value, aggregation_group_absent
		FROM security_detections FINAL WHERE tenant_id = ?`, owner,
	).Scan(&detectionID, &schemaVersion, &ruleID, &revision, &ruleName,
		&catalogue, &rulesetID, &severity, &tactic, &techniqueID,
		&eventClass, &agentID, &hostname, &sourceEvents,
		&eventTime, &detectedTime,
		&evidenceField, &evidenceNegated, &evidenceHeld, &evidenceAbsent,
		&count, &threshold, &window, &firstEventTime, &saturated,
		&groupField, &groupValue, &groupAbsent)
	if err != nil {
		t.Fatalf("read the detection back: %v", err)
	}

	for _, check := range []struct{ name, got, want string }{
		{"detection_id", detectionID, "bc84b318fe13e6f6ad86d64da0730a07"},
		{"rule_id", ruleID, "ssh.failed_password_from_outside"},
		{"rule_name", ruleName, "Failed SSH password from outside the estate"},
		{"rule_source_catalogue", catalogue, "sigma"},
		{"ruleset_id", rulesetID, "3538ec98f5ce3e22e8e65f47cd0344ee"},
		{"severity", severity, "high"},
		{"technique_tactic", tactic, "credential_access"},
		{"technique_id", techniqueID, "T1110.001"},
		{"event_class", eventClass, "authentication"},
		{"agent_id", agentID, "web-01"},
		{"host_hostname", hostname, "web-01.acme.example"},
	} {
		if check.got != check.want {
			t.Errorf("%s came back as %q and was written as %q", check.name, check.got, check.want)
		}
	}
	if revision != 3 || schemaVersion != 1 {
		t.Errorf("revision %d and schema version %d came back", revision, schemaVersion)
	}
	if !eventTime.Equal(at) || !detectedTime.Equal(at.Add(time.Second)) {
		t.Errorf("the times came back as %s and %s", eventTime, detectedTime)
	}
	if len(sourceEvents) != 1 || sourceEvents[0] != "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa" {
		t.Errorf("the source events came back as %v", sourceEvents)
	}

	if len(evidenceField) != 2 || len(evidenceHeld) != 2 || len(evidenceNegated) != 2 || len(evidenceAbsent) != 2 {
		t.Fatalf("the evidence came back as %v / %v / %v / %v",
			evidenceField, evidenceHeld, evidenceNegated, evidenceAbsent)
	}
	if evidenceField[0] != "authentication.outcome" || evidenceHeld[0] != "failure" {
		t.Errorf("the first evidence came back as %q holding %q", evidenceField[0], evidenceHeld[0])
	}
	if !evidenceNegated[1] || !evidenceAbsent[1] {
		t.Error("a negated question about a field the event did not carry lost one of the two")
	}

	// What a counting rule found is the finding, so a store that kept the
	// detection and lost the count would be keeping a threshold detection that
	// reads like a single event.
	if count != 23 || threshold != 20 || window != 60 || !saturated {
		t.Errorf("the aggregation came back as %d of %d over %ds, saturated=%v", count, threshold, window, saturated)
	}
	if !firstEventTime.Equal(at.Add(-time.Minute)) {
		t.Errorf("the window came back reaching to %s", firstEventTime)
	}
	if len(groupField) != 2 || len(groupValue) != 2 || len(groupAbsent) != 2 {
		t.Fatalf("the group came back as %v / %v / %v", groupField, groupValue, groupAbsent)
	}
	if groupField[0] != "authentication.network.source.ip" || groupValue[0] != "203.0.113.10" {
		t.Errorf("the first group came back as %q holding %q", groupField[0], groupValue[0])
	}
}

// What an ordering rule found is the finding, and a store that kept the
// detection and lost which event satisfied which stage would keep a story
// nobody could trace to the events it was made of.
func TestTheStoreKeepsWhatASequenceFound(t *testing.T) {
	address := storeAddress(t)
	store := migratedDetectionStore(t, address)
	owner := tenant(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Date(2026, time.September, 1, 10, 30, 0, 0, time.UTC)
	made := madeDetection(owner, "5e9b2a4c6d8e0f1a2b3c4d5e6f708192", at)
	made.Aggregation = nil
	made.SourceEventIds = []string{"aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"}
	made.Correlation = &detectionv1.Correlation{
		Window:      durationpb.New(5 * time.Minute),
		ClockSpread: durationpb.New(1500 * time.Millisecond),
		Stages: []*detectionv1.Stage{
			{Name: "a failed password", EventId: made.SourceEventIds[0], EventTime: timestamppb.New(at.Add(-time.Minute))},
			{Name: "one that was accepted", EventId: made.SourceEventIds[1], EventTime: timestamppb.New(at)},
		},
		Group: []*detectionv1.Grouping{
			{Field: "authentication.network.source.ip", Value: "203.0.113.10"},
			{Field: "origin.agent_id", Value: "web-01"},
		},
	}

	if err := store.Store(ctx, []detectionstore.Row{detectionstore.Project(made)}); err != nil {
		t.Fatalf("write the detection: %v", err)
	}

	var (
		window      uint32
		spread      int64
		stageName   []string
		stageEvent  []string
		stageAt     []time.Time
		groupField  []string
		groupValue  []string
		groupAbsent []bool
	)
	err := inspector(t, address).QueryRow(ctx, `
		SELECT correlation_window_seconds, correlation_clock_spread_millis,
		       correlation_stage_name, correlation_stage_event_id, correlation_stage_event_time,
		       correlation_group_field, correlation_group_value, correlation_group_absent
		FROM security_detections FINAL WHERE tenant_id = ?`, owner,
	).Scan(&window, &spread, &stageName, &stageEvent, &stageAt, &groupField, &groupValue, &groupAbsent)
	if err != nil {
		t.Fatalf("read the detection back: %v", err)
	}

	if window != 300 || spread != 1500 {
		t.Errorf("the story came back over %ds with a spread of %dms", window, spread)
	}
	if len(stageName) != 2 || len(stageEvent) != 2 || len(stageAt) != 2 {
		t.Fatalf("the stages came back as %v / %v / %v", stageName, stageEvent, stageAt)
	}
	if stageName[0] != "a failed password" || stageEvent[1] != made.SourceEventIds[1] {
		t.Errorf("the stages came back as %v satisfied by %v", stageName, stageEvent)
	}
	if !stageAt[0].Equal(at.Add(-time.Minute)) || !stageAt[1].Equal(at) {
		t.Errorf("the stages came back at %s and %s", stageAt[0], stageAt[1])
	}
	if len(groupField) != 2 || groupValue[0] != "203.0.113.10" || groupAbsent[0] {
		t.Errorf("the group came back as %v / %v / %v", groupField, groupValue, groupAbsent)
	}
}

// The property the whole output path rests on, proved against the engine that
// merges rather than against the code that writes: the same detection written
// twice is one row, because it is named by what decided it.
func TestAReplayedDetectionIsOneRow(t *testing.T) {
	address := storeAddress(t)
	store := migratedDetectionStore(t, address)
	owner := tenant(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Date(2026, time.August, 26, 11, 0, 0, 0, time.UTC)
	made := madeDetection(owner, "ffffffff11112222333344445555aaaa", at)
	row := detectionstore.Project(made)

	for range 3 {
		if err := store.Store(ctx, []detectionstore.Row{row}); err != nil {
			t.Fatalf("write the detection: %v", err)
		}
	}

	var deduplicated, written uint64
	if err := inspector(t, address).QueryRow(ctx,
		"SELECT count() FROM security_detections FINAL WHERE tenant_id = ?", owner,
	).Scan(&deduplicated); err != nil {
		t.Fatalf("count the detections: %v", err)
	}
	if err := inspector(t, address).QueryRow(ctx,
		"SELECT count() FROM security_detections WHERE tenant_id = ?", owner,
	).Scan(&written); err != nil {
		t.Fatalf("count the rows: %v", err)
	}

	if deduplicated != 1 {
		t.Errorf("one detection written three times reads back as %d", deduplicated)
	}
	t.Logf("three writes left %d rows before a merge, and %d detection after FINAL", written, deduplicated)
}

// Two detections that differ only in which rule found them are two findings, and
// the table must not collapse them.
func TestTwoRulesFindingTheSameEventAreTwoDetections(t *testing.T) {
	address := storeAddress(t)
	store := migratedDetectionStore(t, address)
	owner := tenant(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	at := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	rows := make([]detectionstore.Row, 0, 2)
	for index, id := range []string{"11111111111111111111111111111111", "22222222222222222222222222222222"} {
		made := madeDetection(owner, id, at)
		made.Rule.Id = fmt.Sprintf("ssh.rule_%d", index)
		rows = append(rows, detectionstore.Project(made))
	}

	if err := store.Store(ctx, rows); err != nil {
		t.Fatalf("write the detections: %v", err)
	}

	var stored uint64
	if err := inspector(t, address).QueryRow(ctx,
		"SELECT count() FROM security_detections FINAL WHERE tenant_id = ?", owner,
	).Scan(&stored); err != nil {
		t.Fatalf("count the detections: %v", err)
	}
	if stored != 2 {
		t.Errorf("two rules finding the same event stored %d detections", stored)
	}
}

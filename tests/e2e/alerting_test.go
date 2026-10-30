package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertfile"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

type shippedRules struct{ programs []*detection.Program }

func (s shippedRules) Current() analysis.Ruleset { return s }

func (s shippedRules) ID() string { return "3538ec98f5ce3e22e8e65f47cd0344ee" }

func (s shippedRules) For(class eventv1.EventClass) iter.Seq[*detection.Program] {
	return func(yield func(*detection.Program) bool) {
		for _, program := range s.programs {
			if program.Rule().Class == class && !yield(program) {
				return
			}
		}
	}
}

type analysedBatch struct{ records []analysis.Record }

func (a analysedBatch) Consume(ctx context.Context, deliver analysis.Deliver) error {
	return deliver(ctx, a.records)
}

type decidedDetections struct{ made []*detectionv1.Detection }

func (d *decidedDetections) Publish(_ context.Context, made []*detectionv1.Detection) error {
	d.made = append(d.made, made...)
	return nil
}

type detectionBatch struct{ records []alertstore.Record }

func (d detectionBatch) Consume(ctx context.Context, deliver alertstore.Deliver) error {
	return deliver(ctx, d.records)
}

type consideredAlerts struct{ candidates []alert.Candidate }

func (c *consideredAlerts) Record(_ context.Context, candidates []alert.Candidate) ([]alert.Outcome, error) {
	c.candidates = append(c.candidates, candidates...)
	outcomes := make([]alert.Outcome, len(candidates))
	for index := range outcomes {
		outcomes[index] = alert.OutcomeRaised
	}
	return outcomes, nil
}

type toldStories struct{}

func (toldStories) Open(_ context.Context, stories []*incidentv1.Incident) ([]incident.Outcome, error) {
	outcomes := make([]incident.Outcome, len(stories))
	for index := range outcomes {
		outcomes[index] = incident.OutcomeRaised
	}
	return outcomes, nil
}

// Two addresses guessing passwords on one agent, each fast enough to cross the
// counting rule's threshold, interleaved so that nothing about arrival order
// keeps them apart.
func guessingFromTwoAddresses(t *testing.T) ([]analysis.Record, map[string]string) {
	t.Helper()

	start := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	addresses := []string{"203.0.113.10", "198.51.100.7"}
	sentFrom := make(map[string]string)

	var records []analysis.Record
	for index := range 42 {
		eventID := fmt.Sprintf("a1b2c3d4-0000-4000-8000-%012d", index)
		sentFrom[eventID] = addresses[index%2]

		record := fixtures.SSHAuthentication{
			EventID:  eventID,
			At:       start.Add(time.Duration(index) * time.Second),
			SourceIP: addresses[index%2],
		}.Event()
		record.Reception = &eventv1.Reception{
			IngestTime: timestamppb.New(start.Add(time.Minute)),
			Gateway:    "e2e-gateway",
			BatchId:    "e2e-batch",
		}
		payload, err := proto.Marshal(record)
		if err != nil {
			t.Fatalf("encode event: %v", err)
		}
		records = append(records, analysis.Record{Offset: int64(index), Key: []byte(record.GetOrigin().GetAgentId()), Value: payload})
	}
	return records, sentFrom
}

func decidedByTheShippedRules(t *testing.T, records []analysis.Record) []*detectionv1.Detection {
	t.Helper()

	programs, err := rulefile.Read(os.DirFS(filepath.Join("..", "..", "deploy", "rules")))
	if err != nil {
		t.Fatalf("read the shipped rules: %v", err)
	}
	keeper, err := detectionstate.NewKeeper(detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 64, Keys: 32, KeysPerTenant: 32, KeysPerRule: 32})
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}

	decided := &decidedDetections{}
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         analysedBatch{records: records},
		Rules:          shippedRules{programs: programs},
		State:          keeper,
		Detections:     decided,
		Metrics:        analysis.NewMetrics(metrics.New("e2e-analysis")),
		Logger:         slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
		PublishTimeout: time.Second,
		RetryDelay:     time.Millisecond,
		MaxRetryDelay:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}
	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("analyse: %v", err)
	}
	return decided.made
}

func consideredByTheShippedDocument(t *testing.T, made []*detectionv1.Detection) ([]alert.Candidate, *bytes.Buffer) {
	t.Helper()

	tuning, err := alertfile.Tuning(os.DirFS(filepath.Join("..", "..", "deploy")), "alerting.yml")
	if err != nil {
		t.Fatalf("read the shipped alerting document: %v", err)
	}

	records := make([]alertstore.Record, 0, len(made))
	for _, one := range made {
		payload, err := proto.Marshal(one)
		if err != nil {
			t.Fatalf("encode detection: %v", err)
		}
		records = append(records, alertstore.Record{Key: []byte(one.GetOrigin().GetAgentId()), Value: payload})
	}

	var logged bytes.Buffer
	considered := &consideredAlerts{}
	writer, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        detectionBatch{records: records},
		Sink:          considered,
		Stories:       toldStories{},
		Tuning:        tuning,
		Floor:         detectionv1.Severity_SEVERITY_MEDIUM,
		Metrics:       alertstore.NewMetrics(metrics.New("e2e-alerts")),
		Logger:        slog.New(slog.NewJSONHandler(&logged, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the alert writer: %v", err)
	}
	if err := writer.Run(context.Background()); err != nil {
		t.Fatalf("consider the detections: %v", err)
	}
	return considered.candidates, &logged
}

// What the local stack ships is what an operator first sees fire, so the
// detections its rules make are folded with its alerting document here: each
// attacker becomes one piece of work, and two attackers never become one.
func TestTheShippedAlertingDocumentFoldsEachAttackerOfAnAgentApart(t *testing.T) {
	records, sentFrom := guessingFromTwoAddresses(t)
	made := decidedByTheShippedRules(t, records)
	candidates, logged := consideredByTheShippedDocument(t, made)

	addressOf := make(map[string]string, len(made))
	for _, one := range made {
		addressOf[one.GetDetectionId()] = sentFrom[one.GetSourceEventIds()[0]]
	}

	keys := map[string]map[string]map[string]struct{}{}
	for _, candidate := range candidates {
		rule, address := candidate.Alert.GetRule().GetId(), addressOf[candidate.DetectionID]
		if keys[rule] == nil {
			keys[rule] = map[string]map[string]struct{}{}
		}
		if keys[rule][address] == nil {
			keys[rule][address] = map[string]struct{}{}
		}
		keys[rule][address][candidate.Key] = struct{}{}
	}

	for _, rule := range []string{"ssh.failed_password_from_outside", "ssh.repeated_failed_password"} {
		first, second := keys[rule]["203.0.113.10"], keys[rule]["198.51.100.7"]
		if len(first) != 1 || len(second) != 1 {
			t.Errorf("%s folded the first address into %d alerts and the second into %d", rule, len(first), len(second))
			continue
		}
		for key := range first {
			if _, shared := second[key]; shared {
				t.Errorf("%s folds two attackers of one agent into the alert %s", rule, key)
			}
		}
	}

	for _, line := range strings.Split(strings.TrimSpace(logged.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode a line the writer logged: %v", err)
		}
		if entry["msg"] == "alert_key_part_unspoken" {
			t.Errorf("the shipped document keys %v on %v, which its detections never speak of", entry["rule"], entry["part"])
		}
	}
}

// What an agent sends is held to the event contract and nothing more: a gateway
// keeps the fields it does not know, and canonicalisation would have lengthened
// an address and every Ⱥ of a host name. None of that may make the detection of
// an attacker's failed password one its consumers refuse.
func TestAnAgentCannotMakeTheDetectionOfItsEventsOneNobodyRaises(t *testing.T) {
	gateway := startGateway(t, gatewayOptions{})
	client := gateway.client(t, "web-01")

	record := fixtures.SSHAuthentication{
		EventID:  "c0ffee00-0000-4000-8000-000000000001",
		Hostname: strings.Repeat("Ⱥ", 127),
		At:       time.Now().UTC().Add(-time.Minute),
	}.Event()
	record.Origin.Host.Ip = "1::3:4:5:6:7:8%" + strings.Repeat("z", 30)
	for _, bloated := range []struct {
		message proto.Message
		size    int
	}{
		{record.GetOrigin().GetHost(), 100 << 10},
		{record.GetOrigin(), 300 << 10},
		{record.GetTime().GetEventTime(), 100 << 10},
	} {
		if !fixtures.Bloat(bloated.message, bloated.size) {
			t.Fatalf("no %T encodes to %d bytes", bloated.message, bloated.size)
		}
	}

	response, payload := gateway.send(t, client, fixtures.Batch("batch-heavy", record))
	if response.StatusCode != http.StatusOK || !decodeAck(t, payload).GetDurable() {
		t.Fatalf("the gateway answered %d: %s", response.StatusCode, payload)
	}

	var records []analysis.Record
	for index, admitted := range gateway.backbone.published {
		encoded, err := proto.Marshal(admitted)
		if err != nil {
			t.Fatalf("encode the admitted event: %v", err)
		}
		records = append(records, analysis.Record{Offset: int64(index), Key: []byte(admitted.GetOrigin().GetAgentId()), Value: encoded})
	}
	made := decidedByTheShippedRules(t, records)
	if len(made) == 0 {
		t.Fatal("the shipped rules decided nothing about a failed password from outside")
	}
	for _, detected := range made {
		if err := detection.ValidateContract(detected); err != nil {
			t.Errorf("%s made a detection its consumers refuse: %v", detected.GetRule().GetId(), err)
		}
	}
	if candidates, _ := consideredByTheShippedDocument(t, made); len(candidates) != len(made) {
		t.Errorf("%d detections raised %d alerts", len(made), len(candidates))
	}
}

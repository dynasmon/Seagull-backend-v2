package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func authenticationOf(t *testing.T, owner, source string, at time.Time, name string, outcome eventv1.Outcome) analysis.Record {
	t.Helper()

	record := fixtures.SSHAuthentication{EventID: name, At: at, SourceIP: source, Outcome: outcome}.Event()
	record.Origin.TenantId = owner
	record.Reception = &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "e2e-gateway", BatchId: "e2e-batch"}
	payload, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return analysis.Record{Key: []byte(record.GetOrigin().GetAgentId()), Value: payload}
}

// Every shipped stateful rule under the bounds a deployment gets by declaring
// nothing: a flood of invented addresses in one tenant, and then another tenant's
// guessing that succeeds.
func floodedBesideAnotherTenant(t *testing.T) ([]*detectionv1.Detection, string) {
	t.Helper()

	start := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	var records []analysis.Record
	for index := range 8_192 {
		source := fmt.Sprintf("198.18.%d.%d", index/256, index%256)
		name := fmt.Sprintf("f1000000-0000-4000-8000-%012d", index)
		records = append(records, authenticationOf(t, "flooding", source, start, name, eventv1.Outcome_OUTCOME_FAILURE))
	}
	for index := range 20 {
		at := start.Add(time.Duration(index) * time.Second)
		name := fmt.Sprintf("a1000000-0000-4000-8000-%012d", index)
		records = append(records, authenticationOf(t, "another", "203.0.113.10", at, name, eventv1.Outcome_OUTCOME_FAILURE))
	}
	records = append(records, authenticationOf(t, "another", "203.0.113.10", start.Add(30*time.Second),
		"a2000000-0000-4000-8000-000000000000", eventv1.Outcome_OUTCOME_SUCCESS))

	programs, err := rulefile.Read(os.DirFS(filepath.Join("..", "..", "deploy", "rules")))
	if err != nil {
		t.Fatalf("read the shipped rules: %v", err)
	}
	keeper, err := detectionstate.NewKeeper(detectionstate.Bounds{
		Window:             time.Hour,
		ObservationsPerKey: 128,
		Keys:               4096,
		KeysPerTenant:      1024,
		KeysPerRule:        512,
	})
	if err != nil {
		t.Fatalf("bound the detection state: %v", err)
	}

	decided := &decidedDetections{}
	registry := metrics.New("e2e-detection-state")
	engine, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         analysedBatch{records: records},
		Rules:          shippedRules{programs: programs},
		State:          keeper,
		Detections:     decided,
		Metrics:        analysis.NewMetrics(registry),
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

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return decided.made, recorder.Body.String()
}

func TestAFloodInOneTenantLeavesTheShippedRulesDecidingForAnother(t *testing.T) {
	made, exposed := floodedBesideAnotherTenant(t)

	decided := map[string]bool{}
	for _, one := range made {
		if one.GetOrigin().GetTenantId() == "another" {
			decided[one.GetRule().GetId()] = true
		}
	}
	for _, rule := range []string{"ssh.repeated_failed_password", "ssh.password_guessing_that_succeeded"} {
		if !decided[rule] {
			t.Errorf("%s decided nothing for the tenant beside the flood, which got %v", rule, decided)
		}
	}
	if !strings.Contains(exposed, `seagull_detection_state_observations_total{outcome="tenant_at_capacity"}`) {
		t.Error("the flood was not refused at its tenant's quota, so this test proves nothing")
	}
}

// Nothing else evaluates a rule file against the process it watches: promtool
// reads recorded series, and a metric or an outcome renamed here would leave an
// alert that looks shipped and can never fire.
func TestTheDetectionStateAlertsReadWhatTheEngineCounts(t *testing.T) {
	_, exposed := floodedBesideAnotherTenant(t)

	written, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus", "detection-state.yml"))
	if err != nil {
		t.Fatalf("read the alert rules: %v", err)
	}
	var rules struct {
		Groups []struct {
			Rules []struct {
				Alert string `yaml:"alert"`
				Expr  string `yaml:"expr"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(written, &rules); err != nil {
		t.Fatalf("decode the alert rules: %v", err)
	}

	var outcomes []string
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			for _, series := range regexp.MustCompile(`seagull_[a-z_]+`).FindAllString(rule.Expr, -1) {
				if !strings.Contains(exposed, "# TYPE "+series+" ") {
					t.Errorf("%s reads %s, which the engine does not export", rule.Alert, series)
				}
			}
			for _, matcher := range regexp.MustCompile(`outcome=~?"([^"]+)"`).FindAllStringSubmatch(rule.Expr, -1) {
				outcomes = append(outcomes, strings.Split(matcher[1], "|")...)
			}
		}
	}

	slices.Sort(outcomes)
	expected := []string{analysis.OutcomeAtCapacity, analysis.OutcomeRuleAtCapacity, analysis.OutcomeTenantAtCapacity}
	slices.Sort(expected)
	if !slices.Equal(outcomes, expected) {
		t.Errorf("the alerts read the outcomes %v, and a key is refused as %v", outcomes, expected)
	}
}

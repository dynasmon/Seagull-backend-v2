package alertstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

const bySourceAddress = alert.Part("evidence:authentication.network.source.ip")

func fromRule(id, rule string, evidence ...*detectionv1.Evidence) *detectionv1.Detection {
	made := detection(id, detectionv1.Severity_SEVERITY_HIGH)
	made.Rule = &detectionv1.Rule{Id: rule, Revision: 1, Name: rule}
	made.Evidence = evidence
	return made
}

func keyedWriter(t *testing.T, from *source, keyed ...alert.Part) (*alertstore.Writer, *bytes.Buffer, *metrics.Registry) {
	t.Helper()

	tuned, err := alert.NewTuning(alert.Fold{Keyed: keyed, Window: 15 * time.Minute}, nil, nil)
	if err != nil {
		t.Fatalf("compile a tuning: %v", err)
	}
	var logged bytes.Buffer
	registry := metrics.New(t.Name())
	made, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        from,
		Sink:          &sink{},
		Stories:       &stories{},
		Tuning:        tuned,
		Floor:         detectionv1.Severity_SEVERITY_MEDIUM,
		Metrics:       alertstore.NewMetrics(registry),
		Logger:        slog.New(slog.NewJSONHandler(&logged, nil)),
		Now:           func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) },
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	return made, &logged, registry
}

func toldUnspoken(t *testing.T, logged *bytes.Buffer) map[string]int {
	t.Helper()

	told := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(logged.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode log entry: %v", err)
		}
		if entry["msg"] != "alert_key_part_unspoken" {
			continue
		}
		rule, _ := entry["rule"].(string)
		part, _ := entry["part"].(string)
		told[rule+" "+part]++
	}
	return told
}

func exposition(t *testing.T, registry *metrics.Registry) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("the metrics endpoint answered %d", recorder.Code)
	}
	return recorder.Body.String()
}

func TestAKeyPartADetectionSaysNothingAboutIsToldOncePerRuleAndCountedEveryTime(t *testing.T) {
	address := &detectionv1.Evidence{
		Field: "authentication.network.source.ip", Operator: "starts_with", Negated: true, Held: `"203.0.113.10"`,
	}
	from := &source{batches: [][]alertstore.Record{
		{
			record(t, fromRule("first", "ssh.repeated_failed_password")),
			record(t, fromRule("second", "ssh.repeated_failed_password")),
			record(t, fromRule("third", "ssh.some_other_rule")),
		},
		{
			record(t, fromRule("fourth", "ssh.repeated_failed_password")),
			record(t, fromRule("carried", "ssh.failed_password_from_outside", address)),
		},
	}}

	made, logged, registry := keyedWriter(t, from, alert.PartRule, alert.PartAgent, bySourceAddress)
	if err := made.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := map[string]int{
		"ssh.repeated_failed_password evidence:authentication.network.source.ip": 1,
		"ssh.some_other_rule evidence:authentication.network.source.ip":          1,
	}
	if told := toldUnspoken(t, logged); !maps.Equal(told, want) {
		t.Errorf("the writer told %v, and the rules that never spoke of the address are %v", told, want)
	}

	counted := `seagull_alertstore_unspoken_key_parts_total{part="evidence:authentication.network.source.ip"} 4`
	if !strings.Contains(exposition(t, registry), counted) {
		t.Errorf("the metrics do not say %s", counted)
	}
}

func TestAKeyEveryDetectionSpeaksOfTellsNothing(t *testing.T) {
	from := &source{batches: [][]alertstore.Record{{
		record(t, fromRule("first", "ssh.repeated_failed_password")),
	}}}

	made, logged, registry := keyedWriter(t, from, alert.PartRule, alert.PartAgent)
	if err := made.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if told := toldUnspoken(t, logged); len(told) != 0 {
		t.Errorf("a key naming no evidence told %v", told)
	}
	if strings.Contains(exposition(t, registry), "seagull_alertstore_unspoken_key_parts_total{") {
		t.Error("a key naming no evidence counted an unspoken part")
	}
}

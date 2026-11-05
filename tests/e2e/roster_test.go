package e2e_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type caughtUp struct{}

func (caughtUp) Behind(context.Context) (int64, time.Time, error) { return 0, time.Now(), nil }

// promtool reads recorded series, so a metric renamed in a process would leave
// an alert that looks shipped and can never fire.
func TestTheRosterAlertsReadWhatTheGatewayAndTheControlPlaneExport(t *testing.T) {
	registry := metrics.New("e2e")
	if _, err := ingest.NewCurrency(ingest.CurrencyOptions{Log: caughtUp{}, Every: 5 * time.Second, StaleAfter: 30 * time.Second,
		Registry: registry, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	control.NewMetrics(registry)
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposed := recorder.Body.String()

	written, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus", "agent-roster.yml"))
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
	read := 0
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			for _, series := range regexp.MustCompile(`seagull_[a-z_]+`).FindAllString(rule.Expr, -1) {
				read++
				if !strings.Contains(exposed, "# TYPE "+series+" ") {
					t.Errorf("%s reads %s, which neither the gateway nor the control plane exports", rule.Alert, series)
				}
			}
		}
	}
	if read != 3 {
		t.Fatalf("the rules read %d series, and this test was written for three", read)
	}
}

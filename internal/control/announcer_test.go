package control_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func gauged(t *testing.T, registry *metrics.Registry, series string) float64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	lines := bufio.NewScanner(strings.NewReader(recorder.Body.String()))
	for lines.Scan() {
		if value, found := strings.CutPrefix(lines.Text(), series+" "); found {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return parsed
		}
	}
	t.Fatalf("%s is not exported", series)
	return 0
}

func TestHowLongTheOldestDecisionNoGatewayWasToldHasWaitedIsReported(t *testing.T) {
	held := newStubAgents()
	told := &stubAdmissions{unreached: errors.New("the backbone is unreachable")}
	registry := metrics.New("test")
	announcer, err := control.NewAnnouncer(control.AnnouncerOptions{Agents: held, Admissions: told, Metrics: control.NewMetrics(registry),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Every: time.Second, Batch: 10})
	if err != nil {
		t.Fatal(err)
	}

	announcer.Sweep(context.Background())
	decided := held.held["web-01"].GetChangedAt().AsTime()
	waited := gauged(t, registry, "seagull_control_agent_admissions_oldest_outstanding_seconds")
	if since := time.Since(decided).Seconds(); waited < since-5 || waited > since+5 {
		t.Fatalf("a decision recorded %0.fs ago and never published is reported as waiting %0.fs", since, waited)
	}
	if outstanding := gauged(t, registry, "seagull_control_agent_admissions_outstanding"); outstanding != 1 {
		t.Fatalf("%v decisions are reported outstanding, and one is", outstanding)
	}

	told.unreached = nil
	announcer.Sweep(context.Background())
	if waited := gauged(t, registry, "seagull_control_agent_admissions_oldest_outstanding_seconds"); waited != 0 {
		t.Fatalf("once every decision was published the oldest is reported as waiting %vs", waited)
	}
	if outstanding := gauged(t, registry, "seagull_control_agent_admissions_outstanding"); outstanding != 0 || len(told.published) != 1 {
		t.Fatalf("%v decisions are reported outstanding after %d were published", outstanding, len(told.published))
	}
}

// The data plane already holds the decision, without the certificate in force:
// it is written again, and no alarm says a decision went unpublished.
func TestARecordTheLogHoldsInAnOlderShapeIsWrittenAgainAndIsNotOutstanding(t *testing.T) {
	held := newStubAgents()
	active(t, held, "web-01")
	held.announced["web-01"] = held.held["web-01"].GetRevision()
	held.older["web-01"] = true
	told := &stubAdmissions{unreached: errors.New("the backbone is unreachable")}
	registry := metrics.New("test")
	announcer, err := control.NewAnnouncer(control.AnnouncerOptions{Agents: held, Admissions: told, Metrics: control.NewMetrics(registry),
		Logger: slog.New(slog.DiscardHandler), Every: time.Second, Batch: 10})
	if err != nil {
		t.Fatal(err)
	}

	announcer.Sweep(context.Background())
	if outstanding := gauged(t, registry, "seagull_control_agent_admissions_outstanding"); outstanding != 0 {
		t.Fatalf("a record held in an older shape is reported as %v decisions outstanding", outstanding)
	}
	if waited := gauged(t, registry, "seagull_control_agent_admissions_oldest_outstanding_seconds"); waited != 0 {
		t.Fatalf("a record held in an older shape is reported as a decision waiting %vs", waited)
	}

	told.unreached = nil
	announcer.Sweep(context.Background())
	if len(told.published) != 1 || told.published[0].GetFingerprintSha256() != held.held["web-01"].GetIdentity().GetFingerprintSha256() ||
		told.published[0].GetRevision() != held.held["web-01"].GetRevision() {
		t.Fatalf("the record was written again as %v", told.published)
	}
	announcer.Sweep(context.Background())
	if len(told.published) != 1 {
		t.Fatalf("a record written again in the shape this build writes was written again %d times", len(told.published)-1)
	}
}

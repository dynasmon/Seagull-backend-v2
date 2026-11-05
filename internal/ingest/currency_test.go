package ingest_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type followedLog struct {
	mu     sync.Mutex
	behind int64
	newest time.Time
	err    error
	asked  []time.Time
	clock  *time.Time
}

func (l *followedLog) Behind(context.Context) (int64, time.Time, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked = append(l.asked, *l.clock)
	*l.clock = l.clock.Add(700 * time.Millisecond)
	return l.behind, l.newest, l.err
}

func (l *followedLog) answer(behind int64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.behind, l.err = behind, err
}

func currencyOf(t *testing.T, log *followedLog, written *bytes.Buffer) (*ingest.Currency, *metrics.Registry) {
	t.Helper()
	registry := metrics.New("test")
	currency, err := ingest.NewCurrency(ingest.CurrencyOptions{
		Log:        log,
		Every:      5 * time.Second,
		StaleAfter: 30 * time.Second,
		Registry:   registry,
		Logger:     slog.New(slog.NewJSONHandler(written, nil)),
		Now:        func() time.Time { return *log.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return currency, registry
}

func TestARosterNeverConfirmedIsStale(t *testing.T) {
	clock := admissionClock
	currency, _ := currencyOf(t, &followedLog{clock: &clock}, &bytes.Buffer{})
	if !currency.Stale() {
		t.Fatal("a gateway that never confirmed its roster against the log would admit by it")
	}
}

func TestARosterIsCurrentAsOfWhenItAskedAndStaleOncePastItsBound(t *testing.T) {
	clock := admissionClock
	log := &followedLog{clock: &clock, newest: admissionClock.Add(-time.Minute)}
	written := &bytes.Buffer{}
	currency, _ := currencyOf(t, log, written)

	currency.Confirm(context.Background())
	asked := log.asked[0]
	if currency.Stale() || !strings.Contains(written.String(), `"msg":"agent_roster_current"`) {
		t.Fatalf("a roster holding everything the log held is stale, and said %s", written)
	}

	clock = asked.Add(30 * time.Second)
	if currency.Stale() {
		t.Fatal("a roster confirmed exactly its bound ago is stale")
	}
	clock = asked.Add(30*time.Second + time.Millisecond)
	if !currency.Stale() {
		t.Fatal("a roster confirmed past its bound, counted from when it asked, is still admitted by")
	}

	for name, answer := range map[string]struct {
		behind int64
		err    error
	}{
		"behind the log":      {behind: 3},
		"the log unreachable": {err: errors.New("dial tcp: connection refused")},
	} {
		log.answer(answer.behind, answer.err)
		clock = asked.Add(time.Hour)
		currency.Confirm(context.Background())
		if !currency.Stale() {
			t.Errorf("a roster %s was confirmed", name)
		}
	}
	if count := strings.Count(written.String(), `"msg":"agent_roster_stale"`); count != 1 {
		t.Errorf("going stale was said %d times: %s", count, written)
	}

	log.answer(0, nil)
	currency.Confirm(context.Background())
	if currency.Stale() || strings.Count(written.String(), `"msg":"agent_roster_current"`) != 2 {
		t.Fatalf("a roster that caught up again is stale, and said %s", written)
	}
}

func TestHowCurrentTheRosterIsCanBeReadFromOutside(t *testing.T) {
	clock := admissionClock
	log := &followedLog{clock: &clock, newest: admissionClock.Add(-90 * time.Second), behind: 7}
	currency, registry := currencyOf(t, log, &bytes.Buffer{})
	currency.Confirm(context.Background())

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposed := recorder.Body.String()
	for _, series := range []string{
		"seagull_ingest_roster_behind_records 7",
		"seagull_ingest_roster_applied_age_seconds 90.7",
		`seagull_ingest_roster_checks_total{outcome="behind"} 1`,
		`seagull_ingest_roster_checks_total{outcome="unreachable"} 0`,
		"seagull_ingest_roster_confirmed_age_seconds 0.7",
	} {
		if !strings.Contains(exposed, series+"\n") {
			t.Errorf("the gateway does not expose %q:\n%s", series, exposed)
		}
	}
}

type stale struct{}

func (stale) Stale() bool { return true }

func TestAGatewayWhoseRosterIsStaleAdmitsNothingAndKeepsEveryBatchSendable(t *testing.T) {
	registry := metrics.New("test")
	capacity, err := ingest.NewCapacity(64<<20, 16)
	if err != nil {
		t.Fatal(err)
	}
	backbone := &recordingBackbone{}
	handler, err := ingest.NewHandler(ingest.HandlerOptions{Admitter: newAdmitter(t, backbone), Roster: describedRoster, Currency: stale{},
		Capacity: capacity, Metrics: ingest.NewMetrics(registry), MaxBodyBytes: describedBody, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := ingest.Routes(ingest.ServerOptions{Handler: handler, Instrumentation: httpx.NewInstrumentation(metrics.New("http"))})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := proto.Marshal(fixtures.Batch("batch-1", sample()))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, ingest.EventsPath, bytes.NewReader(payload))
	request.TLS = presenting("web-01")
	request.Header.Set("Content-Type", ingest.ContentType)
	recorder := httptest.NewRecorder()
	routes.ServeHTTP(recorder, request)

	body, _ := io.ReadAll(recorder.Result().Body)
	var refused ingestv1.Rejection
	if err := proto.Unmarshal(body, &refused); err != nil || recorder.Code != http.StatusServiceUnavailable ||
		refused.GetCode() != ingest.CodeRosterStale || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("a batch was answered %d %q with Retry-After %q (%v)", recorder.Code, refused.GetCode(), recorder.Header().Get("Retry-After"), err)
	}
	if len(backbone.published) != 0 {
		t.Fatal("a gateway that cannot vouch for its roster published a batch")
	}

	described := ask(t, routes, presenting("web-01"))
	if described.StatusCode != http.StatusServiceUnavailable || described.Header.Get("ETag") != "" {
		t.Fatalf("the descriptor was answered %d with the tag %q", described.StatusCode, described.Header.Get("ETag"))
	}
}

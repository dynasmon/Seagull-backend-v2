package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

type discarded struct{}

func (discarded) PublishEvents(context.Context, []*eventv1.Event) error                { return nil }
func (discarded) PublishInventory(context.Context, []*inventoryv1.Record) error        { return nil }
func (discarded) PublishStatus(context.Context, []*agentv1.Status) error               { return nil }
func (discarded) PublishAssessments(context.Context, []*assessmentv1.Assessment) error { return nil }

type admitsOne string

func (a admitsOne) Tenant(agentID string) (string, bool) { return "acme", agentID == string(a) }
func (a admitsOne) Knows(agentID string) bool            { return agentID == string(a) }

func TestTheDescriptorServesTheLimitsTheGatewayIsConfiguredWith(t *testing.T) {
	settings, err := load(environment(t, map[string]string{
		"SEAGULL_GATEWAY_MAX_BODY":                  "3MiB",
		"SEAGULL_GATEWAY_MAX_EVENTS_PER_BATCH":      "777",
		"SEAGULL_EVENT_MAX_CLOCK_SKEW":              "7m",
		"SEAGULL_EVENT_MAX_AGE":                     "101h",
		"SEAGULL_GATEWAY_MAX_RECORDS_PER_BATCH":     "33",
		"SEAGULL_INVENTORY_MAX_CLOCK_SKEW":          "6m",
		"SEAGULL_INVENTORY_MAX_AGE":                 "501h",
		"SEAGULL_GATEWAY_MAX_REPORTS_PER_BATCH":     "9",
		"SEAGULL_STATUS_MAX_CLOCK_SKEW":             "3m",
		"SEAGULL_STATUS_MAX_AGE":                    "99h",
		"SEAGULL_GATEWAY_MAX_ASSESSMENTS_PER_BATCH": "7",
		"SEAGULL_ASSESSMENT_MAX_CLOCK_SKEW":         "2m",
		"SEAGULL_ASSESSMENT_MAX_AGE":                "601h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	served, err := routes(settings, sinks{events: discarded{}, inventory: discarded{}, status: discarded{}, assessments: discarded{}},
		admitsOne("web-01"), metrics.New("ingest-gateway"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	served.Instrumentation = httpx.NewInstrumentation(metrics.New("ingest-gateway-routes"))
	handler, err := ingest.Routes(served)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, ingest.DescriptorPath, nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: "web-01"}}}}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body, _ := io.ReadAll(recorder.Result().Body)
	var described platformv1.Descriptor
	if err := proto.Unmarshal(body, &described); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("the gateway described itself with %d (%v): %s", recorder.Code, err, body)
	}

	if described.GetMaxBodyBytes() != 3<<20 {
		t.Errorf("the gateway reads bodies of %d bytes and describes %d", 3<<20, described.GetMaxBodyBytes())
	}
	configured := map[string]struct {
		records   uint32
		age, skew time.Duration
	}{
		ingest.EventsRoute:      {records: 777, age: 101 * time.Hour, skew: 7 * time.Minute},
		ingest.InventoryRoute:   {records: 33, age: 501 * time.Hour, skew: 6 * time.Minute},
		ingest.StatusRoute:      {records: 9, age: 99 * time.Hour, skew: 3 * time.Minute},
		ingest.AssessmentsRoute: {records: 7, age: 601 * time.Hour, skew: 2 * time.Minute},
	}
	for _, stream := range described.GetStreams() {
		want, known := configured[stream.GetRoute()]
		if !known {
			t.Errorf("the gateway describes %s, which it is not configured to admit", stream.GetRoute())
			continue
		}
		delete(configured, stream.GetRoute())
		if stream.GetMaxRecordsPerBatch() != want.records || stream.GetMaxAge().AsDuration() != want.age || stream.GetMaxClockSkew().AsDuration() != want.skew {
			t.Errorf("%s is described with %d records, %v old and %v ahead, and configured with %+v", stream.GetRoute(),
				stream.GetMaxRecordsPerBatch(), stream.GetMaxAge().AsDuration(), stream.GetMaxClockSkew().AsDuration(), want)
		}
	}
	for route := range configured {
		t.Errorf("the gateway admits %s and does not describe it", route)
	}
}

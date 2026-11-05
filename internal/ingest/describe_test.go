package ingest_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

type heldRoster struct {
	tenants map[string]string
	known   map[string]bool
}

func (r heldRoster) Tenant(agentID string) (string, bool) {
	tenant, admitted := r.tenants[agentID]
	return tenant, admitted
}

func (r heldRoster) Knows(agentID string) bool { return r.known[agentID] }

type current struct{}

func (current) Stale() bool { return false }

var describedRoster = heldRoster{
	tenants: map[string]string{"web-01": "acme"},
	known:   map[string]bool{"web-01": true, "web-02": true},
}

var (
	eventRules      = ingest.Policy{Gateway: "gateway-a", MaxEventsPerBatch: 11, Event: event.Policy{MaxClockSkew: 4 * time.Minute, MaxAge: 100 * time.Hour}}
	inventoryRules  = ingest.InventoryPolicy{Gateway: "gateway-a", MaxRecordsPerBatch: 5, Record: event.Policy{MaxClockSkew: 3 * time.Minute, MaxAge: 200 * time.Hour}}
	statusRules     = ingest.StatusPolicy{Gateway: "gateway-a", MaxReportsPerBatch: 3, Report: event.Policy{MaxClockSkew: 2 * time.Minute, MaxAge: 50 * time.Hour}}
	assessmentRules = ingest.AssessmentPolicy{Gateway: "gateway-a", MaxAssessmentsPerBatch: 2, Assessment: event.Policy{MaxClockSkew: time.Minute, MaxAge: 300 * time.Hour}}
)

const describedBody = 2 << 20

func describing(t *testing.T, limiter *ratelimit.Limiter) http.Handler {
	t.Helper()
	registry := metrics.New("test")
	capacity, err := ingest.NewCapacity(64<<20, 16)
	if err != nil {
		t.Fatal(err)
	}

	events, err := ingest.NewAdmitter(&recordingBackbone{}, eventRules, ingest.NewMetrics(registry))
	if err != nil {
		t.Fatal(err)
	}
	assets, err := ingest.NewInventoryAdmitter(&recordingInventory{}, inventoryRules, ingest.NewInventoryMetrics(registry))
	if err != nil {
		t.Fatal(err)
	}
	reports, err := ingest.NewStatusAdmitter(&recordingStatus{}, statusRules, ingest.NewStatusMetrics(registry))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ingest.NewAssessmentAdmitter(&recordingAssessments{}, assessmentRules, ingest.NewAssessmentMetrics(registry))
	if err != nil {
		t.Fatal(err)
	}

	eventHandler, err := ingest.NewHandler(ingest.HandlerOptions{Admitter: events, Roster: describedRoster, Currency: current{}, Limiter: limiter,
		Capacity: capacity, Metrics: ingest.NewMetrics(metrics.New("events")), MaxBodyBytes: describedBody, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	inventoryHandler, err := ingest.NewInventoryHandler(ingest.InventoryHandlerOptions{Admitter: assets, Roster: describedRoster, Currency: current{}, Limiter: limiter,
		Capacity: capacity, Metrics: ingest.NewInventoryMetrics(metrics.New("inventory")), MaxBodyBytes: describedBody, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	statusHandler, err := ingest.NewStatusHandler(ingest.StatusHandlerOptions{Admitter: reports, Roster: describedRoster, Currency: current{}, Limiter: limiter,
		Capacity: capacity, Metrics: ingest.NewStatusMetrics(metrics.New("status")), MaxBodyBytes: describedBody, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	assessmentHandler, err := ingest.NewAssessmentHandler(ingest.AssessmentHandlerOptions{Admitter: findings, Roster: describedRoster, Currency: current{}, Limiter: limiter,
		Capacity: capacity, Metrics: ingest.NewAssessmentMetrics(metrics.New("assessments")), MaxBodyBytes: describedBody, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	routes, err := ingest.Routes(ingest.ServerOptions{Handler: eventHandler, Inventory: inventoryHandler, Status: statusHandler,
		Assessments: assessmentHandler, Instrumentation: httpx.NewInstrumentation(metrics.New("http"))})
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

func presenting(agentID string) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: agentID}}}}}
}

func ask(t *testing.T, routes http.Handler, state *tls.ConnectionState, held ...string) *http.Response {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, ingest.DescriptorPath, nil)
	request.TLS = state
	for _, tag := range held {
		request.Header.Add("If-None-Match", tag)
	}
	recorder := httptest.NewRecorder()
	routes.ServeHTTP(recorder, request)
	return recorder.Result()
}

func readDescriptor(t *testing.T, answered *http.Response) *platformv1.Descriptor {
	t.Helper()
	body, err := io.ReadAll(answered.Body)
	if err != nil {
		t.Fatal(err)
	}
	if answered.StatusCode != http.StatusOK || answered.Header.Get("Content-Type") != ingest.ContentType {
		t.Fatalf("the descriptor was answered %d as %q: %s", answered.StatusCode, answered.Header.Get("Content-Type"), body)
	}
	var described platformv1.Descriptor
	if err := proto.Unmarshal(body, &described); err != nil {
		t.Fatalf("decode the descriptor: %v", err)
	}
	return &described
}

func TestTheGatewayDescribesEveryStreamItRoutesAsItsAdmitterJudgesIt(t *testing.T) {
	before := time.Now()
	described := readDescriptor(t, ask(t, describing(t, nil), presenting("web-01")))

	if described.GetProtocolVersion() != protocol.Version || described.GetSupportedProtocol().GetMaximum() != protocol.MaxVersion ||
		described.GetSupportedEventSchema().GetMaximum() != event.MaxSchemaVersion {
		t.Errorf("the descriptor speaks protocol %d %v and event schema %v", described.GetProtocolVersion(),
			described.GetSupportedProtocol(), described.GetSupportedEventSchema())
	}
	if answered := described.GetServerTime().AsTime(); answered.Before(before.Add(-time.Second)) || answered.After(time.Now().Add(time.Second)) {
		t.Errorf("the descriptor says it was answered at %v", answered)
	}
	if described.GetMaxBodyBytes() != describedBody || len(described.GetCapabilities()) != 0 {
		t.Errorf("the gateway describes a body of %d and capabilities %v", described.GetMaxBodyBytes(), described.GetCapabilities())
	}

	type limits struct {
		route, batch, record       string
		schema                     [2]uint32
		records, items, itemsBatch uint32
		ceiling                    int
		age, skew                  time.Duration
	}
	wanted := []limits{
		{route: ingest.EventsRoute, batch: "seagull.ingest.v1.EventBatch", record: "seagull.event.v1.Event",
			schema: [2]uint32{event.MinSchemaVersion, event.MaxSchemaVersion}, records: 11, ceiling: event.MaxEventBytes,
			age: 100 * time.Hour, skew: 4 * time.Minute},
		{route: ingest.InventoryRoute, batch: "seagull.inventory.v1.RecordBatch", record: "seagull.inventory.v1.Record",
			schema: [2]uint32{inventory.MinSchemaVersion, inventory.MaxSchemaVersion}, records: 5, ceiling: inventory.MaxRecordBytes,
			items: inventory.MaxItemsPerRecord, itemsBatch: inventory.MaxItemsPerBatch, age: 200 * time.Hour, skew: 3 * time.Minute},
		{route: ingest.StatusRoute, batch: "seagull.agent.v1.StatusBatch", record: "seagull.agent.v1.Status",
			schema: [2]uint32{agentstatus.MinSchemaVersion, agentstatus.MaxSchemaVersion}, records: 3, ceiling: agentstatus.MaxReportBytes,
			age: 50 * time.Hour, skew: 2 * time.Minute},
		{route: ingest.AssessmentsRoute, batch: "seagull.assessment.v1.AssessmentBatch", record: "seagull.assessment.v1.Assessment",
			schema: [2]uint32{assessment.MinSchemaVersion, assessment.MaxSchemaVersion}, records: 2, ceiling: assessment.MaxAssessmentBytes,
			age: 300 * time.Hour, skew: time.Minute},
	}
	if len(described.GetStreams()) != len(wanted) {
		t.Fatalf("the gateway describes %d streams, and it routes %d", len(described.GetStreams()), len(wanted))
	}
	for index, want := range wanted {
		got := described.GetStreams()[index]
		if got.GetRoute() != want.route || got.GetBatch() != want.batch || got.GetRecord() != want.record ||
			got.GetSupportedSchema().GetMinimum() != want.schema[0] || got.GetSupportedSchema().GetMaximum() != want.schema[1] ||
			got.GetMaxRecordsPerBatch() != want.records || got.GetMaxItemsPerRecord() != want.items || got.GetMaxItemsPerBatch() != want.itemsBatch ||
			got.GetMaxAge().AsDuration() != want.age || got.GetMaxClockSkew().AsDuration() != want.skew {
			t.Errorf("stream %d is described as %v, and its admitter judges it as %+v", index, got, want)
		}
		if room := want.ceiling - int(got.GetMaxRecordBytes()); room <= 0 || room > 1024 {
			t.Errorf("%s describes records of %d bytes against a ceiling of %d", want.route, got.GetMaxRecordBytes(), want.ceiling)
		}
	}
}

// A record that encodes to exactly what its stream describes is admitted with
// the heaviest stamp the gateway can put on it, whether it carried no origin or
// one whose length prefix the stamp pushes past a varint boundary.
func TestARecordKeptWithinTheDescribedSizeIsNeverRefusedForIt(t *testing.T) {
	described := readDescriptor(t, ask(t, describing(t, nil), presenting("web-01")))
	sizes := map[string]int{}
	for _, stream := range described.GetStreams() {
		sizes[stream.GetRoute()] = int(stream.GetMaxRecordBytes())
	}

	longest := ingest.Policy{Gateway: strings.Repeat("g", event.MaxGatewayLength), MaxEventsPerBatch: 1, Event: eventRules.Event}
	agentID, tenant, batchID := strings.Repeat("a", event.MaxAgentIDLength), strings.Repeat("t", event.MaxTenantIDLength), strings.Repeat("b", event.MaxBatchIDLength)
	heaviest := agentidentity.Identity{AgentID: agentID}
	clock := func() time.Time { return admissionClock }
	registry := metrics.New("test")

	events, err := ingest.NewAdmitter(&recordingBackbone{}, longest, ingest.NewMetrics(registry), ingest.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	assets, err := ingest.NewInventoryAdmitter(&recordingInventory{},
		ingest.InventoryPolicy{Gateway: longest.Gateway, MaxRecordsPerBatch: 1, Record: inventoryRules.Record},
		ingest.NewInventoryMetrics(registry), ingest.WithInventoryClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	reports, err := ingest.NewStatusAdmitter(&recordingStatus{},
		ingest.StatusPolicy{Gateway: longest.Gateway, MaxReportsPerBatch: 1, Report: statusRules.Report},
		ingest.NewStatusMetrics(registry), ingest.WithStatusClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ingest.NewAssessmentAdmitter(&recordingAssessments{},
		ingest.AssessmentPolicy{Gateway: longest.Gateway, MaxAssessmentsPerBatch: 1, Assessment: assessmentRules.Assessment},
		ingest.NewAssessmentMetrics(registry), ingest.WithAssessmentClock(clock))
	if err != nil {
		t.Fatal(err)
	}

	for _, hostname := range []int{-1, 0, 1, 60, 119, 120, 121, 122, 123, 124, 125, 126, 200, event.MaxHostnameLength} {
		origin := func() *eventv1.Origin {
			if hostname < 0 {
				return nil
			}
			return &eventv1.Origin{Host: &eventv1.Host{Hostname: strings.Repeat("h", hostname)}}
		}

		record := sample()
		record.Origin = origin()
		weigh(t, record, sizes[ingest.EventsRoute])
		if _, err := events.Admit(context.Background(), heaviest, tenant, &ingestv1.EventBatch{
			ProtocolVersion: protocol.Version, BatchId: batchID, Events: []*eventv1.Event{record}}); err != nil {
			t.Errorf("an event of the described %d bytes, its host named in %d bytes, was refused: %v", sizes[ingest.EventsRoute], hostname, err)
		}

		snapshot := scan()
		snapshot.Origin = origin()
		weigh(t, snapshot, sizes[ingest.InventoryRoute])
		if _, err := assets.Admit(context.Background(), heaviest, tenant, fixtures.InventoryBatch(batchID, snapshot)); err != nil {
			t.Errorf("an inventory record of the described %d bytes, its host named in %d bytes, was refused: %v", sizes[ingest.InventoryRoute], hostname, err)
		}

		report := reported()
		report.Origin = origin()
		weigh(t, report, sizes[ingest.StatusRoute])
		if _, err := reports.Admit(context.Background(), heaviest, tenant, &agentv1.StatusBatch{
			ProtocolVersion: protocol.Version, BatchId: batchID, Reports: []*agentv1.Status{report}}); err != nil {
			t.Errorf("a report of the described %d bytes, its host named in %d bytes, was refused: %v", sizes[ingest.StatusRoute], hostname, err)
		}

		assessed := posture()
		assessed.Origin = origin()
		weigh(t, assessed, sizes[ingest.AssessmentsRoute])
		if _, err := findings.Admit(context.Background(), heaviest, tenant, &assessmentv1.AssessmentBatch{
			ProtocolVersion: protocol.Version, BatchId: batchID, Assessments: []*assessmentv1.Assessment{assessed}}); err != nil {
			t.Errorf("an assessment of the described %d bytes, its host named in %d bytes, was refused: %v", sizes[ingest.AssessmentsRoute], hostname, err)
		}
	}
}

func weigh(t *testing.T, record proto.Message, size int) {
	t.Helper()
	const unknown = 536_870_911
	base := proto.Size(record)
	for length := size - base; length >= 0; length-- {
		padding := protowire.AppendBytes(protowire.AppendTag(nil, unknown, protowire.BytesType), make([]byte, length))
		if base+len(padding) == size {
			record.ProtoReflect().SetUnknown(padding)
			return
		}
	}
	t.Fatalf("no padding brings a record of %d bytes to %d", base, size)
}

func TestAnAgentTheStreamsWouldRefuseIsRefusedTheDescriptorAlike(t *testing.T) {
	routes := describing(t, nil)
	for name, tested := range map[string]struct {
		state  *tls.ConnectionState
		status int
		code   string
	}{
		"no certificate":              {state: nil, status: http.StatusForbidden, code: "unauthenticated_agent"},
		"an agent never registered":   {state: presenting("web-03"), status: http.StatusForbidden, code: ingest.CodeNotRegistered},
		"an agent no longer admitted": {state: presenting("web-02"), status: http.StatusForbidden, code: ingest.CodeNotAdmitted},
	} {
		t.Run(name, func(t *testing.T) {
			answered := ask(t, routes, tested.state)
			body, _ := io.ReadAll(answered.Body)
			var refused ingestv1.Rejection
			if err := proto.Unmarshal(body, &refused); err != nil || answered.StatusCode != tested.status || refused.GetCode() != tested.code {
				t.Fatalf("the descriptor was answered %d %q (%v), and the streams answer %d %q", answered.StatusCode, refused.GetCode(), err, tested.status, tested.code)
			}
			if answered.Header.Get("ETag") != "" {
				t.Fatal("a refused agent was told the tag of what the gateway describes")
			}
		})
	}

	limited := describing(t, ratelimit.NewLimiter(1, 1, 8))
	if first := ask(t, limited, presenting("web-01")); first.StatusCode != http.StatusOK {
		t.Fatalf("the first descriptor was answered %d", first.StatusCode)
	}
	if again := ask(t, limited, presenting("web-01")); again.StatusCode != http.StatusTooManyRequests || again.Header.Get("Retry-After") == "" {
		t.Fatalf("an agent past its budget was answered %d, and its batches would be answered 429", again.StatusCode)
	}
}

func TestADescriptorAskedAgainWithItsTagIsAnsweredUnchanged(t *testing.T) {
	routes := describing(t, nil)
	first := ask(t, routes, presenting("web-01"))
	tag := first.Header.Get("ETag")
	if first.StatusCode != http.StatusOK || tag == "" || first.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("the descriptor was answered %d with the tag %q and %q", first.StatusCode, tag, first.Header.Get("Cache-Control"))
	}

	time.Sleep(2 * time.Millisecond)
	unchanged := ask(t, routes, presenting("web-01"), tag)
	body, _ := io.ReadAll(unchanged.Body)
	if unchanged.StatusCode != http.StatusNotModified || len(body) != 0 || unchanged.Header.Get("ETag") != tag {
		t.Fatalf("asked again with its tag, the descriptor was answered %d with %d bytes and the tag %q", unchanged.StatusCode, len(body), unchanged.Header.Get("ETag"))
	}

	if other := ask(t, routes, presenting("web-01"), `"0123456789abcdef0123456789abcdef"`); other.StatusCode != http.StatusOK || other.Header.Get("ETag") != tag {
		t.Fatalf("asked with another tag, the descriptor was answered %d with the tag %q", other.StatusCode, other.Header.Get("ETag"))
	}
	if again := ask(t, describing(t, nil), presenting("web-01")); again.Header.Get("ETag") != tag {
		t.Fatalf("a second gateway with the same settings tags its descriptor %q, and the first %q", again.Header.Get("ETag"), tag)
	}
}

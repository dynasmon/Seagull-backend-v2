package hunt_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

func handler(t *testing.T, dataset hunt.Dataset, source hunt.Source) *hunt.Handler {
	t.Helper()

	built, err := hunt.NewHandler(dataset, hunt.HandlerOptions{Hunter: hunter(t, source), MaxBodyBytes: 4 << 10})
	if err != nil {
		t.Fatalf("build the handler: %v", err)
	}
	return built
}

func query(t *testing.T, body *huntv1.Query, tenants ...string) *http.Request {
	t.Helper()

	encoded, err := proto.Marshal(body)
	if err != nil {
		t.Fatalf("encode the query: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, hunt.EventsPath, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", hunt.ContentType)
	if tenants != nil {
		request.TLS = verified(certificate("analyst-01", tenants))
	}
	return request
}

func answered(t *testing.T, recorder *httptest.ResponseRecorder, into proto.Message) {
	t.Helper()

	if err := proto.Unmarshal(recorder.Body.Bytes(), into); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
}

// Authorisation is decided before the body is read, so a caller nobody
// authenticated never reaches the store and never learns whether their query
// would have been valid.
func TestACallerWithNoCertificateIsRefusedBeforeTheQueryIsRead(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, &store{}).ServeHTTP(recorder, query(t, asked(nil)))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("an unauthenticated caller was answered with %d", recorder.Code)
	}
	var refusal huntv1.Refusal
	answered(t, recorder, &refusal)
	if refusal.GetCode() != hunt.CodeUnscoped {
		t.Errorf("refused as %q", refusal.GetCode())
	}
}

func TestAQueryIsAnsweredWithAPage(t *testing.T) {
	source := &store{events: []*eventv1.Event{stored("aaaa", day)}}

	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, source).ServeHTTP(recorder, query(t, asked(nil), "acme"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("a valid query was answered with %d: %s", recorder.Code, recorder.Body)
	}
	var page huntv1.EventPage
	answered(t, recorder, &page)
	if len(page.GetEvents()) != 1 || page.GetEvents()[0].GetEventId() != "aaaa" {
		t.Errorf("the page carried %d events", len(page.GetEvents()))
	}
	if got := recorder.Header().Get("Content-Type"); got != hunt.ContentType {
		t.Errorf("the answer was sent as %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("an answer about somebody's telemetry may be cached: %q", got)
	}
}

func TestADetectionsQueryIsAnsweredWithDetections(t *testing.T) {
	source := &store{detections: []*detectionv1.Detection{{DetectionId: "dddd", EventTime: timestamppb.New(day)}}}

	recorder := httptest.NewRecorder()
	handler(t, hunt.Detections, source).ServeHTTP(recorder, query(t, asked(nil), "acme"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("a valid query was answered with %d: %s", recorder.Code, recorder.Body)
	}
	var page huntv1.DetectionPage
	answered(t, recorder, &page)
	if len(page.GetDetections()) != 1 {
		t.Errorf("the page carried %d detections", len(page.GetDetections()))
	}
}

func TestARefusedQueryNamesTheFieldAtFault(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, &store{}).ServeHTTP(recorder, query(t,
		asked(predicate("authentication.user.password", huntv1.Operator_OPERATOR_EQUALS, "x")), "acme"))

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a query naming a field nobody stores was answered with %d", recorder.Code)
	}
	var refusal huntv1.Refusal
	answered(t, recorder, &refusal)
	if refusal.GetCode() != hunt.CodeUnknownField || refusal.GetField() != "authentication.user.password" {
		t.Errorf("refused as %q on %q", refusal.GetCode(), refusal.GetField())
	}
}

func TestAQueryThatIsNotProtobufIsRefused(t *testing.T) {
	request := query(t, asked(nil), "acme")
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, &store{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a query sent as JSON was answered with %d", recorder.Code)
	}
}

func TestABodyBeyondTheCeilingIsRefused(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, hunt.EventsPath, bytes.NewReader(make([]byte, 8<<10)))
	request.Header.Set("Content-Type", hunt.ContentType)
	request.TLS = verified(certificate("analyst-01", []string{"acme"}))

	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, &store{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body twice the ceiling was answered with %d", recorder.Code)
	}
}

// A store that could not answer is the platform's problem, and the caller is
// told to come back rather than told their query was wrong.
func TestAStoreThatCouldNotAnswerIsNotTheCallersFault(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, &store{err: errors.New("connection refused")}).
		ServeHTTP(recorder, query(t, asked(nil), "acme"))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unreachable store was answered with %d", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Error("the caller was not told when to come back")
	}
}

func TestAStoreThatRanOutOfTimeSaysSo(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler(t, hunt.Events, &store{linger: time.Minute, err: context.DeadlineExceeded}).
		ServeHTTP(recorder, query(t, asked(nil), "acme"))

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("a store that ran out of time was answered with %d", recorder.Code)
	}
}

func TestAHandlerNeedsAHunterACeilingAndADataset(t *testing.T) {
	if _, err := hunt.NewHandler(hunt.Events, hunt.HandlerOptions{MaxBodyBytes: 1024}); err == nil {
		t.Error("a handler was built with nothing to ask")
	}
	if _, err := hunt.NewHandler("alerts", hunt.HandlerOptions{Hunter: hunter(t, &store{}), MaxBodyBytes: 1024}); err == nil {
		t.Error("a handler was built for a dataset no store holds")
	}
}

package httpx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type safeBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (s *safeBuffer) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buffer.Write(payload)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buffer.String()
}

func serve(t *testing.T, handler http.Handler, logger *slog.Logger) (string, chan error, context.CancelFunc) {
	t.Helper()

	server, err := httpx.NewServer(httpx.ServerOptions{
		Name:              "test",
		Address:           "127.0.0.1:0",
		Handler:           handler,
		Logger:            logger,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
		ShutdownTimeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- server.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-stopped:
			if err != nil {
				t.Errorf("server stopped with an error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("server did not stop")
		}
	})
	return server.Address(), stopped, cancel
}

func call(t *testing.T, address, path string) *http.Response {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)

	response, err := client.Get("http://" + address + path)
	if err != nil {
		t.Fatalf("call %s: %v", path, err)
	}
	t.Cleanup(func() { response.Body.Close() })
	_, _ = io.Copy(io.Discard, response.Body)
	return response
}

func TestBindFailureIsReportedBeforeAnythingRuns(t *testing.T) {
	_, err := httpx.NewServer(httpx.ServerOptions{
		Name:    "test",
		Address: "256.256.256.256:1",
		Handler: http.NewServeMux(),
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("a server that cannot bind must fail at construction")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Fatalf("the failure does not explain itself: %v", err)
	}
}

// Handlers log through the server's logger, not through the process default:
// a request line has to carry the same identity and format as the rest.
func TestRequestsLogThroughTheServerLogger(t *testing.T) {
	captured := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(captured, &slog.HandlerOptions{Level: slog.LevelDebug})).
		With(slog.String("service", "test-service"))

	instrumentation := httpx.NewInstrumentation(metrics.New("test-service"))
	mux := http.NewServeMux()
	mux.Handle("GET /thing", instrumentation.Handle("thing", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	address, _, _ := serve(t, mux, logger)
	call(t, address, "/thing")

	var served map[string]any
	for _, line := range strings.Split(strings.TrimSpace(captured.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			t.Fatalf("a log line was not structured: %s", line)
		}
		if entry["msg"] == "request_served" {
			served = entry
		}
	}
	if served == nil {
		t.Fatalf("no request line was logged: %s", captured.String())
	}
	for _, field := range []string{"service", "request_id", "route", "status", "elapsed"} {
		if _, present := served[field]; !present {
			t.Fatalf("%s missing from the request line: %v", field, served)
		}
	}
	if served["route"] != "thing" {
		t.Fatalf("unexpected route label %v", served["route"])
	}
}

func TestCallerCannotChooseTheRequestIdentifier(t *testing.T) {
	captured := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(captured, &slog.HandlerOptions{Level: slog.LevelDebug}))

	instrumentation := httpx.NewInstrumentation(metrics.New("test-service"))
	mux := http.NewServeMux()
	mux.Handle("GET /thing", instrumentation.Handle("thing", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	address, _, _ := serve(t, mux, logger)

	client := &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	request, err := http.NewRequest(http.MethodGet, "http://"+address+"/thing", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("X-Request-Id", "chosen-by-the-caller")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	defer response.Body.Close()

	if strings.Contains(captured.String(), "chosen-by-the-caller") {
		t.Fatalf("a caller chose what identifies its request in the logs: %s", captured.String())
	}
}

func TestPanickingHandlerAnswersAndIsCounted(t *testing.T) {
	captured := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(captured, nil))

	registry := metrics.New("test-service")
	instrumentation := httpx.NewInstrumentation(registry)
	mux := http.NewServeMux()
	mux.Handle("GET /boom", instrumentation.Handle("boom", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler fell over")
	})))

	address, _, _ := serve(t, mux, logger)

	response := call(t, address, "/boom")
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.StatusCode)
	}
	if !strings.Contains(captured.String(), "handler_panic") {
		t.Fatalf("the panic was not reported: %s", captured.String())
	}

	exposition := httptestExposition(t, registry)
	if !strings.Contains(exposition, `seagull_http_handler_panics_total{route="boom"}`) {
		t.Fatalf("the panic was not counted: %s", exposition)
	}
}

func TestUnmatchedRouteStillAnswers(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	address, _, _ := serve(t, http.NewServeMux(), logger)

	if response := call(t, address, "/nothing-here"); response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.StatusCode)
	}
}

func TestShutdownReturnsWithoutError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	address, stopped, cancel := serve(t, http.NewServeMux(), logger)
	call(t, address, "/")

	cancel()

	select {
	case err := <-stopped:
		stopped <- err
		if err != nil {
			t.Fatalf("shutdown reported a failure: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not stop")
	}
}

func httptestExposition(t *testing.T, registry *metrics.Registry) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return recorder.Body.String()
}

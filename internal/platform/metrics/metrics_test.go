package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

func TestRegistryExposesBuildIdentity(t *testing.T) {
	registry := metrics.New("ingest-gateway")

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", recorder.Code)
	}
	if !strings.Contains(body, `seagull_build_info{`) || !strings.Contains(body, `service="ingest-gateway"`) {
		t.Fatalf("build info missing from the exposition: %s", body)
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Fatalf("runtime collectors missing from the exposition")
	}
}

func TestRegistriesAreIndependent(t *testing.T) {
	if metrics.New("a") == metrics.New("b") {
		t.Fatal("registries must not be shared through package state")
	}
}

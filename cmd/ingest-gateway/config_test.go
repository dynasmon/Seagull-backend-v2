package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func environment(t *testing.T, set map[string]string) *config.Parser {
	t.Helper()

	values := map[string]string{
		"SEAGULL_BACKBONE_BROKERS":        "127.0.0.1:9092",
		"SEAGULL_BACKBONE_SASL_MECHANISM": "none",
	}
	for _, key := range []string{"SEAGULL_GATEWAY_TLS_CERT", "SEAGULL_GATEWAY_TLS_KEY", "SEAGULL_GATEWAY_AGENT_CA"} {
		path := filepath.Join(t.TempDir(), key)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", key, err)
		}
		values[key] = path
	}
	for key, value := range set {
		values[key] = value
	}
	return config.New(func(key string) (string, bool) {
		value, given := values[key]
		return value, given
	})
}

func TestAGatewayIsNamedNoLongerThanTheNameEveryEventRecords(t *testing.T) {
	for name, tested := range map[string]struct {
		id     string
		starts bool
	}{
		"unnamed":           {id: "", starts: true},
		"at the longest":    {id: strings.Repeat("g", 64), starts: true},
		"one byte too long": {id: strings.Repeat("g", 65), starts: false},
	} {
		t.Run(name, func(t *testing.T) {
			loaded, err := load(environment(t, map[string]string{"SEAGULL_GATEWAY_ID": tested.id}))
			if started := err == nil; started != tested.starts {
				t.Fatalf("a gateway named %q started=%v (%v), and every event it admits records the name it was given", tested.id, started, err)
			}
			if tested.starts && loaded.admissionRules.Gateway == "" {
				t.Fatal("the gateway records no name on the events it admits")
			}
		})
	}
}

func TestAGatewayRateLimitIsAtLeastOneOrTurnedOffInWords(t *testing.T) {
	if _, err := load(environment(t, map[string]string{"SEAGULL_GATEWAY_RATE_PER_SECOND": "0"})); err == nil ||
		!strings.Contains(err.Error(), "SEAGULL_GATEWAY_RATE_PER_SECOND") {
		t.Errorf("a rate of zero was answered %v, and zero used to turn the limiter off without a word", err)
	}

	limited, err := load(environment(t, nil))
	if err != nil || !limited.rateLimited || limited.ratePerSecond != 200 {
		t.Errorf("a gateway configured with nothing limits each agent to %.0f batches a second, limited=%v (%v)",
			limited.ratePerSecond, limited.rateLimited, err)
	}

	off, err := load(environment(t, map[string]string{"SEAGULL_GATEWAY_RATE_PER_SECOND": "unlimited"}))
	if err != nil || off.rateLimited {
		t.Errorf("a gateway told unlimited is limited=%v (%v)", off.rateLimited, err)
	}
}

func TestARosterGoesStaleOnlyOnceTwoConfirmationsWereMissed(t *testing.T) {
	loaded, err := load(environment(t, nil))
	if err != nil || loaded.rosterCheck != 5*time.Second || loaded.rosterStale != 30*time.Second {
		t.Fatalf("a gateway configured with nothing confirms its roster every %s and goes stale after %s (%v)",
			loaded.rosterCheck, loaded.rosterStale, err)
	}
	if _, err := load(environment(t, map[string]string{
		"SEAGULL_GATEWAY_ROSTER_CHECK_INTERVAL": "20s",
		"SEAGULL_GATEWAY_ROSTER_STALE_AFTER":    "30s",
	})); err == nil || !strings.Contains(err.Error(), "SEAGULL_GATEWAY_ROSTER_STALE_AFTER") {
		t.Errorf("a roster that would go stale after one missed confirmation was answered %v", err)
	}
}

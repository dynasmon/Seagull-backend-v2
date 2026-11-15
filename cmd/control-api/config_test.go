package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func environment(t *testing.T, set map[string]string) *config.Parser {
	t.Helper()

	values := map[string]string{
		"SEAGULL_BACKBONE_BROKERS":                "127.0.0.1:9092",
		"SEAGULL_BACKBONE_SASL_MECHANISM":         "none",
		"SEAGULL_ALERT_STORE_ADDRESS":             "127.0.0.1:5432",
		"SEAGULL_CONTROL_TELEMETRY_STORE_ADDRESS": "127.0.0.1:9000",
	}
	for _, key := range []string{
		"SEAGULL_CONTROL_API_TLS_CERT", "SEAGULL_CONTROL_API_TLS_KEY", "SEAGULL_CONTROL_API_CALLER_CA",
		"SEAGULL_CONTROL_API_AGENT_AUTHORITY_CERT", "SEAGULL_CONTROL_API_AGENT_AUTHORITY_KEY", "SEAGULL_CONTROL_API_AGENT_TRUST_BUNDLE",
		"SEAGULL_CONTROL_API_RENEWAL_TLS_CERT", "SEAGULL_CONTROL_API_RENEWAL_TLS_KEY", "SEAGULL_CONTROL_API_AGENT_CA",
		"SEAGULL_CONTROL_API_POLICY",
	} {
		path := filepath.Join(t.TempDir(), key)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", key, err)
		}
		values[key] = path
	}
	values["SEAGULL_DETECTION_RULES"] = t.TempDir()
	for key, value := range set {
		values[key] = value
	}
	return config.New(func(key string) (string, bool) {
		value, given := values[key]
		return value, given
	})
}

func TestAnOperatorRateLimitIsAtLeastOneOrTurnedOffInWords(t *testing.T) {
	if _, err := load(environment(t, map[string]string{"SEAGULL_CONTROL_API_RATE_PER_SECOND": "0"})); err == nil ||
		!strings.Contains(err.Error(), "SEAGULL_CONTROL_API_RATE_PER_SECOND") {
		t.Errorf("a rate of zero was answered %v, and zero used to turn the limiter off without a word", err)
	}

	limited, err := load(environment(t, nil))
	if err != nil || !limited.rateLimited || limited.ratePerSecond != 20 {
		t.Errorf("a control plane configured with nothing limits each caller to %.0f requests a second, limited=%v (%v)",
			limited.ratePerSecond, limited.rateLimited, err)
	}

	off, err := load(environment(t, map[string]string{"SEAGULL_CONTROL_API_RATE_PER_SECOND": "unlimited"}))
	if err != nil || off.rateLimited {
		t.Errorf("a control plane told unlimited is limited=%v (%v)", off.rateLimited, err)
	}
}

// The rules an installation starts from are what its control plane records
// first, so a control plane that was given no tree does not start, and one told
// nothing looks for it where the engine does.
func TestAControlPlaneIsGivenTheRuleTreeItsEngineStartsOn(t *testing.T) {
	given := t.TempDir()
	loaded, err := load(environment(t, map[string]string{"SEAGULL_DETECTION_RULES": given}))
	if err != nil || loaded.rules != given {
		t.Fatalf("a control plane given %s reads its starting rules from %q (%v)", given, loaded.rules, err)
	}

	if _, err := load(environment(t, map[string]string{"SEAGULL_DETECTION_RULES": filepath.Join(given, "absent")})); err == nil ||
		!strings.Contains(err.Error(), "SEAGULL_DETECTION_RULES") {
		t.Errorf("a rule tree that is not there was answered %v", err)
	}

	told, err := load(environment(t, map[string]string{"SEAGULL_DETECTION_RULES": ""}))
	if err == nil && told.rules != "/etc/seagull/rules" {
		t.Errorf("a control plane told nothing reads its starting rules from %q", told.rules)
	}
	if err != nil && !strings.Contains(err.Error(), `"/etc/seagull/rules"`) {
		t.Errorf("a control plane told nothing did not look where the engine does: %v", err)
	}
}

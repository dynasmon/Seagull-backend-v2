package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func lookupFrom(values map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestDefaultsApplyWhenUnset(t *testing.T) {
	parser := config.New(lookupFrom(nil))

	if got := parser.String("SEAGULL_ADDR", ":8443"); got != ":8443" {
		t.Fatalf("string default: %q", got)
	}
	if got := parser.Int("SEAGULL_MAX", 10, 1, 100); got != 10 {
		t.Fatalf("int default: %d", got)
	}
	if got := parser.Duration("SEAGULL_TIMEOUT", time.Second, 0, time.Minute); got != time.Second {
		t.Fatalf("duration default: %s", got)
	}
	if err := parser.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmptyValueCountsAsUnset(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_ADDR": "   "}))

	if got := parser.String("SEAGULL_ADDR", "127.0.0.1:9443"); got != "127.0.0.1:9443" {
		t.Fatalf("expected the default, got %q", got)
	}
	if err := parser.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequiredValueMissingIsReported(t *testing.T) {
	parser := config.New(lookupFrom(nil))
	parser.RequiredString("SEAGULL_BROKERS")

	err := parser.Err()
	if err == nil {
		t.Fatal("expected a failure")
	}
	if !strings.Contains(err.Error(), "SEAGULL_BROKERS") || !strings.Contains(err.Error(), "required") {
		t.Fatalf("error does not name the problem: %v", err)
	}
}

func TestEveryProblemIsReportedTogether(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{
		"SEAGULL_MAX":     "abc",
		"SEAGULL_TIMEOUT": "5",
		"SEAGULL_MODE":    "chaos",
	}))
	parser.Int("SEAGULL_MAX", 1, 1, 10)
	parser.Duration("SEAGULL_TIMEOUT", time.Second, 0, time.Minute)
	parser.Enum("SEAGULL_MODE", "safe", "safe", "strict")
	parser.RequiredString("SEAGULL_BROKERS")

	err := parser.Err()
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, key := range []string{"SEAGULL_MAX", "SEAGULL_TIMEOUT", "SEAGULL_MODE", "SEAGULL_BROKERS"} {
		if !strings.Contains(err.Error(), key) {
			t.Fatalf("%s missing from the report: %v", key, err)
		}
	}
}

func TestRangesAreEnforced(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_MAX": "5000"}))
	parser.Int("SEAGULL_MAX", 10, 1, 100)

	err := parser.Err()
	if err == nil || !strings.Contains(err.Error(), "1..100") {
		t.Fatalf("expected a range failure, got %v", err)
	}
}

func TestSecretIsNeverEchoedInErrors(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_TOKEN": "  "}))
	parser.RequiredSecret("SEAGULL_TOKEN")

	err := parser.Err()
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), "  ") && strings.Contains(err.Error(), "value") {
		t.Fatalf("secret material described in the error: %v", err)
	}
}

func TestSecretReadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	parser := config.New(lookupFrom(map[string]string{"SEAGULL_TOKEN_FILE": path}))
	secret := parser.RequiredSecret("SEAGULL_TOKEN")

	if err := parser.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Reveal() != "s3cr3t" {
		t.Fatalf("unexpected secret value")
	}
	if secret.String() != "[redacted]" {
		t.Fatalf("secret is printable: %s", secret.String())
	}
}

func TestUnreadableSecretFileFailsStartup(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_TOKEN_FILE": "/nonexistent/token"}))
	parser.RequiredSecret("SEAGULL_TOKEN")

	err := parser.Err()
	if err == nil || !strings.Contains(err.Error(), "SEAGULL_TOKEN_FILE") {
		t.Fatalf("expected the file problem to be reported, got %v", err)
	}
}

func TestByteSizesAcceptBinaryUnits(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_BODY": "8MiB"}))
	got := parser.Bytes("SEAGULL_BODY", 1<<20, 1024, 1<<30)

	if err := parser.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 8<<20 {
		t.Fatalf("expected 8 MiB, got %d", got)
	}
}

func TestListSplitsAndTrims(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_BROKERS": "a:9092, b:9092 ,"}))
	got := parser.RequiredList("SEAGULL_BROKERS")

	if err := parser.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "a:9092" || got[1] != "b:9092" {
		t.Fatalf("unexpected list: %v", got)
	}
}

func TestFilePathMustExist(t *testing.T) {
	parser := config.New(lookupFrom(map[string]string{"SEAGULL_CA": "/nonexistent/ca.pem"}))
	parser.RequiredFilePath("SEAGULL_CA")

	if err := parser.Err(); err == nil || !strings.Contains(err.Error(), "SEAGULL_CA") {
		t.Fatalf("expected a path failure, got %v", err)
	}
}

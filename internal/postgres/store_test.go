package postgres

import (
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func TestTheControlStoreVerifiesTLSByDefault(t *testing.T) {
	parser := config.New(func(key string) (string, bool) {
		if key == "SEAGULL_ALERT_STORE_ADDRESS" {
			return "postgres.example:5432", true
		}
		return "", false
	})

	loaded := LoadConfig("SEAGULL_ALERT_STORE", parser)

	if err := parser.Err(); err != nil {
		t.Fatal(err)
	}
	if loaded.SSLMode != "verify-full" {
		t.Fatalf("expected verify-full, got %q", loaded.SSLMode)
	}
}

func TestAnUnknownControlStoreTLSModeIsRejected(t *testing.T) {
	parser := config.New(func(key string) (string, bool) {
		switch key {
		case "SEAGULL_ALERT_STORE_ADDRESS":
			return "postgres.example:5432", true
		case "SEAGULL_ALERT_STORE_SSLMODE":
			return "sometimes", true
		default:
			return "", false
		}
	})

	LoadConfig("SEAGULL_ALERT_STORE", parser)

	if err := parser.Err(); err == nil {
		t.Fatal("expected the unknown sslmode to be rejected")
	}
}

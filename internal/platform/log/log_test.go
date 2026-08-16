package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
)

func TestNewRejectsUnknownLevelAndFormat(t *testing.T) {
	if _, err := log.New(&bytes.Buffer{}, log.Options{Level: "loud"}); err == nil {
		t.Fatal("expected an error for an unknown level")
	}
	if _, err := log.New(&bytes.Buffer{}, log.Options{Format: "xml"}); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestLoggerCarriesServiceIdentity(t *testing.T) {
	var buffer bytes.Buffer
	logger, err := log.New(&buffer, log.Options{Service: "ingest-gateway", Version: "1.2.3"})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	logger.Info("component_started")

	var entry map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &entry); err != nil {
		t.Fatalf("decode entry: %v", err)
	}
	if entry["service"] != "ingest-gateway" || entry["version"] != "1.2.3" {
		t.Fatalf("identity missing from entry: %v", entry)
	}
	if entry["msg"] != "component_started" {
		t.Fatalf("unexpected message: %v", entry["msg"])
	}
}

func TestSecretsNeverReachTheLog(t *testing.T) {
	var buffer bytes.Buffer
	logger, err := log.New(&buffer, log.Options{})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	logger.Info("broker_configured", slog.Any("password", config.Secret("hunter2")))

	if strings.Contains(buffer.String(), "hunter2") {
		t.Fatalf("secret leaked into the log: %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "[redacted]") {
		t.Fatalf("expected a redaction marker: %s", buffer.String())
	}
}

func TestContextLoggerAccumulatesAttributes(t *testing.T) {
	var buffer bytes.Buffer
	logger, err := log.New(&buffer, log.Options{})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	ctx := log.Into(context.Background(), logger)
	ctx = log.With(ctx, slog.String("agent_id", "web-01"))
	log.From(ctx).Info("batch_accepted")

	var entry map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &entry); err != nil {
		t.Fatalf("decode entry: %v", err)
	}
	if entry["agent_id"] != "web-01" {
		t.Fatalf("context attribute missing: %v", entry)
	}
}

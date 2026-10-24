package event_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func weighing(t *testing.T, at time.Time, size int) *eventv1.Event {
	t.Helper()
	record := fixtures.SSHAuthentication{At: at}.Event()
	if !fixtures.Bloat(record, size) {
		t.Fatalf("no event encodes to %d bytes", size)
	}
	return record
}

func TestAnEventIsAdmittedWhileItEncodesWithinTheCeiling(t *testing.T) {
	at := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	policy := event.Policy{MaxClockSkew: time.Minute, MaxAge: time.Hour}

	if err := event.Validate(weighing(t, at, event.MaxEventBytes), at, policy); err != nil {
		t.Fatalf("an event of %d bytes was refused: %v", event.MaxEventBytes, err)
	}

	heavy := weighing(t, at, event.MaxEventBytes+1)
	var violation *event.Violation
	if err := event.Validate(heavy, at, policy); !errors.As(err, &violation) || violation.Field != "event" {
		t.Fatalf("an event one byte above the ceiling was answered %v, and the backbone would refuse it after the agent was told nothing", err)
	}
	if err := event.ValidateContract(heavy); err != nil {
		t.Fatalf("a replay refused an event the topic already holds for what it weighs: %v", err)
	}
}

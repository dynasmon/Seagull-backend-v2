package agentstatus_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func weighing(t *testing.T, at time.Time, size int) *agentv1.Status {
	t.Helper()
	report := fixtures.Report{At: at}.Status()
	if !fixtures.Bloat(report, size) {
		t.Fatalf("no report encodes to %d bytes", size)
	}
	return report
}

func TestAReportIsAdmittedWhileItEncodesWithinTheCeiling(t *testing.T) {
	at := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	policy := event.Policy{MaxClockSkew: time.Minute, MaxAge: time.Hour}

	if err := agentstatus.Validate(weighing(t, at, agentstatus.MaxReportBytes), at, policy); err != nil {
		t.Fatalf("a report of %d bytes was refused: %v", agentstatus.MaxReportBytes, err)
	}

	heavy := weighing(t, at, agentstatus.MaxReportBytes+1)
	var violation *event.Violation
	if err := agentstatus.Validate(heavy, at, policy); !errors.As(err, &violation) || violation.Field != "report" {
		t.Fatalf("a report one byte above the ceiling was answered %v, and the backbone would refuse it after the agent was told nothing", err)
	}
	if err := agentstatus.ValidateContract(heavy); err != nil {
		t.Fatalf("a replay refused a report the topic already holds for what it weighs: %v", err)
	}
}

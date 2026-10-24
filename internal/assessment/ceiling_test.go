package assessment_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func weighing(t *testing.T, at time.Time, size int) *assessmentv1.Assessment {
	t.Helper()
	assessed := fixtures.Posture{At: at}.Assessment()
	if !fixtures.Bloat(assessed, size) {
		t.Fatalf("no assessment encodes to %d bytes", size)
	}
	return assessed
}

func TestAnAssessmentIsAdmittedWhileItEncodesWithinTheCeiling(t *testing.T) {
	at := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	policy := event.Policy{MaxClockSkew: time.Minute, MaxAge: time.Hour}

	if err := assessment.Validate(weighing(t, at, assessment.MaxAssessmentBytes), at, policy); err != nil {
		t.Fatalf("an assessment of %d bytes was refused: %v", assessment.MaxAssessmentBytes, err)
	}

	heavy := weighing(t, at, assessment.MaxAssessmentBytes+1)
	var violation *event.Violation
	if err := assessment.Validate(heavy, at, policy); !errors.As(err, &violation) || violation.Field != "assessment" {
		t.Fatalf("an assessment one byte above the ceiling was answered %v, and the backbone would refuse it after the agent was told nothing", err)
	}
	if err := assessment.ValidateContract(heavy); err != nil {
		t.Fatalf("a replay refused an assessment the topic already holds for what it weighs: %v", err)
	}
}

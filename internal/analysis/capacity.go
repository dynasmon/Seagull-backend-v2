package analysis

import (
	"errors"
	"log/slog"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Tenants and rules arrive in records, so how many refusals the engine remembers
// having told is bounded rather than trusted to stay small; past the bound the
// counter still says how often. Only the batch being decided touches the set,
// one batch at a time, so it holds no lock.
const maxToldAtCapacity = 1024

type atCapacity struct {
	tenant  string
	rule    detection.ID
	outcome string
}

// Every refusal is counted and few are told: a flood of invented group values is
// refused on every event it produces, and a line per event would be the flood
// written down a second time. The one line is what says whom to go and find,
// which a label may not carry.
func (e *Engine) refusedObservation(record *eventv1.Event, rule detection.ID, err error) {
	outcome := refusalOf(err)
	e.metrics.observed(outcome)

	if !outOfRoom(outcome) {
		return
	}
	told := atCapacity{tenant: record.GetOrigin().GetTenantId(), rule: rule, outcome: outcome}
	if _, already := e.told[told]; already || len(e.told) >= maxToldAtCapacity {
		return
	}
	e.told[told] = struct{}{}
	e.logger.Warn("detection_state_at_capacity",
		slog.String("outcome", outcome),
		slog.String("tenant", told.tenant),
		slog.String("rule", string(rule)),
	)
}

func outOfRoom(outcome string) bool {
	switch outcome {
	case OutcomeAtCapacity, OutcomeTenantAtCapacity, OutcomeRuleAtCapacity:
		return true
	}
	return false
}

func refusalOf(err error) string {
	switch {
	case errors.Is(err, detectionstate.ErrAtCapacity):
		return OutcomeAtCapacity
	case errors.Is(err, detectionstate.ErrTenantAtCapacity):
		return OutcomeTenantAtCapacity
	case errors.Is(err, detectionstate.ErrRuleAtCapacity):
		return OutcomeRuleAtCapacity
	case errors.Is(err, detectionstate.ErrTooLate):
		return OutcomeTooLate
	case errors.Is(err, detectionstate.ErrWindowTooLong), errors.Is(err, detectionstate.ErrNoWindow):
		return OutcomeUnbounded
	}
	return OutcomeRefused
}

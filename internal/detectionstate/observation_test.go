package detectionstate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

func TestAnObservationSaysWhichEventItCameFromAndWhen(t *testing.T) {
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	sent := detectionstate.EventName{Agent: "web-01", ID: "e1"}

	for _, one := range []struct {
		name     string
		seen     detectionstate.Observation
		expected error
	}{
		{"whole", detectionstate.Observation{Event: sent, At: at, Value: "203.0.113.10"}, nil},
		{"counting only", detectionstate.Observation{Event: sent, At: at}, nil},
		{"unnamed", detectionstate.Observation{Event: detectionstate.EventName{Agent: "web-01"}, At: at}, detectionstate.ErrNoEvent},
		{"unsent", detectionstate.Observation{Event: detectionstate.EventName{ID: "e1"}, At: at}, detectionstate.ErrNoAgent},
		{"untimed", detectionstate.Observation{Event: sent}, detectionstate.ErrNoTime},
		{
			"sprawling",
			detectionstate.Observation{Event: sent, At: at, Value: strings.Repeat("a", detectionstate.MaxValueLength+1)},
			detectionstate.ErrValueTooLong,
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			if err := one.seen.Validate(); !errors.Is(err, one.expected) {
				t.Errorf("validating a %s observation gave %v, wanted %v", one.name, err, one.expected)
			}
		})
	}
}

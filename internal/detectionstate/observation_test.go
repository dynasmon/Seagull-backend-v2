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

	for _, one := range []struct {
		name     string
		seen     detectionstate.Observation
		expected error
	}{
		{"whole", detectionstate.Observation{Event: "e1", At: at, Value: "203.0.113.10"}, nil},
		{"counting only", detectionstate.Observation{Event: "e1", At: at}, nil},
		{"unnamed", detectionstate.Observation{At: at}, detectionstate.ErrNoEvent},
		{"untimed", detectionstate.Observation{Event: "e1"}, detectionstate.ErrNoTime},
		{
			"sprawling",
			detectionstate.Observation{Event: "e1", At: at, Value: strings.Repeat("a", detectionstate.MaxValueLength+1)},
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

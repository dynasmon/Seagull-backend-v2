package main

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func counting(t *testing.T, count detection.Count) *ruleset.Snapshot {
	t.Helper()

	program, err := detection.Compile(detection.Rule{
		ID:          "ssh.repeated_failed_password",
		Revision:    1,
		Name:        "Repeated failed SSH passwords",
		Description: "More failed passwords from one address than an estate should see.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Count:    count,
		Severity: detection.High,
		Status:   detection.Active,
	})
	if err != nil {
		t.Fatalf("compile a counting rule: %v", err)
	}

	snapshot, err := ruleset.Compose([]*detection.Program{program})
	if err != nil {
		t.Fatalf("compose a ruleset: %v", err)
	}
	return snapshot
}

func bounds() detectionstate.Bounds {
	return detectionstate.Bounds{Window: time.Hour, ObservationsPerKey: 128, Keys: 4096}
}

func TestAStoreIsBoundedBeforeTheEngineIsBuilt(t *testing.T) {
	keeper, err := keeping(bounds(), counting(t, detection.Count{
		AtLeast: 20,
		Within:  time.Minute,
		GroupBy: []detection.Field{"origin.agent_id"},
	}))
	if err != nil {
		t.Fatalf("a rule the bounds admit stopped the process: %v", err)
	}
	if keeper.Keys() != 0 {
		t.Errorf("a new store already holds %d keys", keeper.Keys())
	}
}

// A rule that compiles and could never fire is the quietest way a detection
// surface can be wrong, so the process refuses to start rather than running it.
func TestARuleTheBoundsCannotAnswerStopsTheProcess(t *testing.T) {
	cases := map[string]struct {
		count  detection.Count
		reason error
	}{
		"a window longer than the store keeps": {
			detection.Count{AtLeast: 20, Within: 2 * time.Hour, GroupBy: []detection.Field{"origin.agent_id"}},
			detectionstate.ErrWindowTooLong,
		},
		"a threshold above what a key holds": {
			detection.Count{AtLeast: 512, Within: time.Minute, GroupBy: []detection.Field{"origin.agent_id"}},
			detectionstate.ErrUnreachable,
		},
	}

	for name, subject := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := keeping(bounds(), counting(t, subject.count))
			if !errors.Is(err, subject.reason) {
				t.Fatalf("the process started, or stopped for another reason: %v", err)
			}
		})
	}
}

func TestBoundsThatCannotHoldAnythingAreRefused(t *testing.T) {
	if _, err := keeping(detectionstate.Bounds{}, nil); err == nil {
		t.Error("a store with no bounds at all was built")
	}
}

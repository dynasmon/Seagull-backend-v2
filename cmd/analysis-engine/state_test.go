package main

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func counting(t *testing.T, count detection.Count) *ruleset.Snapshot {
	t.Helper()

	return composed(t, detection.Rule{
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
}

func composed(t *testing.T, rule detection.Rule) *ruleset.Snapshot {
	t.Helper()

	program, err := detection.Compile(rule)
	if err != nil {
		t.Fatalf("compile a rule: %v", err)
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

func deployment() runtime {
	return runtime{
		bounds:       bounds(),
		partitioning: detectionstate.Partitioning{By: broker.PartitionedBy},
		skew:         5 * time.Minute,
	}
}

func TestAStoreIsBoundedBeforeTheEngineIsBuilt(t *testing.T) {
	keeper, err := keeping(deployment(), counting(t, detection.Count{
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
			_, err := keeping(deployment(), counting(t, subject.count))
			if !errors.Is(err, subject.reason) {
				t.Fatalf("the process started, or stopped for another reason: %v", err)
			}
		})
	}
}

func TestBoundsThatCannotHoldAnythingAreRefused(t *testing.T) {
	if _, err := keeping(runtime{}, nil); err == nil {
		t.Error("a store with no bounds at all was built")
	}
}

func acrossAgents() detection.Count {
	return detection.Count{AtLeast: 20, Within: time.Minute, GroupBy: []detection.Field{"authentication.network.source.ip"}}
}

// The stream is keyed by the agent, so one address seen by three agents is
// counted in three places and none of them is the answer. A rule like that
// would look active and report a third of what it was written to find.
func TestARuleTheStreamCannotKeepTogetherStopsTheProcess(t *testing.T) {
	_, err := keeping(deployment(), counting(t, acrossAgents()))
	if !errors.Is(err, detectionstate.ErrSplitState) {
		t.Fatalf("a rule counting across agents was admitted: %v", err)
	}
}

// The same rule, on a deployment that says it is the only reader. The claim is
// what makes it answerable, and the claim is checked against the assignment.
func TestOneReaderOfTheWholeStreamMayCountAcrossAgents(t *testing.T) {
	sole := deployment()
	sole.partitioning.Sole = true

	if _, err := keeping(sole, counting(t, acrossAgents())); err != nil {
		t.Fatalf("a sole reader was refused a rule counting across agents: %v", err)
	}
}

// A rule that does not run has nothing to be executable about, and a translated
// catalogue arrives as drafts. Refusing one would make an import unshippable
// without changing what the estate detects.
func TestARuleThatDoesNotRunIsNotHeldToWhatTheDeploymentCanAnswer(t *testing.T) {
	draft := composed(t, detection.Rule{
		ID:          "ssh.repeated_failed_password",
		Revision:    1,
		Name:        "Repeated failed SSH passwords",
		Description: "Written and not run, so nothing about it has to be answerable yet.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Count:    acrossAgents(),
		Severity: detection.High,
		Status:   detection.Draft,
	})

	if _, err := keeping(deployment(), draft); err != nil {
		t.Fatalf("a draft the deployment could not run stopped the process: %v", err)
	}
}

// What a restart costs, stated as a number: the longest window anything running
// keeps, widened by the skew the gateway admits, because the window is event
// time and the stream is ordered by arrival.
func TestWhatMustBeReadBackIsTheLongestWindowAnythingRunningKeeps(t *testing.T) {
	engine := deployment()

	if window := engine.recovering(nil); window != 0 {
		t.Errorf("a process running nothing reads back %s", window)
	}

	stateless := composed(t, detection.Rule{
		ID:          "authentication.failed",
		Revision:    1,
		Name:        "An authentication failed",
		Description: "Decided from the event in front of it and remembering nothing.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.Predicate{
			Field:    "authentication.outcome",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.TextValue("failure")},
		},
		Severity: detection.High,
		Status:   detection.Active,
	})
	if window := engine.recovering(stateless); window != 0 {
		t.Errorf("a ruleset that remembers nothing reads back %s", window)
	}

	remembering := counting(t, detection.Count{
		AtLeast: 20,
		Within:  10 * time.Minute,
		GroupBy: []detection.Field{"origin.agent_id"},
	})
	if window := engine.recovering(remembering); window != 15*time.Minute {
		t.Errorf("a ten-minute window reads back %s, want the window and the skew", window)
	}
}

// A rule may not ask for more than the store keeps, so what is read back is
// bounded by the store rather than by the rule.
func TestWhatIsReadBackIsNeverMoreThanTheStoreKeeps(t *testing.T) {
	narrow := deployment()
	narrow.bounds.Window = time.Minute

	longest := counting(t, detection.Count{
		AtLeast: 20,
		Within:  time.Hour,
		GroupBy: []detection.Field{"origin.agent_id"},
	})
	if window := narrow.recovering(longest); window != 6*time.Minute {
		t.Errorf("a store keeping a minute reads back %s", window)
	}
}

// The claim that one reader holds the stream, checked against the assignment.
// A deployment that grew a second reader broke exactly the rules that needed it.
func TestAClaimToHoldTheWholeStreamIsCheckedAgainstTheAssignment(t *testing.T) {
	sole := deployment()
	sole.partitioning.Sole = true
	across := counting(t, acrossAgents())

	if err := sole.owns(across, 12, 12); err != nil {
		t.Errorf("a reader holding every partition was refused: %v", err)
	}
	if err := sole.owns(across, 6, 12); err == nil {
		t.Error("a reader holding half the stream went on counting across agents")
	}

	colocated := counting(t, detection.Count{
		AtLeast: 20,
		Within:  time.Minute,
		GroupBy: []detection.Field{"origin.agent_id"},
	})
	if err := sole.owns(colocated, 6, 12); err != nil {
		t.Errorf("a rule the stream keeps together was refused a partial assignment: %v", err)
	}
	if err := sole.owns(nil, 6, 12); err != nil {
		t.Errorf("a process running nothing was refused a partial assignment: %v", err)
	}
}

// A reader that holds none of the stream decides nothing, and a stopping one
// holds nothing: refusing there would turn every shutdown into a failure.
func TestAReaderHoldingNoneOfTheStreamIsNotRefused(t *testing.T) {
	sole := deployment()
	sole.partitioning.Sole = true

	if err := sole.owns(counting(t, acrossAgents()), 0, 12); err != nil {
		t.Errorf("a reader holding nothing was refused: %v", err)
	}
}

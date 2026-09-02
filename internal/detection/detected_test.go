package detection_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	ruleset   = "3538ec98f5ce3e22e8e65f47cd0344ee"
	decidedAt = "2026-08-26T12:00:00Z"
)

// A rule carrying everything a rule may carry, so that a field the contract
// grows and nothing fills has somewhere to fail.
func attributed() detection.Rule {
	subject := rule()
	subject.Source = detection.Source{Catalogue: "sigma", Identifier: "5013fd8a-56f1-4d5c"}
	subject.Tags = []string{"ssh", "credential_access"}
	subject.References = []string{"https://attack.mitre.org/techniques/T1110/001/"}
	subject.Count = detection.Count{
		AtLeast: 20,
		Within:  time.Minute,
		GroupBy: []detection.Field{"authentication.network.source.ip", "origin.agent_id"},
	}
	return subject
}

// The same, for the half of the contract only an ordered rule fills. A rule
// carries a count or a sequence and never both, so covering the contract takes
// one of each.
func correlating() detection.Rule {
	subject := attributed()
	subject.Count = detection.Count{}
	subject.Match = nil
	subject.Sequence = detection.Sequence{
		Within:  time.Minute,
		GroupBy: []detection.Field{"authentication.network.source.ip"},
		Stages: []detection.Stage{
			{Name: "a failed password", Match: detection.Predicate{
				Field: "authentication.outcome", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("failure")},
			}},
			{Name: "one that was accepted", Match: detection.Predicate{
				Field: "authentication.outcome", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("success")},
			}},
		},
	}
	return subject
}

// An event carrying everything the fixture can say about where it came from,
// for the same reason.
func observed(t *testing.T) *eventv1.Event {
	t.Helper()

	at, err := time.Parse(time.RFC3339, "2026-08-26T11:59:00Z")
	if err != nil {
		t.Fatalf("the fixture time is not a time: %v", err)
	}
	return fixtures.SSHAuthentication{Hostname: "web-01", At: at}.Event()
}

func detected(t *testing.T, subject detection.Rule, record *eventv1.Event) *detectionv1.Detection {
	t.Helper()

	at, err := time.Parse(time.RFC3339, decidedAt)
	if err != nil {
		t.Fatalf("the fixture time is not a time: %v", err)
	}

	program, err := detection.Compile(subject)
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}
	match, held := program.Decide(record)
	if !held {
		t.Fatal("the rule did not match the event it was written for")
	}
	if subject.Count.Counts() {
		match.Counted = detection.Counted{
			Group:     program.Group(record),
			Count:     subject.Count.AtLeast + 1,
			First:     record.GetTime().GetEventTime().AsTime().Add(-subject.Count.Within / 2),
			Saturated: true,
		}
	}
	return match.Detected(ruleset, record, at)
}

func correlated(t *testing.T, subject detection.Rule, record *eventv1.Event) *detectionv1.Detection {
	t.Helper()

	at, err := time.Parse(time.RFC3339, decidedAt)
	if err != nil {
		t.Fatalf("the fixture time is not a time: %v", err)
	}

	program, err := detection.Compile(subject)
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}
	reached, evidence := program.Satisfied(record)
	if !reached.Any() {
		t.Fatal("the event satisfied no stage of the rule written for it")
	}

	happened := record.GetTime().GetEventTime().AsTime()
	match := detection.Match{Rule: subject, Evidence: evidence, Correlated: detection.Correlated{
		Group:       program.Group(record),
		ClockSpread: 3 * time.Second,
		Stages: []detection.Satisfied{
			{Name: subject.Sequence.Stages[0].Name, Event: record.GetEventId(), At: happened.Add(-30 * time.Second)},
			{Name: subject.Sequence.Stages[1].Name, Event: "3f7c1d5e9b2a4c6d8e0f1a2b3c4d5e6f", At: happened},
		},
	}}
	return match.Detected(ruleset, record, at)
}

// The origin is copied from the event whole, so what it carries is the event
// contract's business rather than this boundary's. A leaf here for the same
// reason a repeated message is one.
var copiedWhole = map[string]struct{}{"origin": {}}

const wellKnown = "google.protobuf."

// A field added to the detection contract and never filled is a detection that
// promises more than it says, and nothing downstream can tell the difference
// between a field nobody decided about and one this event had nothing to put in.
// This is the same rule the store is held to, run from the contract towards the
// thing that fills it.
func TestEveryFieldOfADetectionIsDecidedAbout(t *testing.T) {
	record := observed(t)
	filled := unfilled(correlated(t, correlating(), record).ProtoReflect(), "")

	for _, path := range unfilled(detected(t, attributed(), record).ProtoReflect(), "") {
		if slices.Contains(filled, path) {
			t.Errorf("the detection contract carries %s and nothing decided what goes in it", path)
		}
	}
}

func unfilled(message protoreflect.Message, prefix string) []string {
	var paths []string
	fields := message.Descriptor().Fields()

	for index := range fields.Len() {
		field := fields.Get(index)
		path := prefix + string(field.Name())

		if !message.Has(field) {
			paths = append(paths, path)
			continue
		}

		_, whole := copiedWhole[path]
		nested := field.Kind() == protoreflect.MessageKind &&
			!field.IsList() && !field.IsMap() && !whole &&
			!strings.HasPrefix(string(field.Message().FullName()), wellKnown)
		if nested {
			paths = append(paths, unfilled(message.Get(field).Message(), path+".")...)
		}
	}
	return paths
}

// The property the whole output stage rests on: a stage that publishes before
// it commits will publish a batch twice when it is retried, and a detection
// that names itself the same way both times is rewritten rather than doubled.
func TestTheSameEventDecidedTwiceNamesTheSameDetection(t *testing.T) {
	first := detected(t, attributed(), observed(t))
	second := detected(t, attributed(), observed(t))

	if first.GetDetectionId() != second.GetDetectionId() {
		t.Errorf("the same rule and event named %s and then %s",
			first.GetDetectionId(), second.GetDetectionId())
	}
	if !proto.Equal(first, second) {
		t.Error("the same rule and event were written down differently twice")
	}
}

// What the name is over, and what it is deliberately not over. A ruleset that
// gained an unrelated rule must not rename what the others found, and the hour
// a replay happens to run at must not either.
func TestADetectionIsNamedByTheRuleTheRevisionAndTheEventsItWasDecidedFrom(t *testing.T) {
	named := detected(t, attributed(), observed(t)).GetDetectionId()

	renames := map[string]bool{
		"the rule":     true,
		"the revision": true,
		"the event":    true,
		"the ruleset":  false,
		"the hour":     false,
	}

	for change, renamed := range renames {
		t.Run(change, func(t *testing.T) {
			subject, record := attributed(), observed(t)
			at := time.Now().UTC()

			switch change {
			case "the rule":
				subject.ID = "ssh.failed_password_from_anywhere"
			case "the revision":
				subject.Revision = 2
			case "the event":
				record.EventId = "99999999-8888-7777-6666-555555555555"
			case "the ruleset":
			case "the hour":
			}

			match, held := running(t, subject.Match).Decide(record)
			if !held {
				t.Fatal("the rule did not match the event it was written for")
			}
			match.Rule = subject

			set := ruleset
			if change == "the ruleset" {
				set = "0000000000000000ffffffffffffffff"
			}
			if change != "the hour" {
				at, _ = time.Parse(time.RFC3339, decidedAt)
			}

			after := match.Detected(set, record, at).GetDetectionId()
			if renamed && after == named {
				t.Errorf("changing %s left the detection named %s", change, after)
			}
			if !renamed && after != named {
				t.Errorf("changing %s renamed the detection %s to %s", change, named, after)
			}
		})
	}
}

// The rule is named, never copied: a detection says which rule fired and where
// to read it, and the ruleset it came from is what makes reading it possible.
func TestADetectionNamesTheRuleAndTheRulesetRatherThanRepeatingThem(t *testing.T) {
	subject := attributed()
	made := detected(t, subject, observed(t))

	if made.GetRule().GetId() != string(subject.ID) {
		t.Errorf("the detection names rule %q and the rule is %q", made.GetRule().GetId(), subject.ID)
	}
	if made.GetRule().GetRevision() != uint32(subject.Revision) {
		t.Errorf("the detection names revision %d and the rule is at %d",
			made.GetRule().GetRevision(), subject.Revision)
	}
	if made.GetRulesetId() != ruleset {
		t.Errorf("the detection names ruleset %q and the process is pinned to %q",
			made.GetRulesetId(), ruleset)
	}

	carried := made.GetRule().ProtoReflect()
	for _, unwanted := range []string{"description", "false_positives", "response", "tags", "references"} {
		if carried.Descriptor().Fields().ByName(protoreflect.Name(unwanted)) != nil {
			t.Errorf("a detection repeats the rule's %s, which the ruleset already holds", unwanted)
		}
	}
}

// Where the rule came from survives into the detection, so a finding made by an
// imported rule can be traced past the rule to the catalogue entry it was made
// from. Absent when the estate wrote the rule itself, rather than half filled.
func TestADetectionSaysWhereAnImportedRuleCameFrom(t *testing.T) {
	made := detected(t, attributed(), observed(t))
	if catalogue := made.GetRule().GetSource().GetCatalogue(); catalogue != "sigma" {
		t.Errorf("the detection says the rule came from %q", catalogue)
	}

	own := detected(t, rule(), observed(t))
	if own.GetRule().GetSource() != nil {
		t.Error("a rule this estate wrote arrived with a catalogue it did not come from")
	}
	if own.GetTechnique() == nil {
		t.Error("a rule that attributes itself to a technique lost it on the way out")
	}
}

// Evidence is the one place a value the event carried is written down. It is
// carried here rather than in a log line, which is what lets an analyst read
// back why the rule fired without the platform quoting a producer into its own
// output.
func TestADetectionCarriesWhatTheEventHeldInTheFieldsTheRuleRead(t *testing.T) {
	made := detected(t, attributed(), observed(t))
	if len(made.GetEvidence()) == 0 {
		t.Fatal("a detection arrived with nothing to say why it was made")
	}

	held := make(map[string]*detectionv1.Evidence, len(made.GetEvidence()))
	for _, seen := range made.GetEvidence() {
		held[seen.GetField()] = seen
	}

	outcome, read := held["authentication.outcome"]
	if !read {
		t.Fatal("the rule read authentication.outcome and the detection does not say so")
	}
	if outcome.GetHeld() != "failure" || outcome.GetOperator() != "equals" {
		t.Errorf("the rule asked %q of authentication.outcome and the event held %q",
			outcome.GetOperator(), outcome.GetHeld())
	}

	address, read := held["authentication.network.source.ip"]
	if !read {
		t.Fatal("the rule read the source address and the detection does not say so")
	}
	if !address.GetNegated() {
		t.Error("the rule asked that the address is not internal and the detection does not say it was negated")
	}
}

// An absent field answers no question, and a detection has to be able to say
// that: the reason a negated rule fired can be that the event never spoke.
func TestADetectionSaysWhenTheEventDidNotCarryAFieldTheRuleRead(t *testing.T) {
	record := observed(t)
	record.GetAuthentication().Network = nil

	made := detected(t, attributed(), record)
	for _, seen := range made.GetEvidence() {
		if seen.GetField() != "authentication.network.source.ip" {
			continue
		}
		if !seen.GetAbsent() {
			t.Error("the event carried no source address and the detection does not say so")
		}
		if seen.GetHeld() != "" {
			t.Errorf("the event carried no source address and the detection says it held %q", seen.GetHeld())
		}
		return
	}
	t.Fatal("the rule read the source address and the detection does not say what it found")
}

// A detection is not an alert: it states what was found and carries nothing an
// operator would later change, so a replay can rewrite it without overwriting
// somebody's triage.
func TestADetectionCarriesNoLifecycle(t *testing.T) {
	fields := (&detectionv1.Detection{}).ProtoReflect().Descriptor().Fields()

	for _, lifecycle := range []string{
		"status", "disposition", "assigned_to", "acknowledged_at", "acknowledged_by",
		"closed_at", "closed_by", "triage_notes", "priority", "false_positive_reason",
	} {
		if fields.ByName(protoreflect.Name(lifecycle)) != nil {
			t.Errorf("a detection carries %s, which belongs to an alert's lifecycle", lifecycle)
		}
	}
}

// The severity a rule may carry and the severity a detection is reported as are
// one set, so a severity that cannot cross the boundary is one a rule cannot be
// written with.
func TestEverySeverityARuleMayCarryCrossesTheBoundary(t *testing.T) {
	for _, held := range []detection.Severity{detection.Low, detection.Medium, detection.High, detection.Critical} {
		subject := attributed()
		subject.Severity = held
		if err := subject.Validate(); err != nil {
			t.Fatalf("a rule with severity %s was refused: %v", held, err)
		}

		reported := detected(t, subject, observed(t)).GetSeverity()
		if reported == detectionv1.Severity_SEVERITY_UNSPECIFIED {
			t.Errorf("a %s rule reports a severity nobody downstream can route on", held)
		}
	}
}

// A detection is placed on a timeline by when the thing happened, not by when
// the platform got round to deciding it.
func TestADetectionSaysWhenTheThingHappenedAndWhenItWasDecided(t *testing.T) {
	record := observed(t)
	made := detected(t, attributed(), record)

	if happened := made.GetEventTime(); !happened.AsTime().Equal(record.GetTime().GetEventTime().AsTime()) {
		t.Errorf("the detection places the event at %s and the event says %s",
			happened.AsTime(), record.GetTime().GetEventTime().AsTime())
	}
	if made.GetDetectedTime().AsTime().Before(made.GetEventTime().AsTime()) {
		t.Error("the detection was decided before the event it was decided from happened")
	}
	if made.GetSchemaVersion() != detection.SchemaVersion {
		t.Errorf("the detection is written to schema %d and this build writes %d",
			made.GetSchemaVersion(), detection.SchemaVersion)
	}
}

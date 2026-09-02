package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// A detection is written to a schema of its own, the way an event is: the
// process that decides one and the process that reads it back are deployed
// apart and upgraded apart.
const SchemaVersion = 1

// What a match becomes when it has to leave the process.
//
// Everything here is the rule's, the event's, or derived from the two, so
// deciding the same event against the same rule again writes the same record.
// What an operator then does about it — acknowledged, assigned, closed — is an
// alert's lifecycle and is deliberately not here: a detection states what was
// found, and merging the two would mean a replay could overwrite somebody's
// triage.
func (m Match) Detected(ruleset string, record *eventv1.Event, at time.Time) *detectionv1.Detection {
	from, happened := []string{record.GetEventId()}, record.GetTime().GetEventTime()
	if m.Rule.Sequence.Correlates() {
		from = m.Correlated.Events()
		happened = timestamppb.New(m.Correlated.Stages[len(m.Correlated.Stages)-1].At.UTC())
	}

	// The origin is copied rather than pointed at: a detection is read after
	// the event that produced it has been let go, so it may not share memory
	// with it.
	origin, _ := proto.Clone(record.GetOrigin()).(*eventv1.Origin)

	return &detectionv1.Detection{
		DetectionId:    identify(m.Rule.ID, m.Rule.Revision, from),
		SchemaVersion:  SchemaVersion,
		Rule:           decided(m.Rule),
		RulesetId:      ruleset,
		Severity:       severities[m.Rule.Severity],
		Technique:      attributed(m.Rule.Technique),
		EventClass:     record.GetEventClass(),
		Origin:         origin,
		SourceEventIds: from,
		EventTime:      happened,
		DetectedTime:   timestamppb.New(at.UTC()),
		Evidence:       gathered(m.Evidence),
		Aggregation:    aggregated(m.Rule.Count, m.Counted),
		Correlation:    correlated(m.Rule.Sequence, m.Correlated),
	}
}

func correlated(sequence Sequence, found Correlated) *detectionv1.Correlation {
	if !sequence.Correlates() {
		return nil
	}

	correlation := &detectionv1.Correlation{
		Window:      durationpb.New(sequence.Within),
		ClockSpread: durationpb.New(found.ClockSpread),
	}
	for _, stage := range found.Stages {
		correlation.Stages = append(correlation.Stages, &detectionv1.Stage{
			Name:      stage.Name,
			EventId:   stage.Event,
			EventTime: timestamppb.New(stage.At.UTC()),
		})
	}
	correlation.Group = bindings(found.Group)
	return correlation
}

func bindings(group []Binding) []*detectionv1.Grouping {
	if len(group) == 0 {
		return nil
	}

	bound := make([]*detectionv1.Grouping, 0, len(group))
	for _, one := range group {
		bound = append(bound, &detectionv1.Grouping{Field: string(one.Field), Value: one.Value, Absent: one.Absent})
	}
	return bound
}

// It is deliberately no part of the identity above. The events named there are
// what this detection is, and re-deciding them reaches the same count, so
// carrying it would say the same thing twice and give a replay a second way to
// disagree with itself.
func aggregated(counting Count, found Counted) *detectionv1.Aggregation {
	if !counting.Counts() {
		return nil
	}

	aggregation := &detectionv1.Aggregation{
		Count:          uint32(found.Count),
		Threshold:      uint32(counting.AtLeast),
		Window:         durationpb.New(counting.Within),
		FirstEventTime: timestamppb.New(found.First.UTC()),
		Saturated:      found.Saturated,
	}
	aggregation.Group = bindings(found.Group)
	return aggregation
}

// A detection is named by what decided it: the rule, the revision it was
// decided at, and the events it was decided from. Nothing about when, and
// nothing about the process — so a replay rewrites the detection it already
// wrote instead of adding a second copy of it, which is what lets a stage be
// retried until it is durable.
//
// The ruleset is not in here on purpose. It names the whole set, so an
// unrelated rule arriving would rename every detection the others made, and a
// replay after any edit at all would duplicate what it found. The revision is
// what says a rule changed, and a detection carries the ruleset beside its
// identity so that two detections sharing a name and disagreeing about the set
// they came from is a visible state rather than a silent one.
//
// Sorted and counted, as a ruleset names itself, so that the same events in a
// different order are the same detection and no two sets can write the same
// bytes.
func identify(rule ID, revision int, events []string) string {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	write(string(rule))
	write(strconv.Itoa(revision))
	write(strconv.Itoa(len(events)))
	for _, event := range slices.Sorted(slices.Values(events)) {
		write(event)
	}
	return hex.EncodeToString(digest.Sum(nil)[:16])
}

// Which rule fired, at which revision, and where that rule came from — enough
// to go and read it. Its prose is not copied: the ruleset is named by its own
// content, so what the rule said is recoverable from the set rather than
// repeated in every detection the set makes.
func decided(rule Rule) *detectionv1.Rule {
	return &detectionv1.Rule{
		Id:       string(rule.ID),
		Revision: uint32(rule.Revision),
		Name:     rule.Name,
		Source:   from(rule.Source),
	}
}

func from(source Source) *detectionv1.Source {
	if source.empty() {
		return nil
	}
	return &detectionv1.Source{Catalogue: source.Catalogue, Identifier: source.Identifier}
}

func attributed(technique Technique) *detectionv1.Technique {
	if technique.empty() {
		return nil
	}
	return &detectionv1.Technique{Tactic: technique.Tactic, Id: technique.ID, Name: technique.Name}
}

// The evidence, as the executor gathered it. This is the one place a value the
// event carried is written down: it is the reason the detection exists, and it
// is kept here rather than in a log line so that what a producer wrote stays
// out of the platform's own output.
func gathered(seen []Evidence) []*detectionv1.Evidence {
	if len(seen) == 0 {
		return nil
	}

	carried := make([]*detectionv1.Evidence, 0, len(seen))
	for _, one := range seen {
		carried = append(carried, &detectionv1.Evidence{
			Field:    string(one.Field),
			Operator: string(one.Operator),
			Negated:  one.Negated,
			Held:     one.Held,
			Absent:   one.Absent,
		})
	}
	return carried
}

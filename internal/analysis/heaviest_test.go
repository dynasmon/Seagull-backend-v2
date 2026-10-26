package analysis_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var grouped = []detection.Field{
	"origin.host.hostname",
	"origin.host.os",
	"origin.host.architecture",
	"collection.collector",
	"authentication.method",
	"authentication.user.domain",
	"authentication.service.name",
	"authentication.service.protocol",
}

func heavyRule(t *testing.T, id string, shape func(*detection.Rule)) *detection.Program {
	t.Helper()

	failure := detection.Predicate{Field: "authentication.outcome", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("failure")}}
	written := detection.Rule{
		ID: detection.ID(id), Revision: 1, Name: "As heavy as a rule may be", Description: "Asks for every byte a detection may carry.",
		Class: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION, Match: failure, Severity: detection.High, Status: detection.Active,
	}
	shape(&written)
	program, err := detection.Compile(written)
	if err != nil {
		t.Fatalf("compile %s: %v", id, err)
	}
	return program
}

func heavyRules(t *testing.T) []*detection.Program {
	t.Helper()

	questioning := heavyRule(t, "heavy.questioning", func(written *detection.Rule) {
		var asked []detection.Expression
		for _, field := range detection.Fields() {
			if kind, _ := detection.KindOf(field); kind != detection.Text {
				continue
			}
			asked = append(asked, detection.Predicate{Field: field, Operator: detection.Present})
			for _, operator := range []detection.Operator{detection.Equals, detection.OneOf, detection.Contains, detection.StartsWith, detection.EndsWith} {
				never := detection.Predicate{Field: field, Operator: operator, Values: []detection.Value{detection.TextValue("never")}}
				asked = append(asked, detection.Not{Term: never})
			}
		}
		written.Match = detection.All{Terms: asked}
	})
	counting := heavyRule(t, "heavy.counting", func(written *detection.Rule) {
		written.Count = detection.Count{AtLeast: 2, Within: 10 * time.Minute, GroupBy: grouped}
	})
	sequencing := heavyRule(t, "heavy.sequencing", func(written *detection.Rule) {
		written.Sequence = detection.Sequence{Within: 10 * time.Minute, GroupBy: grouped}
		for index := range detection.MaxStages {
			written.Sequence.Stages = append(written.Sequence.Stages, detection.Stage{
				Name: fmt.Sprintf("failure %d of a story as long as a story may be", index+1), Match: written.Match,
			})
		}
		written.Match = nil
	})
	return []*detection.Program{questioning, counting, sequencing}
}

// Two events at the longest the contract allows, one quoted at the greatest cost
// a control character takes, with as many bytes of undeclared fields as its
// ceiling leaves, and one that canonicalisation would have lengthened.
func heavyEvents(t *testing.T, kind string, at time.Time) []analysis.Record {
	t.Helper()

	var records []analysis.Record
	for index := range detection.MaxStages {
		record := fixtures.SSHAuthentication{At: at.Add(time.Duration(index) * time.Second)}.Event()
		record.Reception = &eventv1.Reception{IngestTime: timestamppb.New(at)}
		for path, decided := range decisions {
			most, _ := event.LongestText(path)
			setString(t, record, path, heavyText(kind, path, decided.kind, most))
		}
		record.EventId = fmt.Sprintf("%s%02d", strings.Repeat("e", event.MaxEventIDLength-2), index)

		if kind == "quoted" {
			fixtures.Bloat(record.GetOrigin().GetHost(), 120<<10)
			fixtures.Bloat(record.GetOrigin(), 260<<10)
			fixtures.Bloat(record.GetTime().GetEventTime(), 120<<10)
		}
		if err := event.Validate(record, at.Add(time.Minute), event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: time.Hour}); err != nil {
			t.Fatalf("the %s event is not one the gateway admits: %v", kind, err)
		}

		payload, err := proto.Marshal(record)
		if err != nil {
			t.Fatalf("encode the %s event: %v", kind, err)
		}
		records = append(records, analysis.Record{Partition: 0, Offset: int64(len(records)), Value: payload})
	}
	return records
}

func heavyText(kind, path, decided string, most int) string {
	switch {
	case path == "origin.agent_id":
		return strings.Repeat("a", most)
	case decided == addressed:
		return "1::3:4:5:6:7:8%" + strings.Repeat("z", most-len("1::3:4:5:6:7:8%"))
	case kind == "quoted":
		return strings.Repeat("\x00", most)
	case decided == folded || decided == named:
		return strings.Repeat("Ⱥ", most/2)
	}
	return strings.Repeat("a", most)
}

func TestEveryDetectionTheEngineMakesIsOneItsConsumersTakeAndNoHeavierThanItsRule(t *testing.T) {
	programs := heavyRules(t)
	at := time.Now().UTC().Add(-time.Minute)
	source := &oneBatch{records: append(heavyEvents(t, "quoted", at), heavyEvents(t, "folded", at)...)}
	engine, _, _, sink := engineReporting(t, source, pinned{id: "3538ec98f5ce3e22e8e65f47cd0344ee", programs: programs, held: true}, slog.LevelError, &collected{})

	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("run the engine: %v", err)
	}

	heaviest := make(map[string]int, len(programs))
	for _, program := range programs {
		heaviest[string(program.Rule().ID)] = program.Heaviest()
	}
	made := make(map[string]int, len(programs))
	for _, detected := range sink.all() {
		rule := detected.GetRule().GetId()
		made[rule]++
		if size := proto.Size(detected); size > heaviest[rule] {
			t.Errorf("%s made a detection of %d bytes and its heaviest is %d", rule, size, heaviest[rule])
		}
		if err := detection.ValidateContract(detected); err != nil {
			t.Errorf("%s made a detection its consumers refuse: %v", rule, err)
		}
	}
	for rule := range heaviest {
		if made[rule] == 0 {
			t.Errorf("%s made nothing, so it proves nothing", rule)
		}
	}
}

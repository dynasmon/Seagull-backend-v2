package ruleset_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

var published = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// The property the whole ruleset log rests on: what an engine composes from a
// record is the same ruleset the control plane composed from the documents, so
// a detection made against a published ruleset names what a person can read
// back out of the file it was written in.
func TestARulesetReadFromFilesAndFromTheBackboneNameTheSameThing(t *testing.T) {
	written, err := rulefile.Rules(os.DirFS(filepath.Join("..", "..", "deploy", "rules")))
	if err != nil {
		t.Fatalf("read the shipped rules: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("the shipped rule tree holds no rules, so this proves nothing")
	}

	programs := make([]*detection.Program, 0, len(written))
	cases := make(map[detection.ID][]detection.Case, len(written))
	for _, rule := range written {
		programs = append(programs, rule.Program)
		cases[rule.Program.Rule().ID] = rule.Cases
	}

	version, err := ruleset.NewVersion(programs, cases, "dev-engineer", published, "the shipped tree")
	if err != nil {
		t.Fatalf("publish a version: %v", err)
	}

	encoded, err := proto.Marshal(version.Encode())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var crossed rulesetv1.Version
	if err := proto.Unmarshal(encoded, &crossed); err != nil {
		t.Fatalf("decode: %v", err)
	}

	read, err := ruleset.DecodeVersion(&crossed)
	if err != nil {
		t.Fatalf("read the version back: %v", err)
	}
	if read.ID() != version.ID() {
		t.Fatalf("the same rules named %s in files and %s on the backbone", version.ID(), read.ID())
	}
	if read.Snapshot().Rules() != version.Snapshot().Rules() {
		t.Errorf("%d rules crossed of %d", read.Snapshot().Rules(), version.Snapshot().Rules())
	}
	if read.Snapshot().Running() != version.Snapshot().Running() {
		t.Errorf("%d rules run of %d", read.Snapshot().Running(), version.Snapshot().Running())
	}
}

// A case travels with its rule and changes nothing about what the ruleset is,
// so a rule can still be re-checked after it has been published without the
// act of writing a case being a new rollout.
func TestCasesCrossWithTheRuleAndDoNotChangeTheRuleset(t *testing.T) {
	subject := rule("ssh.failed_password")
	held := []detection.Case{{
		Name:   "a failure is matched",
		Expect: detection.Matches,
		Event:  map[detection.Field]detection.Value{"authentication.user.name": detection.TextValue("root")},
	}}

	bare := version(t, nil, compiled(t, subject))
	with := version(t, map[detection.ID][]detection.Case{subject.ID: held}, compiled(t, subject))

	if bare.ID() != with.ID() {
		t.Errorf("writing a case renamed the ruleset from %s to %s", bare.ID(), with.ID())
	}

	read, err := ruleset.DecodeVersion(with.Encode())
	if err != nil {
		t.Fatalf("read the version back: %v", err)
	}
	crossed := read.Cases(subject.ID)
	if len(crossed) != 1 || crossed[0].Name != held[0].Name {
		t.Fatalf("the case did not cross: %v", crossed)
	}
	if got := crossed[0].Event["authentication.user.name"]; got.Text() != "root" {
		t.Errorf("the case event crossed as %v", got)
	}
}

// A record is held to naming itself, so rules rewritten in transit cannot
// become what an engine runs under the name of a ruleset somebody approved.
func TestARecordThatDoesNotNameItselfIsRefused(t *testing.T) {
	encoded := version(t, nil, compiled(t, rule("ssh.session_opened"))).Encode()
	encoded.Rules[0].Name = "something else entirely"

	if _, err := ruleset.DecodeVersion(encoded); err == nil {
		t.Fatal("a record whose rules do not hash to its id was read as that ruleset")
	}
}

func TestAVersionSaysWhoPublishedItAndWhen(t *testing.T) {
	programs := []*detection.Program{compiled(t, rule("ssh.session_opened"))}

	if _, err := ruleset.NewVersion(programs, nil, "", published, ""); err == nil {
		t.Error("a ruleset was published by nobody")
	}
	if _, err := ruleset.NewVersion(programs, nil, "dev-engineer", time.Time{}, ""); err == nil {
		t.Error("a ruleset was published at no time")
	}
}

func TestARuleThisBuildCannotReadIsRefusedRatherThanDefaulted(t *testing.T) {
	for name, break_ := range map[string]func(*rulesetv1.Version){
		"an undeclared status":   func(v *rulesetv1.Version) { v.Rules[0].Status = rulesetv1.Status_STATUS_UNSPECIFIED },
		"an undeclared severity": func(v *rulesetv1.Version) { v.Rules[0].Severity = 0 },
		"an expression with no term": func(v *rulesetv1.Version) {
			v.Rules[0].Match = &rulesetv1.Expression{}
		},
		"a literal with no value": func(v *rulesetv1.Version) {
			v.Rules[0].Match = &rulesetv1.Expression{Term: &rulesetv1.Expression_Predicate{
				Predicate: &rulesetv1.Predicate{Field: "authentication.user.name", Operator: "equals", Values: []*rulesetv1.Value{{}}},
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded := version(t, nil, compiled(t, rule("ssh.session_opened"))).Encode()
			break_(encoded)

			if _, err := ruleset.DecodeVersion(encoded); err == nil {
				t.Fatalf("%s was read as something this build understands", name)
			}
		})
	}
}

// Everything a rule carries crosses, because everything a rule carries changes
// the ruleset it belongs to and a field left behind would rename it.
func TestEveryFieldOfARuleSurvivesTheCrossing(t *testing.T) {
	subject := rule("ssh.failed_password")
	subject.Description = "A description that is long enough to be worth carrying."
	subject.FalsePositives = "A service account that authenticates on a schedule."
	subject.Response = "Check whether the account is meant to reach this host."
	subject.Source = detection.Source{Catalogue: "sigma", Identifier: "abc-123"}
	subject.Tags = []string{"ssh", "bruteforce"}
	subject.References = []string{"https://attack.mitre.org/techniques/T1110/001/"}
	subject.Match = detection.All{Terms: []detection.Expression{
		detection.Predicate{Field: "authentication.user.name", Operator: detection.Equals, Values: []detection.Value{detection.TextValue("root")}},
		detection.Any{Terms: []detection.Expression{
			detection.Predicate{Field: "authentication.network.source.port", Operator: detection.Above, Values: []detection.Value{detection.NumberValue(1024)}},
			detection.Not{Term: detection.Predicate{Field: "authentication.network.source.ip", Operator: detection.Present}},
		}},
	}}

	before := version(t, nil, compiled(t, subject))
	after, err := ruleset.DecodeVersion(before.Encode())
	if err != nil {
		t.Fatalf("read the version back: %v", err)
	}
	if after.ID() != before.ID() {
		t.Fatalf("a rule lost something crossing: %s became %s", before.ID(), after.ID())
	}
}

func version(t *testing.T, cases map[detection.ID][]detection.Case, programs ...*detection.Program) *ruleset.Version {
	t.Helper()

	held, err := ruleset.NewVersion(programs, cases, "dev-engineer", published, "")
	if err != nil {
		t.Fatalf("publish a version: %v", err)
	}
	return held
}

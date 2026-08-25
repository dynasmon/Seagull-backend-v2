package ruleset_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const authentication = eventv1.EventClass_EVENT_CLASS_AUTHENTICATION

func TestASnapshotHoldsEveryRuleAndRunsTheActiveOnes(t *testing.T) {
	snapshot := compose(t,
		compiled(t, rule("ssh.session_opened")),
		compiled(t, draft("ssh.failed_password")),
		compiled(t, rule("ssh.invalid_user")),
	)

	if snapshot.Rules() != 3 {
		t.Errorf("the snapshot holds %d rules", snapshot.Rules())
	}
	if snapshot.Running() != 2 {
		t.Errorf("the snapshot runs %d rules and a draft is not one of them", snapshot.Running())
	}

	running := ids(snapshot, authentication)
	if !slices.Equal(running, []detection.ID{"ssh.invalid_user", "ssh.session_opened"}) {
		t.Errorf("the snapshot runs %v, in rule order and without the draft", running)
	}
}

// The same rules in a different order are the same ruleset, so two processes
// reading the same tree name the same thing whatever their files are called.
func TestOrderDoesNotChangeWhatARulesetIs(t *testing.T) {
	one := compose(t, compiled(t, rule("b.rule")), compiled(t, rule("a.rule")))
	other := compose(t, compiled(t, rule("a.rule")), compiled(t, rule("b.rule")))

	if one.ID() != other.ID() {
		t.Errorf("the same rules named %s and %s", one.ID(), other.ID())
	}
}

// Everything a rule carries can change what a detection says, so everything a
// rule carries changes the ruleset it belongs to.
func TestAnythingARuleCarriesChangesTheRuleset(t *testing.T) {
	before := compose(t, compiled(t, rule("ssh.session_opened"))).ID()

	for field, change := range changesToARule() {
		t.Run(field, func(t *testing.T) {
			if change == nil {
				t.Skip("the contract declares one event class, so a rule has no second one to be written for")
			}

			subject := rule("ssh.session_opened")
			change(&subject)

			if after := compose(t, compiled(t, subject)).ID(); after == before {
				t.Errorf("changing %s left the ruleset named %s", field, after)
			}
		})
	}
}

// A field added to a rule and forgotten in the digest is a field a ruleset is
// not named by, and two rulesets that decide events differently would then share
// a name — which is what makes a detection traceable to the rules that made it.
// Held in both directions, so a field that leaves the domain fails here too.
func TestEveryFieldOfARuleIsAccountedForInTheRulesetItNames(t *testing.T) {
	accounted := changesToARule()
	carried := reflect.TypeFor[detection.Rule]()

	for index := range carried.NumField() {
		field := carried.Field(index).Name
		if _, named := accounted[field]; !named {
			t.Errorf("a rule carries %s and nothing here says whether it names the ruleset", field)
		}
	}
	for field := range accounted {
		if _, declared := carried.FieldByName(field); !declared {
			t.Errorf("%s is accounted for here and a rule does not carry it", field)
		}
	}
}

// Every field of a rule, and a second rule the domain still accepts that differs
// only in that field. A field with no second value to give it is named with no
// change rather than left out, so the coverage above still accounts for it.
func changesToARule() map[string]func(*detection.Rule) {
	return map[string]func(*detection.Rule){
		"ID":             func(r *detection.Rule) { r.ID = "ssh.something_else" },
		"Revision":       func(r *detection.Rule) { r.Revision = 2 },
		"Name":           func(r *detection.Rule) { r.Name = "Another name" },
		"Description":    func(r *detection.Rule) { r.Description = "Another description." },
		"Class":          nil,
		"Match":          func(r *detection.Rule) { r.Match = predicate("authentication.user.uid") },
		"Severity":       func(r *detection.Rule) { r.Severity = detection.High },
		"Status":         func(r *detection.Rule) { r.Status = detection.Disabled },
		"Technique":      func(r *detection.Rule) { r.Technique.ID = "T1110.003" },
		"FalsePositives": func(r *detection.Rule) { r.FalsePositives = "An administrator mistyping a password." },
		"Response":       func(r *detection.Rule) { r.Response = "Do something else." },
		"Tags":           func(r *detection.Rule) { r.Tags = []string{"ssh"} },
		"References":     func(r *detection.Rule) { r.References = []string{"https://attack.mitre.org/techniques/T1110/001/"} },
		"Source": func(r *detection.Rule) {
			r.Source = detection.Source{Catalogue: "sigma", Identifier: "5013fd8a-56f1-4d5c-9f1d-4c9d0a1f3b77"}
		},
	}
}

// A tag is a set and a reference is a list, so filing a rule under the same two
// words in the other order is the same rule and citing the same two pages in the
// other order is not.
func TestTagsAreASetAndReferencesAreAList(t *testing.T) {
	tagged := func(tags ...string) detection.Rule {
		subject := rule("ssh.session_opened")
		subject.Tags = tags
		return subject
	}
	cited := func(references ...string) detection.Rule {
		subject := rule("ssh.session_opened")
		subject.References = references
		return subject
	}

	one := compose(t, compiled(t, tagged("ssh", "credential_access"))).ID()
	other := compose(t, compiled(t, tagged("credential_access", "ssh"))).ID()
	if one != other {
		t.Errorf("the same two tags in the other order named %s and %s", one, other)
	}

	first := "https://attack.mitre.org/techniques/T1110/001/"
	second := "https://example.test/runbooks/ssh"
	one = compose(t, compiled(t, cited(first, second))).ID()
	other = compose(t, compiled(t, cited(second, first))).ID()
	if one == other {
		t.Errorf("the same two references in the other order both named %s", one)
	}
}

// A list that is not counted can borrow what follows it: a rule tagged `ssh` and
// citing nothing would otherwise write the bytes of one tagged nothing and
// citing `ssh`.
func TestOneListCannotBeReadAsAnother(t *testing.T) {
	tagged := rule("ssh.session_opened")
	tagged.Tags = []string{"https://example.test/"}

	cited := rule("ssh.session_opened")
	cited.References = []string{"https://example.test/"}

	if _, err := detection.Compile(tagged); err == nil {
		t.Fatal("a tag that is a link was accepted and this test needs it refused")
	}

	tagged.Tags = []string{"ssh"}
	cited.References = []string{"https://example.test/ssh"}

	one := compose(t, compiled(t, tagged)).ID()
	other := compose(t, compiled(t, cited)).ID()
	if one == other {
		t.Errorf("a tag and a reference wrote the same ruleset name %s", one)
	}
}

func TestTheSameRulesAlwaysNameTheSameRuleset(t *testing.T) {
	first := compose(t, compiled(t, rule("a.rule")), compiled(t, draft("b.rule")))
	second := compose(t, compiled(t, rule("a.rule")), compiled(t, draft("b.rule")))

	if first.ID() != second.ID() {
		t.Errorf("two identical rulesets are named %s and %s", first.ID(), second.ID())
	}
	if first.ID() == "" {
		t.Error("a ruleset has no name")
	}
}

func TestARulesetHoldsOneRulePerId(t *testing.T) {
	_, err := ruleset.Compose([]*detection.Program{
		compiled(t, rule("a.rule")),
		compiled(t, draft("a.rule")),
	})
	if err == nil {
		t.Fatal("a ruleset holding one id twice was composed")
	}
	if got := err.Error(); got != `a ruleset holds one rule per id and "a.rule" arrives twice` {
		t.Errorf("the refusal reads %q", got)
	}
}

func TestARulesetHoldsCompiledRules(t *testing.T) {
	if _, err := ruleset.Compose([]*detection.Program{compiled(t, rule("a.rule")), nil}); err == nil {
		t.Fatal("a ruleset holding nothing at all was composed")
	}
}

// A fresh deployment has no rules and is still a ruleset: it is named, it is
// consistent, and asking it what runs for a class gives nothing rather than
// failing.
func TestARulesetCanHoldNothing(t *testing.T) {
	snapshot := compose(t)

	if snapshot.Rules() != 0 || snapshot.Running() != 0 {
		t.Errorf("an empty ruleset holds %d rules and runs %d", snapshot.Rules(), snapshot.Running())
	}
	if snapshot.ID() == "" {
		t.Error("an empty ruleset has no name")
	}
	if read := ids(snapshot, authentication); len(read) != 0 {
		t.Errorf("an empty ruleset runs %v", read)
	}
}

// Composing copies what it was given, so a caller that keeps its slice and
// writes into it cannot change a ruleset a worker is already reading.
func TestComposingKeepsWhatItWasGivenToItself(t *testing.T) {
	programs := []*detection.Program{compiled(t, rule("a.rule")), compiled(t, rule("b.rule"))}
	snapshot := compose(t, programs...)

	programs[0], programs[1] = programs[1], programs[0]
	if read := ids(snapshot, authentication); !slices.Equal(read, []detection.ID{"a.rule", "b.rule"}) {
		t.Errorf("the ruleset changed under the snapshot and now runs %v", read)
	}
}

func ids(snapshot *ruleset.Snapshot, class eventv1.EventClass) []detection.ID {
	var read []detection.ID
	for program := range snapshot.For(class) {
		read = append(read, program.Rule().ID)
	}
	return read
}

func compose(t *testing.T, programs ...*detection.Program) *ruleset.Snapshot {
	t.Helper()

	snapshot, err := ruleset.Compose(programs)
	if err != nil {
		t.Fatalf("compose a ruleset: %v", err)
	}
	return snapshot
}

func compiled(t *testing.T, subject detection.Rule) *detection.Program {
	t.Helper()

	program, err := detection.Compile(subject)
	if err != nil {
		t.Fatalf("compile %q: %v", subject.ID, err)
	}
	return program
}

func rule(id detection.ID) detection.Rule {
	return detection.Rule{
		ID:          id,
		Revision:    1,
		Name:        "A name",
		Description: "A description.",
		Class:       authentication,
		Match:       predicate("authentication.user.name"),
		Severity:    detection.Medium,
		Status:      detection.Active,
		Technique: detection.Technique{
			Tactic: "credential_access",
			ID:     "T1110.001",
			Name:   "Brute Force: Password Guessing",
		},
	}
}

func draft(id detection.ID) detection.Rule {
	written := rule(id)
	written.Status = detection.Draft
	return written
}

func predicate(field detection.Field) detection.Expression {
	return detection.Predicate{Field: field, Operator: detection.Present}
}

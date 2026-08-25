package detection_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The rule the rest of this file breaks one piece at a time: ten failed SSH
// passwords are not modelled yet, so this is what a stateless version of the
// same intent looks like.
func rule() detection.Rule {
	return detection.Rule{
		ID:          "ssh.failed_password_from_outside",
		Revision:    1,
		Name:        "Failed SSH password from an external address",
		Description: "A password authentication over SSH failed for a session that came from outside the estate.",
		Class:       eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Match: detection.All{Terms: []detection.Expression{
			detection.Predicate{
				Field:    "authentication.outcome",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("failure")},
			},
			detection.Predicate{
				Field:    "authentication.service.protocol",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("ssh")},
			},
			detection.Not{Term: detection.Predicate{
				Field:    "authentication.network.source.ip",
				Operator: detection.StartsWith,
				Values:   []detection.Value{detection.TextValue("10.")},
			}},
		}},
		Severity: detection.Medium,
		Status:   detection.Active,
		Technique: detection.Technique{
			Tactic: "credential_access",
			ID:     "T1110.001",
			Name:   "Brute Force: Password Guessing",
		},
		FalsePositives: "An administrator mistyping a password from a home connection.",
		Response:       "Confirm the account is expected to be reachable from outside, then check for a pattern from the same address.",
	}
}

func TestARuleTheEngineCanRunIsAccepted(t *testing.T) {
	if err := rule().Validate(); err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}
}

func TestOnlyAnActiveRuleRuns(t *testing.T) {
	running := map[detection.Status]bool{
		detection.Active:     true,
		detection.Draft:      false,
		detection.Disabled:   false,
		detection.Deprecated: false,
	}
	for status, expected := range running {
		if runs := status.Runs(); runs != expected {
			t.Errorf("a %s rule runs=%v", status, runs)
		}
	}
}

func TestARuleTheEngineCannotRunIsRefusedByPart(t *testing.T) {
	cases := map[string]struct {
		part   string
		says   string
		broken func(*detection.Rule)
	}{
		"no id":                 {"id", "lowercase words", func(r *detection.Rule) { r.ID = "" }},
		"id in capitals":        {"id", "lowercase words", func(r *detection.Rule) { r.ID = "SSH.Failed" }},
		"id carrying a version": {"id", "ends in a version", func(r *detection.Rule) { r.ID = "ssh.failed_password_v2" }},
		"no revision":           {"revision", "at least 1", func(r *detection.Rule) { r.Revision = 0 }},
		"no name":               {"name", "is missing", func(r *detection.Rule) { r.Name = "  " }},
		"no description":        {"description", "is missing", func(r *detection.Rule) { r.Description = "" }},
		"unknown severity":      {"severity", "not one of low", func(r *detection.Rule) { r.Severity = "urgent" }},
		"unknown status":        {"status", "not one of draft", func(r *detection.Rule) { r.Status = "on" }},
		"no class": {"class", "must name the class", func(r *detection.Rule) {
			r.Class = eventv1.EventClass_EVENT_CLASS_UNSPECIFIED
		}},
		"a class the contract does not declare": {"class", "does not declare", func(r *detection.Rule) {
			r.Class = eventv1.EventClass(4242)
		}},
		"half a technique": {"technique", "or none of the three", func(r *detection.Rule) {
			r.Technique = detection.Technique{Tactic: "credential_access"}
		}},
		"a tactic ATT&CK does not have": {"technique.tactic", "enterprise tactic", func(r *detection.Rule) {
			r.Technique.Tactic = "credential_theft"
		}},
		"a technique id that is not one": {"technique.id", "T1110", func(r *detection.Rule) {
			r.Technique.ID = "T110"
		}},
		"no match": {"match", "matches everything", func(r *detection.Rule) { r.Match = nil }},
		"a match that asks nothing": {"match.all", "has no terms", func(r *detection.Rule) {
			r.Match = detection.All{}
		}},
		"a field the contract does not declare": {"match.authentication.user.nam", "not a field the contract declares", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.user.nam",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("root")},
			}
		}},
		"an operator that is not one": {"match.authentication.user.name", "not an operator", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.user.name",
				Operator: "matches",
				Values:   []detection.Value{detection.TextValue("root")},
			}
		}},
		"text asked a number's question": {"match.authentication.user.name", "does not ask that", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.user.name",
				Operator: detection.Above,
				Values:   []detection.Value{detection.NumberValue(10)},
			}
		}},
		"a number asked to contain": {"match.authentication.network.source.port", "does not ask that", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.network.source.port",
				Operator: detection.Contains,
				Values:   []detection.Value{detection.TextValue("22")},
			}
		}},
		"a number compared against text": {"match.authentication.network.source.port", "holds number and is compared against", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.network.source.port",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("22")},
			}
		}},
		"nothing to compare against": {"match.authentication.user.name", "nothing to compare against", func(r *detection.Rule) {
			r.Match = detection.Predicate{Field: "authentication.user.name", Operator: detection.Equals}
		}},
		"more values than the operator reads": {"match.authentication.user.name", "and it reads 1", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.user.name",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("root"), detection.TextValue("admin")},
			}
		}},
		"compared against nothing at all": {"match.authentication.user.name", "every event matches", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.user.name",
				Operator: detection.Contains,
				Values:   []detection.Value{detection.TextValue("   ")},
			}
		}},
		"a choice the contract does not declare": {"match.authentication.outcome", "the contract declares", func(r *detection.Rule) {
			r.Match = detection.Predicate{
				Field:    "authentication.outcome",
				Operator: detection.Equals,
				Values:   []detection.Value{detection.TextValue("refused")},
			}
		}},
		"a rule nested past reading": {"match", "nests deeper than", func(r *detection.Rule) { r.Match = nested(detection.MaxDepth + 2) }},
		"half a source": {"source", "or neither", func(r *detection.Rule) {
			r.Source = detection.Source{Catalogue: "sigma"}
		}},
		"a source with no catalogue": {"source", "or neither", func(r *detection.Rule) {
			r.Source = detection.Source{Identifier: "5013fd8a-56f1-4d5c-9f1d-4c9d0a1f3b77"}
		}},
		"a catalogue that is not a name": {"source.catalogue", "lowercase words", func(r *detection.Rule) {
			r.Source = detection.Source{Catalogue: "Sigma HQ", Identifier: "5013fd8a"}
		}},
		"a tag that is not a name": {"tags[0]", "lowercase words", func(r *detection.Rule) {
			r.Tags = []string{"Privilege Escalation"}
		}},
		"the same tag twice": {"tags[1]", "already carries", func(r *detection.Rule) {
			r.Tags = []string{"ssh", "ssh"}
		}},
		"more tags than a rule can carry": {"tags", "above the ceiling", func(r *detection.Rule) {
			r.Tags = names(detection.MaxTags + 1)
		}},
		"a reference that is not a link": {"references[0]", "http or https link", func(r *detection.Rule) {
			r.References = []string{"the runbook in the wiki"}
		}},
		"a reference under a scheme nobody can open": {"references[0]", "http or https link", func(r *detection.Rule) {
			r.References = []string{"file:///etc/seagull/runbook.md"}
		}},
		"the same reference twice": {"references[1]", "already carries", func(r *detection.Rule) {
			r.References = []string{"https://attack.mitre.org/techniques/T1110/001/", "https://attack.mitre.org/techniques/T1110/001/"}
		}},
		"a reference longer than one anybody wrote": {"references[0]", "longer than", func(r *detection.Rule) {
			r.References = []string{"https://example.test/" + strings.Repeat("a", detection.MaxReferenceLength)}
		}},
		"more references than a rule can carry": {"references", "above the ceiling", func(r *detection.Rule) {
			r.References = links(detection.MaxReferences + 1)
		}},
	}

	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			subject := rule()
			broken.broken(&subject)

			err := subject.Validate()
			if err == nil {
				t.Fatalf("a rule with %s was accepted", name)
			}

			var violation *detection.Violation
			if !errors.As(err, &violation) {
				t.Fatalf("the refusal is a %T and should name the part that is wrong", err)
			}
			if !strings.HasPrefix(violation.Part, broken.part) {
				t.Errorf("the refusal points at %q and should point at %q: %v", violation.Part, broken.part, err)
			}
			if !strings.Contains(violation.Reason, broken.says) {
				t.Errorf("the refusal reads %q and should say %q", violation.Reason, broken.says)
			}
		})
	}
}

// A rule that reads the envelope and no body is valid: what an event carries
// about the agent that sent it is common to every class.
func TestARuleMayReadTheEnvelopeAlone(t *testing.T) {
	subject := rule()
	subject.Match = detection.Predicate{
		Field:    "origin.host.hostname",
		Operator: detection.EndsWith,
		Values:   []detection.Value{detection.TextValue(".dmz.internal")},
	}
	if err := subject.Validate(); err != nil {
		t.Fatalf("a rule reading the envelope was refused: %v", err)
	}
}

// A rule says where it came from, what it is filed under and what explains it,
// or says none of it: this estate wrote most of them, and nothing about a rule
// written here has an upstream identifier to carry.
func TestARuleThatSaysWhereItCameFromIsAccepted(t *testing.T) {
	subject := rule()
	subject.Source = detection.Source{Catalogue: "sigma", Identifier: "5013fd8a-56f1-4d5c-9f1d-4c9d0a1f3b77"}
	subject.Tags = []string{"ssh", "credential_access"}
	subject.References = []string{
		"https://attack.mitre.org/techniques/T1110/001/",
		"http://internal.example.test/runbooks/ssh",
	}

	if err := subject.Validate(); err != nil {
		t.Fatalf("a rule carrying its provenance was refused: %v", err)
	}
}

// The technique is optional, because not everything worth detecting is an
// adversary technique.
func TestARuleWithoutATechniqueIsAccepted(t *testing.T) {
	subject := rule()
	subject.Technique = detection.Technique{}
	if err := subject.Validate(); err != nil {
		t.Fatalf("a rule that attributes itself to nothing was refused: %v", err)
	}
}

func TestARefusalNamesTheRuleAndThePart(t *testing.T) {
	subject := rule()
	subject.Severity = "urgent"

	err := subject.Validate()
	if err == nil {
		t.Fatal("an unknown severity was accepted")
	}
	message := err.Error()
	for _, expected := range []string{string(subject.ID), "severity", "urgent"} {
		if !strings.Contains(message, expected) {
			t.Errorf("the refusal does not mention %q: %s", expected, message)
		}
	}
}

func names(count int) []string {
	tags := make([]string, 0, count)
	for index := range count {
		tags = append(tags, fmt.Sprintf("tag%d", index))
	}
	return tags
}

func links(count int) []string {
	references := make([]string, 0, count)
	for index := range count {
		references = append(references, fmt.Sprintf("https://example.test/%d", index))
	}
	return references
}

func nested(depth int) detection.Expression {
	term := detection.Expression(detection.Predicate{
		Field:    "authentication.user.name",
		Operator: detection.Equals,
		Values:   []detection.Value{detection.TextValue("root")},
	})
	for range depth {
		term = detection.Not{Term: term}
	}
	return term
}

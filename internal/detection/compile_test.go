package detection_test

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

func TestARuleCompilesIntoWhatItAsks(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	const asked = `(authentication.outcome equals failure and ` +
		`authentication.service.protocol equals "ssh" and ` +
		`not authentication.network.source.ip starts_with "10.")`
	if written := program.String(); written != asked {
		t.Errorf("the rule compiled to\n%s\nand should have compiled to\n%s", written, asked)
	}
	if program.Rule().ID != rule().ID {
		t.Errorf("the program carries rule %q", program.Rule().ID)
	}
}

// The short form a rule writes a choice in survives compilation, which is how
// the program says it resolved `failure` to the value the contract declares
// rather than keeping the word.
func TestAChoiceCompilesToTheValueTheContractDeclares(t *testing.T) {
	subject := rule()
	subject.Match = detection.Predicate{
		Field:    "authentication.activity",
		Operator: detection.OneOf,
		Values:   []detection.Value{detection.TextValue("logon"), detection.TextValue("logoff")},
	}

	program, err := detection.Compile(subject)
	if err != nil {
		t.Fatalf("a rule asking about an activity was refused: %v", err)
	}
	if written := program.String(); written != "authentication.activity one_of [logon, logoff]" {
		t.Errorf("the rule compiled to %s", written)
	}
}

func TestACompiledRuleNamesTheFieldsItReads(t *testing.T) {
	program, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("a rule that should run was refused: %v", err)
	}

	read := []detection.Field{
		"authentication.network.source.ip",
		"authentication.outcome",
		"authentication.service.protocol",
	}
	if fields := program.Fields(); !slices.Equal(fields, read) {
		t.Errorf("the program reads %v and should read %v", fields, read)
	}
}

// Compilation is validation and then everything only the contract's own types
// can answer, so nothing the domain refuses can reach a program.
func TestARuleTheDomainRefusesIsNotCompiled(t *testing.T) {
	subject := rule()
	subject.Severity = "urgent"

	program, err := detection.Compile(subject)
	if err == nil {
		t.Fatal("a rule with an unknown severity compiled")
	}
	if program != nil {
		t.Error("a refused rule produced a program")
	}

	var violation *detection.Violation
	if !errors.As(err, &violation) {
		t.Fatalf("the refusal is a %T and should name the part that is wrong", err)
	}
	if violation.Part != "severity" {
		t.Errorf("the refusal points at %q", violation.Part)
	}
}

// A literal the field could never carry compares false against every event, so
// a rule that states one is refused rather than left quiet.
func TestALiteralIsHeldToTheTypeItsFieldHolds(t *testing.T) {
	cases := map[string]struct {
		field detection.Field
		value detection.Value
		says  string
	}{
		"below what an unsigned field holds": {
			"authentication.network.source.port", detection.NumberValue(-1), "whole numbers from 0 to 4294967295",
		},
		"above what a thirty-two bit field holds": {
			"authentication.network.source.port", detection.NumberValue(1 << 33), "whole numbers from 0 to 4294967295",
		},
		"a fraction against a whole number": {
			"authentication.network.source.port", detection.NumberValue(3.5), "the field holds whole numbers",
		},
		"a number no rule can state exactly": {
			"collection.sequence", detection.NumberValue(1e30), "whole numbers from 0 to 9007199254740992",
		},
		"a number that is not one": {
			"collection.sequence", detection.NumberValue(math.Inf(1)), "the field holds whole numbers",
		},
	}

	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			subject := rule()
			subject.Match = detection.Predicate{
				Field:    broken.field,
				Operator: detection.Equals,
				Values:   []detection.Value{broken.value},
			}

			err := compileRefusal(t, subject)
			if !strings.Contains(err.Reason, broken.says) {
				t.Errorf("the refusal reads %q and should say %q", err.Reason, broken.says)
			}
			if !strings.HasPrefix(err.Part, "match."+string(broken.field)) {
				t.Errorf("the refusal points at %q", err.Part)
			}
		})
	}
}

// The ceiling is the contract's and not the product's: a port is a uint32
// because the contract says so, and a rule naming one no service listens on is
// a rule that is wrong rather than one that cannot be written.
func TestALiteralTheFieldCanCarryIsCompiled(t *testing.T) {
	for _, value := range []float64{0, 22, 70000, math.MaxUint32} {
		subject := rule()
		subject.Match = detection.Predicate{
			Field:    "authentication.network.source.port",
			Operator: detection.Equals,
			Values:   []detection.Value{detection.NumberValue(value)},
		}
		if _, err := detection.Compile(subject); err != nil {
			t.Errorf("a port of %v was refused: %v", value, err)
		}
	}
}

func TestCompilingTheSameRuleTwiceGivesTheSameProgram(t *testing.T) {
	first, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	second, err := detection.Compile(rule())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if first.String() != second.String() {
		t.Errorf("the same rule compiled to\n%s\nand then to\n%s", first, second)
	}
}

func compileRefusal(t *testing.T, subject detection.Rule) *detection.Violation {
	t.Helper()

	_, err := detection.Compile(subject)
	if err == nil {
		t.Fatal("the rule compiled and should have been refused")
	}
	var violation *detection.Violation
	if !errors.As(err, &violation) {
		t.Fatalf("the refusal is a %T and should name the part that is wrong", err)
	}
	return violation
}

package ruleset

import (
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// Mapped explicitly in both directions rather than by name, so renaming a
// constant on either side is a compile error here instead of a rule that means
// something else once it has crossed a runtime boundary.
var (
	severities = map[detection.Severity]detectionv1.Severity{
		detection.Low:      detectionv1.Severity_SEVERITY_LOW,
		detection.Medium:   detectionv1.Severity_SEVERITY_MEDIUM,
		detection.High:     detectionv1.Severity_SEVERITY_HIGH,
		detection.Critical: detectionv1.Severity_SEVERITY_CRITICAL,
	}

	statuses = map[detection.Status]rulesetv1.Status{
		detection.Draft:      rulesetv1.Status_STATUS_DRAFT,
		detection.Active:     rulesetv1.Status_STATUS_ACTIVE,
		detection.Disabled:   rulesetv1.Status_STATUS_DISABLED,
		detection.Deprecated: rulesetv1.Status_STATUS_DEPRECATED,
	}

	expectations = map[detection.Expectation]rulesetv1.Expectation{
		detection.Matches:      rulesetv1.Expectation_EXPECTATION_MATCH,
		detection.DoesNotMatch: rulesetv1.Expectation_EXPECTATION_NO_MATCH,
	}

	written     = reversed(severities)
	standing    = reversed(statuses)
	expectingOf = reversed(expectations)
)

func reversed[K comparable, V comparable](forward map[K]V) map[V]K {
	backward := make(map[V]K, len(forward))
	for key, value := range forward {
		backward[value] = key
	}
	return backward
}

func encodeRule(rule detection.Rule, cases []detection.Case) *rulesetv1.Rule {
	encoded := &rulesetv1.Rule{
		Id:             string(rule.ID),
		Revision:       uint32(rule.Revision),
		Name:           rule.Name,
		Description:    rule.Description,
		EventClass:     rule.Class,
		Match:          encodeExpression(rule.Match),
		Severity:       severities[rule.Severity],
		Status:         statuses[rule.Status],
		FalsePositives: rule.FalsePositives,
		Response:       rule.Response,
		Tags:           slices.Clone(rule.Tags),
		References:     slices.Clone(rule.References),
	}

	if rule.Technique != (detection.Technique{}) {
		encoded.Technique = &detectionv1.Technique{
			Tactic: rule.Technique.Tactic,
			Id:     rule.Technique.ID,
			Name:   rule.Technique.Name,
		}
	}
	if rule.Count.Counts() {
		encoded.Count = &rulesetv1.Count{
			AtLeast: uint32(rule.Count.AtLeast),
			Within:  durationpb.New(rule.Count.Within),
		}
		for _, field := range rule.Count.GroupBy {
			encoded.Count.GroupBy = append(encoded.Count.GroupBy, string(field))
		}
	}
	if rule.Source != (detection.Source{}) {
		encoded.Source = &detectionv1.Source{
			Catalogue:  rule.Source.Catalogue,
			Identifier: rule.Source.Identifier,
		}
	}
	for _, subject := range cases {
		encoded.Cases = append(encoded.Cases, encodeCase(subject))
	}
	return encoded
}

// An undeclared severity, status or expectation is refused rather than read as
// the zero one: a rule arriving from a build that knows a value this one does
// not must not quietly become a draft that nothing runs.
func decodeRule(encoded *rulesetv1.Rule) (detection.Rule, []detection.Case, error) {
	if encoded == nil {
		return detection.Rule{}, nil, errors.New("a ruleset holds rules and one of them is nothing")
	}

	severity, declared := written[encoded.GetSeverity()]
	if !declared {
		return detection.Rule{}, nil, fmt.Errorf("rule %q carries a severity this build does not declare", encoded.GetId())
	}
	status, known := standing[encoded.GetStatus()]
	if !known {
		return detection.Rule{}, nil, fmt.Errorf("rule %q carries a status this build does not declare", encoded.GetId())
	}
	match, err := decodeExpression(encoded.GetMatch())
	if err != nil {
		return detection.Rule{}, nil, fmt.Errorf("rule %q: %w", encoded.GetId(), err)
	}

	rule := detection.Rule{
		ID:          detection.ID(encoded.GetId()),
		Revision:    int(encoded.GetRevision()),
		Name:        encoded.GetName(),
		Description: encoded.GetDescription(),
		Class:       encoded.GetEventClass(),
		Match:       match,
		Severity:    severity,
		Status:      status,
		Technique: detection.Technique{
			Tactic: encoded.GetTechnique().GetTactic(),
			ID:     encoded.GetTechnique().GetId(),
			Name:   encoded.GetTechnique().GetName(),
		},
		FalsePositives: encoded.GetFalsePositives(),
		Response:       encoded.GetResponse(),
		Source: detection.Source{
			Catalogue:  encoded.GetSource().GetCatalogue(),
			Identifier: encoded.GetSource().GetIdentifier(),
		},
		Tags:       slices.Clone(encoded.GetTags()),
		References: slices.Clone(encoded.GetReferences()),
		Count:      decodeCount(encoded.GetCount()),
	}

	cases := make([]detection.Case, 0, len(encoded.GetCases()))
	for _, subject := range encoded.GetCases() {
		read, err := decodeCase(subject)
		if err != nil {
			return detection.Rule{}, nil, fmt.Errorf("rule %q: %w", encoded.GetId(), err)
		}
		cases = append(cases, read)
	}
	return rule, cases, nil
}

// A rule that counts must arrive counting. Dropping it would publish a rule
// that decides one event at a time under the name of one that decides on
// twenty, which is a different rule running under an unchanged revision.
func decodeCount(encoded *rulesetv1.Count) detection.Count {
	if encoded == nil {
		return detection.Count{}
	}

	count := detection.Count{
		AtLeast: int(encoded.GetAtLeast()),
		Within:  encoded.GetWithin().AsDuration(),
	}
	for _, field := range encoded.GetGroupBy() {
		count.GroupBy = append(count.GroupBy, detection.Field(field))
	}
	return count
}

func encodeExpression(expression detection.Expression) *rulesetv1.Expression {
	switch term := expression.(type) {
	case detection.Predicate:
		values := make([]*rulesetv1.Value, 0, len(term.Values))
		for _, value := range term.Values {
			values = append(values, encodeValue(value))
		}
		return &rulesetv1.Expression{Term: &rulesetv1.Expression_Predicate{Predicate: &rulesetv1.Predicate{
			Field:    string(term.Field),
			Operator: string(term.Operator),
			Values:   values,
		}}}
	case detection.All:
		return &rulesetv1.Expression{Term: &rulesetv1.Expression_All{All: encodeTerms(term.Terms)}}
	case detection.Any:
		return &rulesetv1.Expression{Term: &rulesetv1.Expression_Any{Any: encodeTerms(term.Terms)}}
	case detection.Not:
		return &rulesetv1.Expression{Term: &rulesetv1.Expression_Negated{Negated: encodeExpression(term.Term)}}
	default:
		return nil
	}
}

func encodeTerms(terms []detection.Expression) *rulesetv1.Terms {
	held := &rulesetv1.Terms{Terms: make([]*rulesetv1.Expression, 0, len(terms))}
	for _, term := range terms {
		held.Terms = append(held.Terms, encodeExpression(term))
	}
	return held
}

func decodeExpression(encoded *rulesetv1.Expression) (detection.Expression, error) {
	switch term := encoded.GetTerm().(type) {
	case *rulesetv1.Expression_Predicate:
		values := make([]detection.Value, 0, len(term.Predicate.GetValues()))
		for _, value := range term.Predicate.GetValues() {
			read, err := decodeValue(value)
			if err != nil {
				return nil, err
			}
			values = append(values, read)
		}
		return detection.Predicate{
			Field:    detection.Field(term.Predicate.GetField()),
			Operator: detection.Operator(term.Predicate.GetOperator()),
			Values:   values,
		}, nil
	case *rulesetv1.Expression_All:
		terms, err := decodeTerms(term.All.GetTerms())
		if err != nil {
			return nil, err
		}
		return detection.All{Terms: terms}, nil
	case *rulesetv1.Expression_Any:
		terms, err := decodeTerms(term.Any.GetTerms())
		if err != nil {
			return nil, err
		}
		return detection.Any{Terms: terms}, nil
	case *rulesetv1.Expression_Negated:
		negated, err := decodeExpression(term.Negated)
		if err != nil {
			return nil, err
		}
		return detection.Not{Term: negated}, nil
	default:
		return nil, errors.New("an expression carries no term this build can read")
	}
}

func decodeTerms(encoded []*rulesetv1.Expression) ([]detection.Expression, error) {
	terms := make([]detection.Expression, 0, len(encoded))
	for _, term := range encoded {
		read, err := decodeExpression(term)
		if err != nil {
			return nil, err
		}
		terms = append(terms, read)
	}
	return terms, nil
}

func encodeValue(value detection.Value) *rulesetv1.Value {
	switch value.Kind() {
	case detection.Number:
		return &rulesetv1.Value{Literal: &rulesetv1.Value_Number{Number: value.Number()}}
	case detection.Truth:
		return &rulesetv1.Value{Literal: &rulesetv1.Value_Truth{Truth: value.Truth()}}
	default:
		return &rulesetv1.Value{Literal: &rulesetv1.Value_Text{Text: value.Text()}}
	}
}

func decodeValue(encoded *rulesetv1.Value) (detection.Value, error) {
	switch literal := encoded.GetLiteral().(type) {
	case *rulesetv1.Value_Text:
		return detection.TextValue(literal.Text), nil
	case *rulesetv1.Value_Number:
		return detection.NumberValue(literal.Number), nil
	case *rulesetv1.Value_Truth:
		return detection.TruthValue(literal.Truth), nil
	default:
		return detection.Value{}, errors.New("a literal carries no value this build can read")
	}
}

func encodeCase(subject detection.Case) *rulesetv1.Case {
	encoded := &rulesetv1.Case{
		Name:        subject.Name,
		Description: subject.Description,
		Expect:      expectations[subject.Expect],
		Event:       make(map[string]*rulesetv1.Value, len(subject.Event)),
		Severity:    severities[subject.Severity],
	}
	for field, value := range subject.Event {
		encoded.Event[string(field)] = encodeValue(value)
	}
	for _, field := range subject.Evidence {
		encoded.Evidence = append(encoded.Evidence, string(field))
	}
	return encoded
}

// A case may leave the severity unset, which asks nothing about it; a rule may
// not, which is why only this side reads an unspecified severity as a value.
func decodeCase(encoded *rulesetv1.Case) (detection.Case, error) {
	expectation, declared := expectingOf[encoded.GetExpect()]
	if !declared {
		return detection.Case{}, fmt.Errorf("case %q expects something this build does not declare", encoded.GetName())
	}

	subject := detection.Case{
		Name:        encoded.GetName(),
		Description: encoded.GetDescription(),
		Expect:      expectation,
		Event:       make(map[detection.Field]detection.Value, len(encoded.GetEvent())),
	}
	if encoded.GetSeverity() != detectionv1.Severity_SEVERITY_UNSPECIFIED {
		severity, known := written[encoded.GetSeverity()]
		if !known {
			return detection.Case{}, fmt.Errorf("case %q carries a severity this build does not declare", encoded.GetName())
		}
		subject.Severity = severity
	}

	for field, value := range encoded.GetEvent() {
		read, err := decodeValue(value)
		if err != nil {
			return detection.Case{}, fmt.Errorf("case %q: %w", encoded.GetName(), err)
		}
		subject.Event[detection.Field(field)] = read
	}
	for _, field := range encoded.GetEvidence() {
		subject.Evidence = append(subject.Evidence, detection.Field(field))
	}
	return subject, nil
}

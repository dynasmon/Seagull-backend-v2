package detection

import (
	"fmt"
	"regexp"
	"strings"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Bounds are part of what a rule is, the way `internal/event` declares what an
// event may carry. A rule is written by a person and read by a machine on every
// event, so both ends need a ceiling.
const (
	MaxIDLength          = 120
	MaxNameLength        = 200
	MaxDescriptionLength = 2000
	MaxGuidanceLength    = 2000
	MaxValues            = 4096
	MaxDepth             = 16
)

var (
	identifier = regexp.MustCompile(`^[a-z][a-z0-9]*([._][a-z0-9]+)*$`)
	versioned  = regexp.MustCompile(`[._]v\d+$`)
	technique  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

// What is wrong with a rule, naming the part of the rule that is wrong so the
// author can find it without reading the whole thing back.
type Violation struct {
	Rule   ID
	Part   string
	Reason string
}

func (v *Violation) Error() string {
	if v.Rule == "" {
		return fmt.Sprintf("%s %s", v.Part, v.Reason)
	}
	return fmt.Sprintf("rule %q: %s %s", v.Rule, v.Part, v.Reason)
}

// Whether the platform can run this rule at all. Everything here is decided
// from the rule and the contract, with nothing loaded and nothing running, so a
// rule is refused where it is written rather than on the event that would have
// tripped over it.
func (r Rule) Validate() error {
	if !identifier.MatchString(string(r.ID)) || len(r.ID) > MaxIDLength {
		return r.violation("id", fmt.Sprintf("must be lowercase words joined by . or _, up to %d characters", MaxIDLength))
	}
	if versioned.MatchString(string(r.ID)) {
		return r.violation("id", "ends in a version: the revision carries that, and an id that moves with it cannot say that two rules are the same rule")
	}
	if r.Revision < 1 {
		return r.violation("revision", "must be at least 1, and must go up when the rule changes")
	}
	if err := r.text("name", r.Name, MaxNameLength, true); err != nil {
		return err
	}
	if err := r.text("description", r.Description, MaxDescriptionLength, true); err != nil {
		return err
	}
	if err := r.text("false_positives", r.FalsePositives, MaxGuidanceLength, false); err != nil {
		return err
	}
	if err := r.text("response", r.Response, MaxGuidanceLength, false); err != nil {
		return err
	}
	if _, declared := severities[r.Severity]; !declared {
		return r.violation("severity", fmt.Sprintf("is %q, which is not one of low, medium, high, critical", r.Severity))
	}
	if _, declared := statuses[r.Status]; !declared {
		return r.violation("status", fmt.Sprintf("is %q, which is not one of draft, active, disabled, deprecated", r.Status))
	}
	if err := r.validateTechnique(); err != nil {
		return err
	}
	if err := r.validateClass(); err != nil {
		return err
	}
	return r.validateExpression("match", r.Match, 0)
}

func (r Rule) validateClass() error {
	if r.Class == eventv1.EventClass_EVENT_CLASS_UNSPECIFIED {
		return r.violation("class", "must name the class of event the rule reads")
	}
	if _, declared := eventv1.EventClass_name[int32(r.Class)]; !declared {
		return r.violation("class", fmt.Sprintf("is %d, which the contract does not declare", r.Class))
	}
	return nil
}

func (r Rule) validateTechnique() error {
	if r.Technique.empty() {
		return nil
	}
	if r.Technique.Tactic == "" || r.Technique.ID == "" || r.Technique.Name == "" {
		return r.violation("technique", "needs a tactic, an id and a name, or none of the three")
	}
	if _, declared := tactics[r.Technique.Tactic]; !declared {
		return r.violation("technique.tactic", fmt.Sprintf("is %q, which is not an ATT&CK enterprise tactic", r.Technique.Tactic))
	}
	if !technique.MatchString(r.Technique.ID) {
		return r.violation("technique.id", fmt.Sprintf("is %q and should read like T1110 or T1110.001", r.Technique.ID))
	}
	return r.text("technique.name", r.Technique.Name, MaxNameLength, true)
}

func (r Rule) validateExpression(part string, expression Expression, depth int) error {
	if expression == nil {
		return r.violation(part, "is missing: a rule that asks nothing matches everything")
	}
	if depth > MaxDepth {
		return r.violation(part, fmt.Sprintf("nests deeper than %d, which is deeper than a rule anybody can read", MaxDepth))
	}

	switch term := expression.(type) {
	case Predicate:
		return r.validatePredicate(part, term)
	case Not:
		return r.validateExpression(part+".not", term.Term, depth+1)
	case All:
		return r.validateTerms(part+".all", term.Terms, depth)
	case Any:
		return r.validateTerms(part+".any", term.Terms, depth)
	default:
		return r.violation(part, fmt.Sprintf("is a %T, which is not part of the rule language", expression))
	}
}

func (r Rule) validateTerms(part string, terms []Expression, depth int) error {
	if len(terms) == 0 {
		return r.violation(part, "has no terms: a rule that asks nothing matches everything")
	}
	for index, term := range terms {
		if err := r.validateExpression(fmt.Sprintf("%s[%d]", part, index), term, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (r Rule) validatePredicate(part string, predicate Predicate) error {
	where := part + "." + string(predicate.Field)

	kind, declared := KindOf(predicate.Field)
	if !declared {
		return r.violation(where, "is not a field the contract declares")
	}
	if !AddressableBy(predicate.Field, r.Class) {
		return r.violation(where, fmt.Sprintf("belongs to another class, so a %s rule would never match it", bodyOf(r.Class)))
	}
	if !predicate.Operator.known() {
		return r.violation(where, fmt.Sprintf("asks %q, which is not an operator", predicate.Operator))
	}
	if !predicate.Operator.asks(kind) {
		return r.violation(where, fmt.Sprintf("holds %s, and %s does not ask that", kind, predicate.Operator))
	}
	return r.validateValues(where, predicate, kind)
}

func (r Rule) validateValues(where string, predicate Predicate, kind Kind) error {
	minimum, maximum := predicate.Operator.takes()
	switch {
	case len(predicate.Values) < minimum:
		return r.violation(where, fmt.Sprintf("gives %s nothing to compare against", predicate.Operator))
	case maximum > 0 && len(predicate.Values) > maximum:
		return r.violation(where, fmt.Sprintf("gives %s %d values and it reads %d", predicate.Operator, len(predicate.Values), maximum))
	case len(predicate.Values) > MaxValues:
		return r.violation(where, fmt.Sprintf("lists %d values, above the ceiling of %d", len(predicate.Values), MaxValues))
	}

	for _, value := range predicate.Values {
		if !value.fits(kind) {
			return r.violation(where, fmt.Sprintf("holds %s and is compared against %s", kind, value))
		}
		if value.Kind() == Text && strings.TrimSpace(value.Text()) == "" {
			return r.violation(where, "is compared against nothing, which every event matches")
		}
		if kind == Choice && !names(value.Text(), ChoicesOf(predicate.Field)) {
			return r.violation(where, fmt.Sprintf("is compared against %s, and the contract declares %s",
				value, strings.Join(ChoicesOf(predicate.Field), ", ")))
		}
	}
	return nil
}

func names(value string, choices []string) bool {
	for _, choice := range choices {
		if choice == value {
			return true
		}
	}
	return false
}

func (r Rule) text(part, value string, ceiling int, required bool) error {
	trimmed := strings.TrimSpace(value)
	switch {
	case trimmed == "" && required:
		return r.violation(part, "is missing")
	case len(value) > ceiling:
		return r.violation(part, fmt.Sprintf("is longer than %d characters", ceiling))
	}
	return nil
}

func (r Rule) violation(part, reason string) error {
	return &Violation{Rule: r.ID, Part: part, Reason: reason}
}

package sigma

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

var comparators = map[string]detection.Operator{
	"contains":   detection.Contains,
	"startswith": detection.StartsWith,
	"endswith":   detection.EndsWith,
	"lt":         detection.Below,
	"lte":        detection.AtMost,
	"gt":         detection.Above,
	"gte":        detection.AtLeast,
}

// Every Sigma modifier this build knows of and does not translate, with the
// reason it does not. Named one by one so that a rule using one is told what
// the platform cannot say, rather than being told the modifier is a typo.
var untranslatable = map[string]string{
	"re":           "matches a regular expression, and the rule language has no pattern operator on purpose: a pattern makes evaluation cost something a rule author sets and the platform pays",
	"cidr":         "matches a network range, and the rule language compares text and numbers; the prefix of an address is written as a wildcard",
	"base64":       "compares against an encoding of the value, and a rule here reads the record the platform normalised rather than a re-encoding of it",
	"base64offset": "compares against an encoding of the value, and a rule here reads the record the platform normalised rather than a re-encoding of it",
	"utf16":        "compares against an encoding of the value, and a rule here reads the record the platform normalised rather than a re-encoding of it",
	"utf16le":      "compares against an encoding of the value, and a rule here reads the record the platform normalised rather than a re-encoding of it",
	"utf16be":      "compares against an encoding of the value, and a rule here reads the record the platform normalised rather than a re-encoding of it",
	"wide":         "compares against an encoding of the value, and a rule here reads the record the platform normalised rather than a re-encoding of it",
	"windash":      "expands one value into several spellings of a Windows command line, and this platform carries no command line",
	"expand":       "resolves a placeholder from a backend's own configuration, and nothing here holds one",
	"fieldref":     "compares one field against another, and every question the rule language asks is about one field and a literal",
	"minute":       "reads a part of a timestamp, and time is not addressable by a rule: a window is not a predicate",
	"hour":         "reads a part of a timestamp, and time is not addressable by a rule: a window is not a predicate",
	"day":          "reads a part of a timestamp, and time is not addressable by a rule: a window is not a predicate",
	"week":         "reads a part of a timestamp, and time is not addressable by a rule: a window is not a predicate",
	"month":        "reads a part of a timestamp, and time is not addressable by a rule: a window is not a predicate",
	"year":         "reads a part of a timestamp, and time is not addressable by a rule: a window is not a predicate",
}

type asked struct {
	held     mapped
	kind     detection.Kind
	operator detection.Operator
	cased    bool
	all      bool
	exists   bool
}

func (r *reader) question(part, key string, node *yaml.Node) (detection.Expression, error) {
	name, modifiers, _ := strings.Cut(key, "|")
	held, known := taxonomy[name]
	if !known {
		return nil, r.fault(node, part, fmt.Sprintf("names %q, which this build does not translate: it reads %s", name, fieldsNamed()))
	}
	kind, declared := detection.KindOf(held.field)
	if !declared {
		return nil, r.fault(node, part, fmt.Sprintf("stands for %q, which the contract no longer declares", held.field))
	}

	question := asked{held: held, kind: kind}
	if err := r.modifiers(part, modifiers, node, &question); err != nil {
		return nil, err
	}
	return r.compared(part, question, node)
}

func (r *reader) modifiers(part, written string, node *yaml.Node, question *asked) error {
	if written == "" {
		return nil
	}

	for _, modifier := range strings.Split(written, "|") {
		switch {
		case modifier == "all":
			question.all = true
		case modifier == "cased":
			question.cased = true
		case modifier == "exists":
			question.exists = true
		case comparators[modifier] != "":
			if question.operator != "" {
				return r.fault(node, part, fmt.Sprintf("asks %s and %s at once, and a question asks one thing", question.operator, comparators[modifier]))
			}
			question.operator = comparators[modifier]
		default:
			if reason, named := untranslatable[modifier]; named {
				return r.fault(node, part, fmt.Sprintf("is written |%s, which %s", modifier, reason))
			}
			return r.fault(node, part, fmt.Sprintf("is written |%s, which is not a Sigma modifier this build reads", modifier))
		}
	}

	switch {
	case question.exists && (question.all || question.cased || question.operator != ""):
		return r.fault(node, part, "asks whether the field is there and asks something of its value at the same time")
	case question.all && question.operator != "" && question.operator != detection.Contains &&
		question.operator != detection.StartsWith && question.operator != detection.EndsWith:
		return r.fault(node, part, fmt.Sprintf("asks |all of %s, and every value of a field can only hold together for contains, startswith and endswith", question.operator))
	}
	return nil
}

func (r *reader) compared(part string, question asked, node *yaml.Node) (detection.Expression, error) {
	if question.exists {
		return r.presence(part, question, node)
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return detection.Not{Term: detection.Predicate{Field: question.held.field, Operator: detection.Present}}, nil
	}
	if node.Kind == yaml.ScalarNode {
		return r.term(part, question, node)
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, part, "is compared against neither a value nor a list of values")
	}
	if len(node.Content) == 0 {
		return nil, r.fault(node, part, "is compared against an empty list, which no event answers")
	}

	if listed, taken := r.oneOf(part, question, node); taken {
		return listed, nil
	}
	terms := make([]detection.Expression, 0, len(node.Content))
	for index, item := range node.Content {
		term, err := r.term(fmt.Sprintf("%s[%d]", part, index), question, resolve(item))
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	if question.all {
		return detection.All{Terms: terms}, nil
	}
	return detection.Any{Terms: terms}, nil
}

// A list of plain values under a field is one question with many answers rather
// than many questions, which is what the rule language calls `one_of` and what
// the compiler turns into a set.
func (r *reader) oneOf(part string, question asked, node *yaml.Node) (detection.Expression, bool) {
	if question.all || question.operator != "" || question.kind == detection.Truth {
		return nil, false
	}

	values := make([]detection.Value, 0, len(node.Content))
	for _, item := range node.Content {
		item = resolve(item)
		if item == nil || item.Kind != yaml.ScalarNode || item.Tag == "!!null" {
			return nil, false
		}
		term, err := r.term(part, question, item)
		if err != nil {
			return nil, false
		}
		predicate, plain := term.(detection.Predicate)
		if !plain || predicate.Operator != detection.Equals {
			return nil, false
		}
		values = append(values, predicate.Values[0])
	}
	return detection.Predicate{Field: question.held.field, Operator: detection.OneOf, Values: values}, true
}

func (r *reader) presence(part string, question asked, node *yaml.Node) (detection.Expression, error) {
	var there bool
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || node.Decode(&there) != nil {
		return nil, r.fault(node, part, "is written |exists and reads true or false")
	}

	present := detection.Predicate{Field: question.held.field, Operator: detection.Present}
	if there {
		return present, nil
	}
	return detection.Not{Term: present}, nil
}

func (r *reader) term(part string, question asked, node *yaml.Node) (detection.Expression, error) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return nil, r.fault(node, part, "is compared against something that is not a value")
	}
	predicate := detection.Predicate{Field: question.held.field, Operator: question.operator}

	switch question.kind {
	case detection.Number:
		number, err := strconv.ParseFloat(strings.TrimSpace(node.Value), 64)
		if err != nil {
			return nil, r.fault(node, part, fmt.Sprintf("holds a number and is compared against %q", node.Value))
		}
		if predicate.Operator == "" {
			predicate.Operator = detection.Equals
		}
		predicate.Values = []detection.Value{detection.NumberValue(number)}
		return predicate, nil

	case detection.Truth:
		var truth bool
		if node.Tag != "!!bool" || node.Decode(&truth) != nil || question.operator != "" {
			return nil, r.fault(node, part, "holds true or false and is compared against something else")
		}
		return detection.Predicate{Field: question.held.field, Operator: detection.Equals, Values: []detection.Value{detection.TruthValue(truth)}}, nil
	}

	if question.kind == detection.Choice && question.operator != "" {
		return nil, r.fault(node, part, fmt.Sprintf("is one of %s, and %s does not ask that",
			strings.Join(detection.ChoicesOf(question.held.field), ", "), question.operator))
	}
	if question.operator != "" && question.kind != detection.Text && question.kind != detection.Choice {
		return nil, r.fault(node, part, fmt.Sprintf("holds %s, and %s does not ask that", question.kind, question.operator))
	}

	operator, literal, err := r.pattern(part, question, node)
	if err != nil {
		return nil, err
	}
	written, err := r.written(part, question, operator, literal, node)
	if err != nil {
		return nil, err
	}
	return detection.Predicate{Field: question.held.field, Operator: operator, Values: []detection.Value{detection.TextValue(written)}}, nil
}

// A Sigma value may anchor a wildcard at either end, and the rule language says
// each of those three shapes with an operator of its own. Anything else — a
// wildcard in the middle, a single-character `?`, a value that is only a
// wildcard — is refused, because translating it would need a pattern the rule
// language deliberately does not have.
func (r *reader) pattern(part string, question asked, node *yaml.Node) (detection.Operator, string, error) {
	literal, leading, trailing, readable := glob(node.Value)
	switch {
	case !readable:
		return "", "", r.fault(node, part, fmt.Sprintf("is compared against %q, and a wildcard is read only at the start or the end of a value: the rule language has no pattern operator", node.Value))
	case (leading || trailing) && question.operator != "":
		return "", "", r.fault(node, part, fmt.Sprintf("is asked %s of %q, which says how to match twice", question.operator, node.Value))
	case strings.TrimSpace(literal) == "":
		return "", "", r.fault(node, part, fmt.Sprintf("is compared against %q, which every event carrying the field answers", node.Value))
	}

	if question.operator != "" {
		return question.operator, literal, nil
	}
	switch {
	case leading && trailing:
		return detection.Contains, literal, nil
	case leading:
		return detection.EndsWith, literal, nil
	case trailing:
		return detection.StartsWith, literal, nil
	}
	return detection.Equals, literal, nil
}

func (r *reader) written(part string, question asked, operator detection.Operator, literal string, node *yaml.Node) (string, error) {
	if question.kind == detection.Choice {
		if question.cased {
			return "", r.fault(node, part, fmt.Sprintf("is written |cased and is one of %s, which the contract declares and an event does not spell",
				strings.Join(detection.ChoicesOf(question.held.field), ", ")))
		}
		return strings.ToLower(strings.TrimSpace(literal)), nil
	}

	switch question.held.holds {
	case preserved:
		if !question.cased {
			return "", r.fault(node, part, fmt.Sprintf("compares without case, and the canonical form keeps the case of %s on purpose, so a translation of this could only match less than the rule says: write |cased to compare it as this platform stores it", question.held.field))
		}
		return literal, nil

	case canonical:
		if question.cased {
			return "", r.fault(node, part, fmt.Sprintf("is written |cased, and %s is rewritten to one text form for every address, so case is not something an event holds in it", question.held.field))
		}
		if operator != detection.Equals {
			return literal, nil
		}
		return address(literal), nil

	case typed:
		if question.cased {
			return "", r.fault(node, part, fmt.Sprintf("is written |cased, and %s holds %s", question.held.field, question.kind))
		}
		return literal, nil
	}

	if question.cased {
		return "", r.fault(node, part, fmt.Sprintf("is written |cased, and the canonical form folded %s before a rule reads it, so a comparison that kept case could never hold", question.held.field))
	}
	return strings.ToLower(strings.TrimSpace(literal)), nil
}

// The same text form the canonical stage puts an address in, so a rule written
// against `::ffff:10.0.0.5` compares against the `10.0.0.5` the event holds.
// Text that is not an address is left as it arrived, which is what that stage
// does with it too.
func address(literal string) string {
	trimmed := strings.TrimSpace(literal)
	parsed, err := netip.ParseAddr(trimmed)
	if err != nil {
		return trimmed
	}
	return parsed.Unmap().String()
}

func glob(value string) (literal string, leading, trailing, readable bool) {
	var built strings.Builder
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\\':
			if index+1 == len(value) {
				built.WriteByte('\\')
				continue
			}
			index++
			if value[index] != '*' && value[index] != '?' && value[index] != '\\' {
				built.WriteByte('\\')
			}
			built.WriteByte(value[index])
		case '*':
			switch {
			case index == 0:
				leading = true
			case index == len(value)-1:
				trailing = true
			default:
				return "", false, false, false
			}
		case '?':
			return "", false, false, false
		default:
			built.WriteByte(value[index])
		}
	}
	return built.String(), leading, trailing, true
}

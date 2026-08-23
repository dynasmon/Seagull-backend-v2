package rulefile

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// A term is either a question about a field or one of the three ways of putting
// terms together. Which one it is comes from the keys it carries, so a term
// that is neither says so rather than being read as one that asks nothing.
func (r *reader) expression(part string, node *yaml.Node, depth int) (detection.Expression, error) {
	if depth > detection.MaxDepth {
		return nil, r.fault(node, part, fmt.Sprintf("nests deeper than %d, which is deeper than a rule anybody can read", detection.MaxDepth))
	}

	held, refused := fieldsOf(node)
	if refused != "" {
		return nil, r.fault(node, part, refused)
	}
	r.at(part, node)

	switch {
	case held.has("field"):
		return r.predicate(part, &held, depth)
	case held.has("all"):
		terms, err := r.terms(part, &held, "all", depth)
		return detection.All{Terms: terms}, err
	case held.has("any"):
		terms, err := r.terms(part, &held, "any", depth)
		return detection.Any{Terms: terms}, err
	case held.has("not"):
		inner, _ := held.take("not")
		term, err := r.expression(part+".not", inner, depth+1)
		if err != nil {
			return nil, err
		}
		if err := r.alone(part, &held); err != nil {
			return nil, err
		}
		return detection.Not{Term: term}, nil
	}
	return nil, r.fault(node, part, "is neither a question about a field nor one of all, any, not")
}

func (r *reader) terms(part string, held *mapping, name string, depth int) ([]detection.Expression, error) {
	node, _ := held.take(name)
	list := resolve(node)
	joined := part + "." + name
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil, r.fault(held.at(name), joined, "is not a list of terms")
	}

	terms := make([]detection.Expression, 0, len(list.Content))
	for index, item := range list.Content {
		term, err := r.expression(fmt.Sprintf("%s[%d]", joined, index), item, depth+1)
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return terms, r.alone(part, held)
}

func (r *reader) alone(part string, held *mapping) error {
	left := held.rest()
	if len(left) == 0 {
		return nil
	}
	return r.fault(held.key[left[0]], part, fmt.Sprintf("is written beside %s, and a term says one thing", strings.Join(left, " and ")))
}

func (r *reader) predicate(part string, held *mapping, depth int) (detection.Expression, error) {
	name, err := r.words(held, part+".field", "field")
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, r.fault(held.at("field"), part+".field", "is missing")
	}
	where := part + "." + name

	asked := held.rest()
	switch {
	case len(asked) == 0:
		return nil, r.fault(held.node, where, fmt.Sprintf("is asked nothing: write one of %s beside it", operators()))
	case len(asked) > 1:
		return nil, r.fault(held.key[asked[1]], where,
			fmt.Sprintf("is asked %s at once, and a question asks one thing", strings.Join(asked, " and ")))
	}

	operator := detection.Operator(asked[0])
	if !slices.Contains(detection.Operators(), operator) {
		return nil, r.fault(held.key[asked[0]], where,
			fmt.Sprintf("is asked %q, which is not an operator: write one of %s", asked[0], operators()))
	}
	node, _ := held.take(asked[0])
	r.at(where, held.at("field"))

	values, err := r.values(where, operator, node)
	if err != nil {
		return nil, err
	}
	return detection.Predicate{Field: detection.Field(name), Operator: operator, Values: values}, nil
}

func (r *reader) values(where string, operator detection.Operator, node *yaml.Node) ([]detection.Value, error) {
	switch operator {
	case detection.Present:
		var truth bool
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || node.Decode(&truth) != nil || !truth {
			return nil, r.fault(node, where, "is written `present: true`; to ask that a field is not there, put the question under `not`")
		}
		return nil, nil

	case detection.OneOf:
		list := resolve(node)
		if list == nil || list.Kind != yaml.SequenceNode {
			return nil, r.fault(node, where, "reads a list of values")
		}
		values := make([]detection.Value, 0, len(list.Content))
		for index, item := range list.Content {
			value, given := valueOf(item)
			if !given {
				return nil, r.fault(item, fmt.Sprintf("%s[%d]", where, index), "is not text, a number or true and false")
			}
			values = append(values, value)
		}
		return values, nil
	}

	value, given := valueOf(node)
	if !given {
		return nil, r.fault(node, where, "is not text, a number or true and false")
	}
	return []detection.Value{value}, nil
}

// A literal is typed the way the file wrote it: `22` is a number and `"22"` is
// text, so what a rule compares against is what somebody meant to write rather
// than what the field it names happens to hold.
func valueOf(node *yaml.Node) (detection.Value, bool) {
	node = resolve(node)
	if node == nil || node.Kind != yaml.ScalarNode {
		return detection.Value{}, false
	}

	switch node.Tag {
	case "!!str":
		return detection.TextValue(node.Value), true
	case "!!int", "!!float":
		var number float64
		if node.Decode(&number) != nil {
			return detection.Value{}, false
		}
		return detection.NumberValue(number), true
	case "!!bool":
		var truth bool
		if node.Decode(&truth) != nil {
			return detection.Value{}, false
		}
		return detection.TruthValue(truth), true
	}
	return detection.Value{}, false
}

func operators() string {
	written := make([]string, 0, len(detection.Operators()))
	for _, operator := range detection.Operators() {
		written = append(written, string(operator))
	}
	return strings.Join(written, ", ")
}

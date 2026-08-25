package rulefile

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// The cases written beside a rule, in the order the file writes them.
//
// A case is held to the rule it is written under as it is read, so a fixture
// naming a field the rule's class cannot carry is refused where it was written
// rather than passing later by describing an event nobody meant.
func (r *reader) cases(held *mapping, subject detection.Rule) ([]detection.Case, error) {
	node, given := held.take("tests")
	if !given {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, "tests", "is not a list of cases")
	}
	if len(node.Content) > detection.MaxCases {
		return nil, r.fault(node, "tests",
			fmt.Sprintf("holds %d cases, above the ceiling of %d", len(node.Content), detection.MaxCases))
	}

	named := make(map[string]struct{}, len(node.Content))
	cases := make([]detection.Case, 0, len(node.Content))
	for index, item := range node.Content {
		part := fmt.Sprintf("tests[%d]", index)
		r.at(part, item)

		written, err := r.oneCase(part, item)
		if err != nil {
			return nil, err
		}
		if _, twice := named[written.Name]; twice {
			return nil, r.fault(item, part+".name",
				fmt.Sprintf("is %q, which another case already is, and a failure names the case", written.Name))
		}
		if err := subject.Accepts(part, written); err != nil {
			return nil, r.refused(item, err)
		}

		named[written.Name] = struct{}{}
		cases = append(cases, written)
	}
	return cases, nil
}

func (r *reader) oneCase(part string, node *yaml.Node) (detection.Case, error) {
	held, refused := fieldsOf(node)
	if refused != "" {
		return detection.Case{}, r.fault(node, part, "a case "+refused)
	}
	for _, name := range []string{"name", "description", "expect", "severity", "evidence", "event"} {
		r.at(part+"."+name, held.at(name))
	}

	var written detection.Case
	var err error
	if written.Name, err = r.words(&held, part+".name", "name"); err != nil {
		return written, err
	}
	if written.Description, err = r.words(&held, part+".description", "description"); err != nil {
		return written, err
	}

	expect, err := r.words(&held, part+".expect", "expect")
	if err != nil {
		return written, err
	}
	written.Expect = detection.Expectation(expect)

	severity, err := r.words(&held, part+".severity", "severity")
	if err != nil {
		return written, err
	}
	written.Severity = detection.Severity(severity)

	evidence, err := r.list(&held, part+".evidence", "evidence")
	if err != nil {
		return written, err
	}
	for _, field := range evidence {
		written.Evidence = append(written.Evidence, detection.Field(field))
	}

	if written.Event, err = r.carried(part, &held); err != nil {
		return written, err
	}
	if left := held.rest(); len(left) > 0 {
		return written, r.fault(held.key[left[0]], part+"."+left[0], "is not part of a case")
	}
	return written, nil
}

// The event a case describes, written as the fields it carries: a field the case
// does not name is one the event does not have, which is how a case says that
// something is absent.
func (r *reader) carried(part string, held *mapping) (map[detection.Field]detection.Value, error) {
	node, given := held.take("event")
	if !given {
		return nil, nil
	}

	fields, refused := fieldsOf(node)
	if refused != "" {
		return nil, r.fault(node, part+".event", "an event "+refused)
	}

	carried := make(map[detection.Field]detection.Value, len(fields.order))
	for _, name := range fields.order {
		where := part + ".event." + name
		r.at(where, fields.at(name))

		value, given := valueOf(fields.value[name])
		if !given {
			return nil, r.fault(fields.at(name), where, "is not text, a number or true and false")
		}
		carried[detection.Field(name)] = value
	}
	return carried, nil
}

package sigma

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// One named part of a Sigma detection. A map is every question in it holding at
// once; a list of maps is any one of them holding. A list of bare values is a
// keyword search over a whole record, which is refused: a rule here asks about
// named fields, and a keyword translated into a search of the collected line
// would be a different rule wearing the same title.
func (r *reader) selection(part string, node *yaml.Node) (detection.Expression, error) {
	node = resolve(node)
	if node == nil {
		return nil, r.fault(nil, part, "is written with nothing under it")
	}

	switch node.Kind {
	case yaml.MappingNode:
		return r.questions(part, node)

	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return nil, r.fault(node, part, "is an empty list, so it says nothing about an event")
		}
		terms := make([]detection.Expression, 0, len(node.Content))
		for index, item := range node.Content {
			item = resolve(item)
			if item == nil || item.Kind != yaml.MappingNode {
				return nil, r.fault(item, fmt.Sprintf("%s[%d]", part, index),
					"is a value rather than a map of fields: a keyword searches a whole record, and a rule here asks about named fields")
			}
			term, err := r.questions(fmt.Sprintf("%s[%d]", part, index), item)
			if err != nil {
				return nil, err
			}
			terms = append(terms, term)
		}
		return detection.Any{Terms: terms}, nil
	}
	return nil, r.fault(node, part, "is neither a map of fields nor a list of them")
}

func (r *reader) questions(part string, node *yaml.Node) (detection.Expression, error) {
	held, refused := fieldsOf(node)
	if refused != "" {
		return nil, r.fault(node, part, refused)
	}
	if len(held.order) == 0 {
		return nil, r.fault(node, part, "asks nothing of an event")
	}

	terms := make([]detection.Expression, 0, len(held.order))
	for _, key := range held.order {
		where := part + "." + key
		value, given := held.take(key)
		if !given {
			value = held.at(key)
		}
		term, err := r.question(where, key, value)
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return detection.All{Terms: terms}, nil
}

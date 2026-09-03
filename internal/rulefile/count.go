package rulefile

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// The count a rule was written with, if it was written with one. What a count
// means is the domain's to decide, so this reads a shape and hands over three
// values: how many, inside how long, and grouped by what.
func (r *reader) count(held *mapping) (detection.Count, error) {
	node, given := held.take("count")
	if !given {
		return detection.Count{}, nil
	}

	counted, refused := fieldsOf(node)
	if refused != "" {
		return detection.Count{}, r.fault(node, "count", refused)
	}
	for _, part := range []string{"at_least", "within", "group_by"} {
		r.at("count."+part, counted.at(part))
	}

	var count detection.Count
	var err error
	if count.AtLeast, err = r.whole(&counted, "count.at_least", "at_least"); err != nil {
		return count, err
	}
	if count.Within, err = r.window(&counted, "count.within", "within"); err != nil {
		return count, err
	}
	if count.GroupBy, err = r.grouping(&counted, "count.group_by", "group_by"); err != nil {
		return count, err
	}

	if left := counted.rest(); len(left) > 0 {
		return count, r.fault(counted.key[left[0]], "count."+left[0], "is not part of a count")
	}
	return count, nil
}

func (r *reader) window(held *mapping, part, name string) (time.Duration, error) {
	node, given := held.take(name)
	if !given {
		return 0, nil
	}
	if node.Kind != yaml.ScalarNode {
		return 0, r.fault(node, part, "is not a window")
	}

	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return 0, r.fault(node, part, fmt.Sprintf("is %q, and a window reads like 60s, 5m or 2h", node.Value))
	}
	return parsed, nil
}

// Each field is remembered where it was written, so a domain refusal naming
// `count.group_by[1]` points at the second field rather than at the list.
func (r *reader) grouping(held *mapping, part, name string) ([]detection.Field, error) {
	node, given := held.take(name)
	if !given {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, part, "is not a list of fields")
	}

	grouped := make([]detection.Field, 0, len(node.Content))
	for index, item := range node.Content {
		where := fmt.Sprintf("%s[%d]", part, index)
		value := resolve(item)
		if value == nil || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return nil, r.fault(item, where, "is not the name of a field")
		}
		r.at(where, value)
		grouped = append(grouped, detection.Field(value.Value))
	}
	return grouped, nil
}

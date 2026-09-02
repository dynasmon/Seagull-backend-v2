package rulefile

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// The sequence a rule was written with, if it was written with one. What a
// sequence means is the domain's to decide, so this reads a shape and hands over
// three things: the stages in the order they were written, the window they must
// fit inside, and what makes two events part of the same story.
func (r *reader) sequence(held *mapping) (detection.Sequence, error) {
	node, given := held.take("sequence")
	if !given {
		return detection.Sequence{}, nil
	}

	ordered, refused := fieldsOf(node)
	if refused != "" {
		return detection.Sequence{}, r.fault(node, "sequence", refused)
	}
	for _, part := range []string{"stages", "within", "group_by"} {
		r.at("sequence."+part, ordered.at(part))
	}

	var sequence detection.Sequence
	var err error
	if sequence.Stages, err = r.stages(&ordered); err != nil {
		return sequence, err
	}
	if sequence.Within, err = r.window(&ordered, "sequence.within", "within"); err != nil {
		return sequence, err
	}
	if sequence.GroupBy, err = r.grouping(&ordered, "sequence.group_by", "group_by"); err != nil {
		return sequence, err
	}

	if left := ordered.rest(); len(left) > 0 {
		return sequence, r.fault(ordered.key[left[0]], "sequence."+left[0], "is not part of a sequence")
	}
	return sequence, nil
}

// Each stage is remembered where it was written, so a domain refusal naming
// `sequence.stages[1].match` points at the second stage rather than at the list.
func (r *reader) stages(ordered *mapping) ([]detection.Stage, error) {
	node, given := ordered.take("stages")
	if !given {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, "sequence.stages", "is not a list of stages")
	}

	stages := make([]detection.Stage, 0, len(node.Content))
	for index, item := range node.Content {
		where := fmt.Sprintf("sequence.stages[%d]", index)
		r.at(where, item)

		held, refused := fieldsOf(item)
		if refused != "" {
			return nil, r.fault(item, where, "a stage "+refused)
		}
		r.at(where+".name", held.at("name"))
		r.at(where+".match", held.at("match"))

		name, err := r.words(&held, where+".name", "name")
		if err != nil {
			return nil, err
		}
		stage := detection.Stage{Name: name}

		if match, written := held.take("match"); written {
			if stage.Match, err = r.expression(where+".match", match, 0); err != nil {
				return nil, err
			}
		}
		if left := held.rest(); len(left) > 0 {
			return nil, r.fault(held.key[left[0]], where+"."+left[0], "is not part of a stage")
		}
		stages = append(stages, stage)
	}
	return stages, nil
}

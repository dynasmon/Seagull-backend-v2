package rulefile

import (
	"fmt"
	"math"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// Rules as a file writes them, which is what a translation from another rule
// language produces: a document somebody reads, edits and writes the cases for
// before an estate ships it. The cases are not written here, because a rule
// arriving from outside has none and the reviewer is the one who decides what
// it should find.
func Write(rules []detection.Rule) ([]byte, error) {
	written := document{SchemaVersion: SchemaVersion, Rules: make([]rule, 0, len(rules))}
	for _, subject := range rules {
		one, err := writable(subject)
		if err != nil {
			return nil, err
		}
		written.Rules = append(written.Rules, one)
	}
	return yaml.Marshal(written)
}

type document struct {
	SchemaVersion int    `yaml:"schema_version"`
	Rules         []rule `yaml:"rules"`
}

type rule struct {
	ID             string     `yaml:"id"`
	Revision       int        `yaml:"revision"`
	Name           string     `yaml:"name"`
	Description    string     `yaml:"description,omitempty"`
	Class          string     `yaml:"class"`
	Severity       string     `yaml:"severity"`
	Status         string     `yaml:"status"`
	Technique      *technique `yaml:"technique,omitempty"`
	FalsePositives string     `yaml:"false_positives,omitempty"`
	Response       string     `yaml:"response,omitempty"`
	Source         *source    `yaml:"source,omitempty"`
	Tags           []string   `yaml:"tags,omitempty"`
	References     []string   `yaml:"references,omitempty"`
	Count          *count     `yaml:"count,omitempty"`
	Sequence       *sequence  `yaml:"sequence,omitempty"`
	Match          *yaml.Node `yaml:"match,omitempty"`
}

type technique struct {
	Tactic string `yaml:"tactic"`
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
}

type source struct {
	Catalogue  string `yaml:"catalogue"`
	Identifier string `yaml:"identifier"`
}

type count struct {
	AtLeast int      `yaml:"at_least"`
	Within  string   `yaml:"within"`
	GroupBy []string `yaml:"group_by,omitempty"`
}

type sequence struct {
	Within  string   `yaml:"within"`
	GroupBy []string `yaml:"group_by,omitempty"`
	Stages  []stage  `yaml:"stages"`
}

type stage struct {
	Name  string     `yaml:"name"`
	Match *yaml.Node `yaml:"match"`
}

func writable(subject detection.Rule) (rule, error) {
	written := rule{
		ID:             string(subject.ID),
		Revision:       subject.Revision,
		Name:           subject.Name,
		Description:    subject.Description,
		Class:          detection.ClassName(subject.Class),
		Severity:       string(subject.Severity),
		Status:         string(subject.Status),
		FalsePositives: subject.FalsePositives,
		Response:       subject.Response,
		Tags:           subject.Tags,
		References:     subject.References,
	}

	if subject.Technique != (detection.Technique{}) {
		written.Technique = &technique{Tactic: subject.Technique.Tactic, ID: subject.Technique.ID, Name: subject.Technique.Name}
	}
	if subject.Source != (detection.Source{}) {
		written.Source = &source{Catalogue: subject.Source.Catalogue, Identifier: subject.Source.Identifier}
	}
	if subject.Count.Counts() {
		written.Count = &count{AtLeast: subject.Count.AtLeast, Within: subject.Count.Within.String(), GroupBy: grouping(subject.Count.GroupBy)}
	}
	if subject.Sequence.Correlates() {
		ordered, err := staged(subject.Sequence)
		if err != nil {
			return written, err
		}
		written.Sequence = ordered
		return written, nil
	}

	match, err := expressionNode(subject.Match)
	if err != nil {
		return written, err
	}
	written.Match = match
	return written, nil
}

func staged(ordered detection.Sequence) (*sequence, error) {
	written := &sequence{Within: ordered.Within.String(), GroupBy: grouping(ordered.GroupBy), Stages: make([]stage, 0, len(ordered.Stages))}
	for _, part := range ordered.Stages {
		match, err := expressionNode(part.Match)
		if err != nil {
			return nil, err
		}
		written.Stages = append(written.Stages, stage{Name: part.Name, Match: match})
	}
	return written, nil
}

func grouping(fields []detection.Field) []string {
	if len(fields) == 0 {
		return nil
	}

	grouped := make([]string, 0, len(fields))
	for _, field := range fields {
		grouped = append(grouped, string(field))
	}
	return grouped
}

func expressionNode(expression detection.Expression) (*yaml.Node, error) {
	switch term := expression.(type) {
	case detection.Predicate:
		return predicateNode(term)
	case detection.All:
		terms, err := termNodes(term.Terms)
		if err != nil {
			return nil, err
		}
		return mappingNode("all", terms), nil
	case detection.Any:
		terms, err := termNodes(term.Terms)
		if err != nil {
			return nil, err
		}
		return mappingNode("any", terms), nil
	case detection.Not:
		inner, err := expressionNode(term.Term)
		if err != nil {
			return nil, err
		}
		return mappingNode("not", inner), nil
	}
	return nil, fmt.Errorf("a %T is not part of the rule language", expression)
}

func termNodes(terms []detection.Expression) (*yaml.Node, error) {
	listed := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, term := range terms {
		node, err := expressionNode(term)
		if err != nil {
			return nil, err
		}
		listed.Content = append(listed.Content, node)
	}
	return listed, nil
}

func predicateNode(predicate detection.Predicate) (*yaml.Node, error) {
	node := mappingNode("field", scalarNode(detection.TextValue(string(predicate.Field))))

	switch predicate.Operator {
	case detection.Present:
		node.Content = append(node.Content, scalarNode(detection.TextValue(string(predicate.Operator))), scalarNode(detection.TruthValue(true)))
		return node, nil

	case detection.OneOf:
		listed := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, value := range predicate.Values {
			listed.Content = append(listed.Content, scalarNode(value))
		}
		node.Content = append(node.Content, scalarNode(detection.TextValue(string(predicate.Operator))), listed)
		return node, nil
	}

	if len(predicate.Values) != 1 {
		return nil, fmt.Errorf("%s asks %s of %d values", predicate.Field, predicate.Operator, len(predicate.Values))
	}
	node.Content = append(node.Content, scalarNode(detection.TextValue(string(predicate.Operator))), scalarNode(predicate.Values[0]))
	return node, nil
}

func mappingNode(name string, value *yaml.Node) *yaml.Node {
	return &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: []*yaml.Node{scalarNode(detection.TextValue(name)), value},
	}
}

// A literal is written back in the type the rule holds it as, so that reading
// the file again gives the same rule: `22` is a number and `"22"` is text, and
// the tag is what keeps them apart through a round trip.
func scalarNode(value detection.Value) *yaml.Node {
	switch value.Kind() {
	case detection.Number:
		if number := value.Number(); number == math.Trunc(number) && math.Abs(number) < 1<<53 {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.FormatInt(int64(number), 10)}
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: strconv.FormatFloat(value.Number(), 'g', -1, 64)}
	case detection.Truth:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(value.Truth())}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value.Text()}
}

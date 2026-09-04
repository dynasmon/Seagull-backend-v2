package sigma

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// A mapping read one key at a time. What is left when the translator has taken
// the keys it knows is what the document says and Sigma-as-supported does not
// have, which is the difference between a construct that is refused and one
// that is quietly dropped.
type mapping struct {
	node  *yaml.Node
	value map[string]*yaml.Node
	key   map[string]*yaml.Node
	order []string
	taken map[string]struct{}
}

func fieldsOf(node *yaml.Node) (mapping, string) {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return mapping{}, "is not a mapping"
	}

	read := mapping{
		node:  node,
		value: make(map[string]*yaml.Node, len(node.Content)/2),
		key:   make(map[string]*yaml.Node, len(node.Content)/2),
		taken: make(map[string]struct{}, len(node.Content)/2),
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		name := node.Content[index].Value
		if _, twice := read.value[name]; twice {
			return mapping{}, fmt.Sprintf("says %s twice", name)
		}
		read.key[name] = node.Content[index]
		read.value[name] = node.Content[index+1]
		read.order = append(read.order, name)
	}
	return read, ""
}

func (m *mapping) take(name string) (*yaml.Node, bool) {
	m.taken[name] = struct{}{}

	node := resolve(m.value[name])
	if node == nil {
		return nil, false
	}
	return node, true
}

func (m *mapping) at(name string) *yaml.Node {
	if value := resolve(m.value[name]); value != nil {
		return value
	}
	if key, written := m.key[name]; written {
		return key
	}
	return m.node
}

func (m *mapping) rest() []string {
	var left []string
	for _, name := range m.order {
		if _, taken := m.taken[name]; !taken {
			left = append(left, name)
		}
	}
	return left
}

// An alias stands for the node it was anchored to. The walk is bounded because
// a document can point an alias at itself, and a reader that followed one would
// never come back.
func resolve(node *yaml.Node) *yaml.Node {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode && depth < detection.MaxDepth; depth++ {
		node = node.Alias
	}
	return node
}

type reader struct {
	source string
	rule   string
}

func (r *reader) fault(node *yaml.Node, part, reason string) error {
	fault := &Fault{Source: r.source, Rule: r.rule, Part: part, Reason: reason}
	if node != nil {
		fault.Line, fault.Column = node.Line, node.Column
	}
	return fault
}

func (r *reader) refused(node *yaml.Node, err error) error {
	var violation *detection.Violation
	if !errors.As(err, &violation) {
		return r.fault(node, "", err.Error())
	}

	fault := &Fault{
		Source: r.source,
		Rule:   r.rule,
		Part:   "the rule this translates into: " + violation.Part,
		Reason: violation.Reason,
		cause:  err,
	}
	if node != nil {
		fault.Line, fault.Column = node.Line, node.Column
	}
	return fault
}

// A Sigma file may hold several documents joined by an `action` key, which is
// how one rule is written as a base and repeated. Nothing here reads that, and
// a second document is refused rather than translated on its own: a repeated
// rule read without its base is a rule that says less than its author wrote.
func documentOf(read *reader, data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, read.fault(nil, "", "is empty")
		}
		return nil, read.fault(nil, "", err.Error())
	}

	var next yaml.Node
	if decoder.Decode(&next) == nil {
		return nil, read.fault(&next, "", "holds more than one document, and this translates one Sigma rule at a time")
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, read.fault(&root, "", "is empty")
	}
	return root.Content[0], nil
}

func (r *reader) words(held *mapping, part, name string) (string, error) {
	node, given := held.take(name)
	if !given {
		return "", nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", r.fault(node, part, "is not text")
	}
	return node.Value, nil
}

// Sigma writes a list of one as either a list or the value on its own, and both
// mean the same thing.
func (r *reader) list(held *mapping, part, name string) ([]string, error) {
	node, given := held.take(name)
	if !given {
		return nil, nil
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		return []string{node.Value}, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, part, "is neither text nor a list of text")
	}

	read := make([]string, 0, len(node.Content))
	for index, item := range node.Content {
		value := resolve(item)
		if value == nil || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return nil, r.fault(item, fmt.Sprintf("%s[%d]", part, index), "is not text")
		}
		read = append(read, value.Value)
	}
	return read, nil
}

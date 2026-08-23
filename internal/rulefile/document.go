package rulefile

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// The version of the file format, which is neither the revision of a rule nor
// the version of the event contract: those say when a detection changed and
// what an event carries, and this says how a file is laid out. A file written
// for a layout this build does not know is refused rather than read as far as
// it happens to fit.
const SchemaVersion = 1

// Where a rule file is wrong and what is wrong with it, in a shape an editor
// and a control plane can both use: the file, the position in it, the rule, the
// part of the rule, and what it would have had to say instead.
type Fault struct {
	Source string
	Line   int
	Column int
	Rule   detection.ID
	Part   string
	Reason string

	cause error
}

func (f *Fault) Error() string {
	written := []string{fmt.Sprintf("%s:%d:%d:", f.Source, f.Line, f.Column)}
	if f.Rule != "" {
		written = append(written, fmt.Sprintf("rule %q:", f.Rule))
	}
	if f.Part != "" {
		written = append(written, f.Part)
	}
	return strings.Join(append(written, f.Reason), " ")
}

// A refusal from the domain keeps its own type underneath, so what refused a
// rule can still be asked about after the file has said where it was written.
func (f *Fault) Unwrap() error { return f.cause }

// A mapping read one key at a time. What is left when a shape has taken the
// keys it knows is what the file says and the shape does not have, which is the
// difference between a typo that is refused and one that is quietly a default.
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

// A key written with nothing after it is the same as a key that is not there,
// so that a rule left half written is refused for what it is missing rather
// than for the shape of the hole.
func (m *mapping) take(name string) (*yaml.Node, bool) {
	m.taken[name] = struct{}{}

	node := resolve(m.value[name])
	if node == nil || node.Tag == "!!null" {
		return nil, false
	}
	return node, true
}

// Whether the file wrote the key at all, which is not whether it wrote
// anything after it.
func (m *mapping) has(name string) bool {
	_, written := m.value[name]
	return written
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

// The keys the shape did not know about, in the order the file wrote them.
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

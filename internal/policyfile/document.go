// Package policyfile reads who may do what out of a YAML document. It decides
// nothing: what it produces is an authz policy, and authz is what refuses.
package policyfile

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

const SchemaVersion = 1

const maxAliasDepth = 8

type Fault struct {
	Source string
	Line   int
	Column int
	Part   string
	Reason string

	cause error
}

func (f *Fault) Error() string {
	written := []string{fmt.Sprintf("%s:%d:%d:", f.Source, f.Line, f.Column)}
	if f.Part != "" {
		written = append(written, f.Part)
	}
	return strings.Join(append(written, f.Reason), " ")
}

func (f *Fault) Unwrap() error { return f.cause }

// Unread keys are refused, not defaulted: `tenant:` for `tenants:` must never
// read as "no tenants".
type mapping struct {
	node  *yaml.Node
	value map[string]*yaml.Node
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
		taken: make(map[string]struct{}, len(node.Content)/2),
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		name := node.Content[index].Value
		if _, twice := read.value[name]; twice {
			return mapping{}, fmt.Sprintf("says %s twice", name)
		}
		read.value[name] = node.Content[index+1]
		read.order = append(read.order, name)
	}
	return read, ""
}

func (m *mapping) take(name string) (*yaml.Node, bool) {
	m.taken[name] = struct{}{}

	node := resolve(m.value[name])
	if node == nil || node.Tag == "!!null" {
		return nil, false
	}
	return node, true
}

func (m *mapping) unread() []string {
	var left []string
	for _, name := range m.order {
		if _, asked := m.taken[name]; !asked {
			left = append(left, name)
		}
	}
	return left
}

func (m *mapping) at(name string) *yaml.Node {
	if node := m.value[name]; node != nil {
		return node
	}
	return m.node
}

func resolve(node *yaml.Node) *yaml.Node {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode && depth < maxAliasDepth; depth++ {
		node = node.Alias
	}
	return node
}

type reader struct {
	source string
}

func (r *reader) fault(node *yaml.Node, part, reason string) *Fault {
	fault := &Fault{Source: r.source, Part: part, Reason: reason}
	if node != nil {
		fault.Line, fault.Column = node.Line, node.Column
	}
	return fault
}

func (r *reader) refused(node *yaml.Node, part string, err error) *Fault {
	fault := r.fault(node, part, err.Error())
	fault.cause = err
	return fault
}

func (r *reader) strings(node *yaml.Node, part string) ([]string, error) {
	node = resolve(node)
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, part, "is not a list")
	}

	values := make([]string, 0, len(node.Content))
	for index, item := range node.Content {
		item = resolve(item)
		if item == nil || item.Kind != yaml.ScalarNode {
			return nil, r.fault(item, fmt.Sprintf("%s[%d]", part, index), "is not a name")
		}
		values = append(values, item.Value)
	}
	return values, nil
}

func (r *reader) scalar(held *mapping, part, name string) (string, error) {
	node, given := held.take(name)
	if !given {
		return "", r.fault(held.at(name), part+"."+name, "is missing")
	}
	if node.Kind != yaml.ScalarNode {
		return "", r.fault(node, part+"."+name, "is not a value")
	}
	return node.Value, nil
}

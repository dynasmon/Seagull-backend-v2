package rulefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// A rule as a file holds it: what runs, the cases written beside it, and the
// file both came out of. A process only needs the first; a harness and a
// control plane need all three.
type Written struct {
	Program *detection.Program
	Cases   []detection.Case
	Source  string
}

// Every rule written under the tree, parsed, validated and compiled, in the
// order the files are named. The filesystem is the caller's to choose, so
// nothing here reaches for a path of its own.
//
// One broken file does not hide the rest: every file is read and every fault
// is reported together. Nothing is returned unless all of it is good, because
// half a ruleset is a detection surface nobody asked for.
func Rules(fsys fs.FS) ([]Written, error) {
	var (
		programs []Written
		faults   []error
		seen     = make(map[detection.ID]string)
	)

	walked := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !written(name) {
			return nil
		}

		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			faults = append(faults, err)
			return nil
		}
		read, err := parse(name, data, seen)
		if err != nil {
			faults = append(faults, err)
			return nil
		}
		programs = append(programs, read...)
		return nil
	})
	if walked != nil {
		return nil, walked
	}
	if len(faults) > 0 {
		return nil, errors.Join(faults...)
	}
	return programs, nil
}

// What a process loads to run rules, which is every rule under the tree and
// nothing about how any of them is checked.
func Read(fsys fs.FS) ([]*detection.Program, error) {
	written, err := Rules(fsys)
	if err != nil {
		return nil, err
	}

	programs := make([]*detection.Program, 0, len(written))
	for _, rule := range written {
		programs = append(programs, rule.Program)
	}
	return programs, nil
}

// One document, named so that a fault can say where it came from.
func Parse(source string, data []byte) ([]Written, error) {
	return parse(source, data, make(map[detection.ID]string))
}

func written(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func parse(source string, data []byte, seen map[detection.ID]string) ([]Written, error) {
	read := &reader{source: source}

	body, err := documentOf(read, data)
	if err != nil || body == nil {
		return nil, err
	}
	held, refused := fieldsOf(body)
	if refused != "" {
		return nil, read.fault(body, "", "a rule file "+refused+" of schema_version and rules")
	}

	if err := version(read, &held); err != nil {
		return nil, err
	}
	list, given := held.take("rules")
	if !given {
		return nil, read.fault(body, "rules", "is missing: a rule file holds the rules it was written for")
	}
	if list.Kind != yaml.SequenceNode {
		return nil, read.fault(list, "rules", "is not a list of rules")
	}
	if left := held.rest(); len(left) > 0 {
		return nil, read.fault(held.key[left[0]], left[0], "is not part of a rule file")
	}

	written := make([]Written, 0, len(list.Content))
	for _, node := range list.Content {
		rule, err := compiled(read, node, seen)
		if err != nil {
			return nil, err
		}
		written = append(written, rule)
	}
	return written, nil
}

func compiled(read *reader, node *yaml.Node, seen map[detection.ID]string) (Written, error) {
	rule, cases, err := read.rule(node)
	if err != nil {
		return Written{}, err
	}

	// A detection names the rule that made it, so two rules under one id would
	// make an alert that cannot be traced back to what decided it.
	if first, twice := seen[rule.ID]; twice {
		return Written{}, read.fault(read.locate("id", node), "id",
			fmt.Sprintf("is also the id of a rule in %s, and a detection names the rule that made it", first))
	}

	program, err := detection.Compile(rule)
	if err != nil {
		return Written{}, read.refused(node, err)
	}
	seen[rule.ID] = read.source
	return Written{Program: program, Cases: cases, Source: read.source}, nil
}

// A file holds one document. A second one after it would be read by nothing and
// noticed by nobody, which is how a rule disappears.
func documentOf(read *reader, data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, read.fault(nil, "", err.Error())
	}

	var next yaml.Node
	if decoder.Decode(&next) == nil {
		return nil, read.fault(&next, "", "holds more than one document, and a rule file holds one")
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil
	}
	return root.Content[0], nil
}

func version(read *reader, held *mapping) error {
	if !held.has("schema_version") {
		return read.fault(held.node, "schema_version", "is missing: a rule file says which layout it was written for")
	}

	declared, err := read.whole(held, "schema_version", "schema_version")
	if err != nil {
		return err
	}
	if declared != SchemaVersion {
		return read.fault(held.at("schema_version"), "schema_version",
			fmt.Sprintf("is %d and this build reads %d", declared, SchemaVersion))
	}
	return nil
}

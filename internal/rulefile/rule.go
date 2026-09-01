package rulefile

import (
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Reads one file, remembering where each part of each rule was written. What a
// rule means is the domain's to decide, so almost nothing here is a judgement:
// this reads a shape, and the refusals it can give are about the shape.
type reader struct {
	source string
	id     detection.ID
	where  map[string]*yaml.Node
}

func (r *reader) fault(node *yaml.Node, part, reason string) error {
	fault := &Fault{Source: r.source, Rule: r.id, Part: part, Reason: reason}
	if node != nil {
		fault.Line, fault.Column = node.Line, node.Column
	}
	return fault
}

// The domain refuses a rule by naming the part that is wrong; this gives that
// name back the line it was written on, and keeps the refusal underneath so
// that what refused the rule can still be asked about.
func (r *reader) refused(fallback *yaml.Node, err error) error {
	var violation *detection.Violation
	if !errors.As(err, &violation) {
		return r.fault(fallback, "", err.Error())
	}

	node := r.locate(violation.Part, fallback)
	fault := &Fault{
		Source: r.source,
		Rule:   violation.Rule,
		Part:   violation.Part,
		Reason: violation.Reason,
		cause:  err,
	}
	if node != nil {
		fault.Line, fault.Column = node.Line, node.Column
	}
	return fault
}

// A part the file never wrote — `match.all[0].authentication.user.name` when
// the file wrote the term and the domain named the field inside it — is found
// by giving up its last segment until something matches.
func (r *reader) locate(part string, fallback *yaml.Node) *yaml.Node {
	for part != "" {
		if node, written := r.where[part]; written {
			return node
		}
		cut := strings.LastIndexAny(part, ".[")
		if cut < 0 {
			break
		}
		part = part[:cut]
	}
	return fallback
}

func (r *reader) at(part string, node *yaml.Node) {
	if _, written := r.where[part]; !written && node != nil {
		r.where[part] = node
	}
}

func (r *reader) rule(node *yaml.Node) (detection.Rule, []detection.Case, error) {
	r.id, r.where = "", make(map[string]*yaml.Node)

	held, refused := fieldsOf(node)
	if refused != "" {
		return detection.Rule{}, nil, r.fault(node, "", "a rule "+refused)
	}

	id, err := r.words(&held, "id", "id")
	if err != nil {
		return detection.Rule{}, nil, err
	}
	r.id = detection.ID(id)

	rule := detection.Rule{ID: r.id}
	for _, part := range []string{"id", "revision", "name", "description", "severity", "status", "class", "source", "tags", "references", "count", "tests"} {
		r.at(part, held.at(part))
	}

	if rule.Revision, err = r.whole(&held, "revision", "revision"); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.Name, err = r.words(&held, "name", "name"); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.Description, err = r.words(&held, "description", "description"); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.FalsePositives, err = r.words(&held, "false_positives", "false_positives"); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.Response, err = r.words(&held, "response", "response"); err != nil {
		return detection.Rule{}, nil, err
	}

	severity, err := r.words(&held, "severity", "severity")
	if err != nil {
		return detection.Rule{}, nil, err
	}
	rule.Severity = detection.Severity(severity)

	status, err := r.words(&held, "status", "status")
	if err != nil {
		return detection.Rule{}, nil, err
	}
	rule.Status = detection.Status(status)

	if rule.Class, err = r.class(&held); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.Technique, err = r.technique(&held); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.Source, err = r.provenance(&held); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.Tags, err = r.list(&held, "tags", "tags"); err != nil {
		return detection.Rule{}, nil, err
	}
	if rule.References, err = r.list(&held, "references", "references"); err != nil {
		return detection.Rule{}, nil, err
	}

	if rule.Count, err = r.count(&held); err != nil {
		return detection.Rule{}, nil, err
	}

	if match, given := held.take("match"); given {
		if rule.Match, err = r.expression("match", match, 0); err != nil {
			return detection.Rule{}, nil, err
		}
	}
	r.at("match", held.at("match"))

	cases, err := r.cases(&held, rule)
	if err != nil {
		return detection.Rule{}, nil, err
	}

	if left := held.rest(); len(left) > 0 {
		return detection.Rule{}, nil, r.fault(held.key[left[0]], left[0], "is not part of a rule")
	}
	return rule, cases, nil
}

func (r *reader) class(held *mapping) (class eventv1.EventClass, err error) {
	name, err := r.words(held, "class", "class")
	if err != nil || name == "" {
		return class, err
	}

	class, declared := detection.ClassNamed(name)
	if !declared {
		return class, r.fault(held.at("class"), "class", fmt.Sprintf("is %q, and a rule is written for one of %s",
			name, strings.Join(detection.Classes(), ", ")))
	}
	return class, nil
}

func (r *reader) technique(held *mapping) (detection.Technique, error) {
	node, given := held.take("technique")
	if !given {
		return detection.Technique{}, nil
	}

	attributed, refused := fieldsOf(node)
	if refused != "" {
		return detection.Technique{}, r.fault(node, "technique", refused)
	}

	var technique detection.Technique
	var err error
	if technique.Tactic, err = r.words(&attributed, "technique.tactic", "tactic"); err != nil {
		return technique, err
	}
	if technique.ID, err = r.words(&attributed, "technique.id", "id"); err != nil {
		return technique, err
	}
	if technique.Name, err = r.words(&attributed, "technique.name", "name"); err != nil {
		return technique, err
	}
	for _, part := range []string{"tactic", "id", "name"} {
		r.at("technique."+part, attributed.at(part))
	}

	if left := attributed.rest(); len(left) > 0 {
		return technique, r.fault(attributed.key[left[0]], "technique."+left[0], "is not part of a technique")
	}
	return technique, nil
}

func (r *reader) provenance(held *mapping) (detection.Source, error) {
	node, given := held.take("source")
	if !given {
		return detection.Source{}, nil
	}

	from, refused := fieldsOf(node)
	if refused != "" {
		return detection.Source{}, r.fault(node, "source", refused)
	}

	var source detection.Source
	var err error
	if source.Catalogue, err = r.words(&from, "source.catalogue", "catalogue"); err != nil {
		return source, err
	}
	if source.Identifier, err = r.words(&from, "source.identifier", "identifier"); err != nil {
		return source, err
	}
	for _, part := range []string{"catalogue", "identifier"} {
		r.at("source."+part, from.at(part))
	}

	if left := from.rest(); len(left) > 0 {
		return source, r.fault(from.key[left[0]], "source."+left[0], "is not part of a source")
	}
	return source, nil
}

// Each item is remembered where it was written, so a domain refusal naming
// `tags[2]` points at the third tag rather than at the list.
func (r *reader) list(held *mapping, part, name string) ([]string, error) {
	node, given := held.take(name)
	if !given {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, part, "is not a list")
	}

	read := make([]string, 0, len(node.Content))
	for index, item := range node.Content {
		where := fmt.Sprintf("%s[%d]", part, index)
		value := resolve(item)
		if value == nil || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return nil, r.fault(item, where, "is not text")
		}
		r.at(where, value)
		read = append(read, value.Value)
	}
	return read, nil
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

func (r *reader) whole(held *mapping, part, name string) (int, error) {
	node, given := held.take(name)
	if !given {
		return 0, nil
	}

	var number int
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" || node.Decode(&number) != nil {
		return 0, r.fault(node, part, "is not a whole number")
	}
	return number, nil
}

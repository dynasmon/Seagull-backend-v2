package alertfile

import (
	"fmt"
	"io/fs"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
)

const (
	MaxBytes        = 1 << 20
	MaxRules        = 4096
	MaxSuppressions = 4096
)

// What an estate gets without writing a document: alerts fold per rule and per
// agent inside a quarter of an hour, and nothing is silenced after being closed.
// A cooldown is opt-in because it is the only one of the three that can keep an
// operator from hearing about activity they have not decided about.
var Defaults = alert.Fold{
	Keyed:    []alert.Part{alert.PartRule, alert.PartAgent},
	Window:   15 * time.Minute,
	Cooldown: 0,
}

// Nothing is returned unless all of it is good: half a tuning is a set of alerts
// somebody silenced by accident.
func Read(source string, data []byte) (*alert.Tuning, error) {
	if len(data) > MaxBytes {
		return nil, &Fault{Source: source, Reason: fmt.Sprintf("is %d bytes, above the ceiling of %d", len(data), MaxBytes)}
	}

	r := &reader{source: source}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, r.fault(nil, "", "is not readable as YAML: "+err.Error())
	}
	if len(document.Content) == 0 {
		return nil, r.fault(nil, "", "is empty")
	}

	held, refused := fieldsOf(document.Content[0])
	if refused != "" {
		return nil, r.fault(document.Content[0], "", "an alerting document "+refused)
	}

	if err := r.version(&held); err != nil {
		return nil, err
	}
	defaults, err := r.defaults(&held)
	if err != nil {
		return nil, err
	}
	byRule, err := r.rules(&held, defaults)
	if err != nil {
		return nil, err
	}
	suppressions, err := r.suppressions(&held)
	if err != nil {
		return nil, err
	}
	if left := held.unread(); len(left) > 0 {
		return nil, r.fault(held.at(left[0]), left[0], "is not part of an alerting document")
	}

	tuning, err := alert.NewTuning(defaults, byRule, suppressions)
	if err != nil {
		return nil, r.refused(held.node, "", err)
	}
	return tuning, nil
}

func Tuning(fsys fs.FS, name string) (*alert.Tuning, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	return Read(name, data)
}

func (r *reader) version(held *mapping) error {
	node, given := held.take("schema_version")
	if !given {
		return r.fault(held.node, "schema_version", "is missing; a document that does not say how it is laid out cannot be read")
	}

	var version int
	if err := node.Decode(&version); err != nil {
		return r.fault(node, "schema_version", "is not a number")
	}
	if version != SchemaVersion {
		return r.fault(node, "schema_version", fmt.Sprintf("is %d and this build reads %d", version, SchemaVersion))
	}
	return nil
}

func (r *reader) defaults(held *mapping) (alert.Fold, error) {
	node, given := held.take("defaults")
	if !given {
		return Defaults, nil
	}
	declared, refused := fieldsOf(node)
	if refused != "" {
		return alert.Fold{}, r.fault(node, "defaults", refused)
	}
	fold, err := r.fold(&declared, "defaults", Defaults)
	if err != nil {
		return alert.Fold{}, err
	}
	if left := declared.unread(); len(left) > 0 {
		return alert.Fold{}, r.fault(declared.at(left[0]), "defaults."+left[0], "is not part of a fold")
	}
	return fold, nil
}

// The mapping is read rather than reopened, so a fold declared beside a rule id
// does not report that id as a key nobody asked for.
func (r *reader) fold(held *mapping, part string, fallback alert.Fold) (alert.Fold, error) {
	fold := fallback
	if keys, given := held.take("key"); given {
		written, err := r.strings(keys, part+".key")
		if err != nil {
			return alert.Fold{}, err
		}
		fold.Keyed = make([]alert.Part, 0, len(written))
		for index, name := range written {
			parsed, err := alert.ParsePart(name)
			if err != nil {
				return alert.Fold{}, r.refused(keys.Content[index], fmt.Sprintf("%s.key[%d]", part, index), err)
			}
			fold.Keyed = append(fold.Keyed, parsed)
		}
	}
	window, err := r.duration(held, part, "window", fold.Window)
	if err != nil {
		return alert.Fold{}, err
	}
	cooldown, err := r.duration(held, part, "cooldown", fold.Cooldown)
	if err != nil {
		return alert.Fold{}, err
	}
	fold.Window, fold.Cooldown = window, cooldown
	return fold, nil
}

func (r *reader) duration(held *mapping, part, name string, fallback time.Duration) (time.Duration, error) {
	node, given := held.take(name)
	if !given {
		return fallback, nil
	}
	if node.Kind != yaml.ScalarNode {
		return 0, r.fault(node, part+"."+name, "is not a duration")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return 0, r.fault(node, part+"."+name, fmt.Sprintf("%q is not a duration", node.Value))
	}
	if parsed < 0 {
		return 0, r.fault(node, part+"."+name, "is negative")
	}
	return parsed, nil
}

func (r *reader) rules(held *mapping, defaults alert.Fold) (map[string]alert.Fold, error) {
	node, given := held.take("rules")
	if !given {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, "rules", "is not a list")
	}
	if len(node.Content) > MaxRules {
		return nil, r.fault(node, "rules", fmt.Sprintf("declares %d folds, above the ceiling of %d", len(node.Content), MaxRules))
	}

	byRule := make(map[string]alert.Fold, len(node.Content))
	for index, item := range node.Content {
		part := fmt.Sprintf("rules[%d]", index)
		entry, refused := fieldsOf(item)
		if refused != "" {
			return nil, r.fault(item, part, refused)
		}

		id, err := r.scalar(&entry, part, "id")
		if err != nil {
			return nil, err
		}
		if _, twice := byRule[id]; twice {
			return nil, r.fault(entry.at("id"), part+".id", fmt.Sprintf("%q is folded twice", id))
		}

		fold, err := r.fold(&entry, part, defaults)
		if err != nil {
			return nil, err
		}
		if left := entry.unread(); len(left) > 0 {
			return nil, r.fault(entry.at(left[0]), part+"."+left[0], "is not part of a fold")
		}
		byRule[id] = fold
	}
	return byRule, nil
}

func (r *reader) suppressions(held *mapping) ([]alert.Suppression, error) {
	node, given := held.take("suppressions")
	if !given {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, r.fault(node, "suppressions", "is not a list")
	}
	if len(node.Content) > MaxSuppressions {
		return nil, r.fault(node, "suppressions", fmt.Sprintf("declares %d, above the ceiling of %d", len(node.Content), MaxSuppressions))
	}

	suppressions := make([]alert.Suppression, 0, len(node.Content))
	for index, item := range node.Content {
		part := fmt.Sprintf("suppressions[%d]", index)
		entry, refused := fieldsOf(item)
		if refused != "" {
			return nil, r.fault(item, part, refused)
		}

		suppression := alert.Suppression{}
		if rule, given := entry.take("rule"); given {
			if rule.Kind != yaml.ScalarNode {
				return nil, r.fault(rule, part+".rule", "is not a rule id")
			}
			suppression.Rule = rule.Value
		}
		reason, err := r.scalar(&entry, part, "reason")
		if err != nil {
			return nil, err
		}
		suppression.Reason = reason

		if until, given := entry.take("until"); given {
			parsed, err := time.Parse(time.RFC3339, until.Value)
			if err != nil {
				return nil, r.fault(until, part+".until", fmt.Sprintf("%q is not an RFC 3339 instant", until.Value))
			}
			suppression.Until = parsed.UTC()
		}
		if when, given := entry.take("when"); given {
			selector, err := r.selector(when, part+".when")
			if err != nil {
				return nil, err
			}
			suppression.When = selector
		}

		if left := entry.unread(); len(left) > 0 {
			return nil, r.fault(entry.at(left[0]), part+"."+left[0], "is not part of a suppression")
		}
		suppressions = append(suppressions, suppression)
	}
	return suppressions, nil
}

func (r *reader) selector(node *yaml.Node, part string) (alert.Selector, error) {
	held, refused := fieldsOf(node)
	if refused != "" {
		return nil, r.fault(node, part, refused)
	}

	selector := make(alert.Selector, len(held.order))
	for _, name := range held.order {
		which, err := alert.ParsePart(name)
		if err != nil {
			return nil, r.refused(held.at(name), part+"."+name, err)
		}
		values, given := held.take(name)
		if !given {
			return nil, r.fault(held.at(name), part+"."+name, "names no value")
		}
		written, err := r.strings(values, part+"."+name)
		if err != nil {
			return nil, err
		}
		if len(written) == 0 {
			return nil, r.fault(values, part+"."+name, "is an empty list, which matches nothing")
		}
		selector[which] = written
	}
	if len(selector) == 0 {
		return nil, r.fault(node, part, "selects nothing")
	}
	return selector, nil
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

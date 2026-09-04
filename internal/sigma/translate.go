package sigma

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The name a translated rule says it came from, so a detection can be traced
// past the rule to the Sigma rule it was made from.
const Catalogue = "sigma"

var levels = map[string]detection.Severity{
	"informational": detection.Low,
	"low":           detection.Low,
	"medium":        detection.Medium,
	"high":          detection.High,
	"critical":      detection.Critical,
}

var understood = []string{"title", "id", "status", "description", "references", "tags", "logsource", "detection", "falsepositives", "level"}

var ignored = []string{"author", "date", "modified", "license", "name", "related", "fields", "scope", "taxonomy"}

var beyond = map[string]string{
	"correlation": "is a Sigma correlation, which is a document naming other rules by their own names; this translates one rule at a time",
	"action":      "joins several documents into one rule, and a repeated rule read without the one it repeats says less than its author wrote",
	"filter":      "is a Sigma filter, which suppresses another rule rather than detecting anything: what this platform removes from an alert is tuning, and it is written where alerts are tuned",
}

// One Sigma document, translated into the rule the platform runs.
//
// The rule goes through `detection.Compile` before it is returned, so what
// refuses a rule file refuses this too, and nothing that could not run is ever
// handed back. It is returned as a draft: a rule this estate has never seen
// hold against its own telemetry is not a rule this estate detects with.
func Translate(source string, data []byte) (detection.Rule, error) {
	reading := &reader{source: source}

	body, err := documentOf(reading, data)
	if err != nil {
		return detection.Rule{}, err
	}
	held, refused := fieldsOf(body)
	if refused != "" {
		return detection.Rule{}, reading.fault(body, "", "a Sigma rule "+refused)
	}

	rule, err := reading.translate(&held, body)
	if err != nil {
		return detection.Rule{}, err
	}
	if _, err := detection.Compile(rule); err != nil {
		return detection.Rule{}, reading.refused(body, err)
	}
	return rule, nil
}

func (r *reader) translate(held *mapping, body *yaml.Node) (detection.Rule, error) {
	title, err := r.words(held, "title", "title")
	if err != nil {
		return detection.Rule{}, err
	}
	if strings.TrimSpace(title) == "" {
		return detection.Rule{}, r.fault(held.at("title"), "title", "is missing, and it is what the rule is called here")
	}
	r.rule = title

	rule := detection.Rule{Name: title, Revision: 1, Status: detection.Draft}
	if rule.ID, err = r.identify(held, title); err != nil {
		return rule, err
	}
	if rule.Description, err = r.words(held, "description", "description"); err != nil {
		return rule, err
	}
	if rule.Severity, err = r.severity(held); err != nil {
		return rule, err
	}
	if rule.Source, err = r.provenance(held, title); err != nil {
		return rule, err
	}
	if rule.FalsePositives, err = r.falsePositives(held); err != nil {
		return rule, err
	}
	if rule.Tags, err = r.list(held, "tags", "tags"); err != nil {
		return rule, err
	}
	if rule.References, err = r.list(held, "references", "references"); err != nil {
		return rule, err
	}
	if rule.Class, err = r.logsource(held); err != nil {
		return rule, err
	}
	if rule.Match, rule.Count, err = r.detection(held); err != nil {
		return rule, err
	}
	return rule, r.left(held, body)
}

// A Sigma status says where a rule stands in the catalogue it came from, and it
// does not survive translation: standing here is about this estate, and a
// translated rule has never been held to anything of ours. One that its own
// catalogue has withdrawn is refused rather than imported as a draft.
func (r *reader) left(held *mapping, body *yaml.Node) error {
	status, err := r.words(held, "status", "status")
	if err != nil {
		return err
	}
	if standing := strings.ToLower(strings.TrimSpace(status)); standing == "deprecated" || standing == "unsupported" {
		return r.fault(held.at("status"), "status", fmt.Sprintf("is %q, and importing a rule its own catalogue has withdrawn is importing a decision somebody already made", standing))
	}

	for _, name := range ignored {
		held.take(name)
	}
	left := held.rest()
	if len(left) == 0 {
		return nil
	}
	if reason, named := beyond[left[0]]; named {
		return r.fault(held.key[left[0]], left[0], reason)
	}
	return r.fault(held.key[left[0]], left[0], fmt.Sprintf("is not part of a Sigma rule this build reads: it reads %s", strings.Join(understood, ", ")))
}

func (r *reader) identify(held *mapping, title string) (detection.ID, error) {
	var built strings.Builder
	for _, letter := range strings.ToLower(title) {
		switch {
		case letter >= 'a' && letter <= 'z', letter >= '0' && letter <= '9':
			built.WriteRune(letter)
		case built.Len() > 0 && !strings.HasSuffix(built.String(), "_"):
			built.WriteByte('_')
		}
	}

	named := strings.Trim(built.String(), "_")
	if named == "" || (named[0] >= '0' && named[0] <= '9') {
		return "", r.fault(held.at("title"), "title",
			fmt.Sprintf("is %q, and the id this build makes of it is %q, which is not one a rule can carry: a rule id is lowercase words joined by . or _", title, named))
	}
	return detection.ID(named), nil
}

func (r *reader) severity(held *mapping) (detection.Severity, error) {
	level, err := r.words(held, "level", "level")
	if err != nil {
		return "", err
	}

	severity, known := levels[strings.ToLower(strings.TrimSpace(level))]
	if !known {
		return "", r.fault(held.at("level"), "level",
			fmt.Sprintf("is %q, and how loud a detection is is a decision rather than a default: write informational, low, medium, high or critical", level))
	}
	return severity, nil
}

func (r *reader) provenance(held *mapping, title string) (detection.Source, error) {
	identifier, err := r.words(held, "id", "id")
	if err != nil {
		return detection.Source{}, err
	}
	if strings.TrimSpace(identifier) == "" {
		identifier = title
	}
	return detection.Source{Catalogue: Catalogue, Identifier: identifier}, nil
}

func (r *reader) falsePositives(held *mapping) (string, error) {
	written, err := r.list(held, "falsepositives", "falsepositives")
	if err != nil {
		return "", err
	}

	kept := make([]string, 0, len(written))
	for _, entry := range written {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, "; "), nil
}

func (r *reader) logsource(held *mapping) (class eventv1.EventClass, err error) {
	node, given := held.take("logsource")
	if !given {
		return class, r.fault(held.at("logsource"), "logsource", "is missing, and it is what says which events the rule reads")
	}

	written, refused := fieldsOf(node)
	if refused != "" {
		return class, r.fault(node, "logsource", refused)
	}
	var source logsource
	if source.Category, err = r.words(&written, "logsource.category", "category"); err != nil {
		return class, err
	}
	if source.Product, err = r.words(&written, "logsource.product", "product"); err != nil {
		return class, err
	}
	if source.Service, err = r.words(&written, "logsource.service", "service"); err != nil {
		return class, err
	}
	if left := written.rest(); len(left) > 0 {
		return class, r.fault(written.key[left[0]], "logsource."+left[0], "is not part of a log source")
	}

	class, err = classOf(source)
	if err != nil {
		return class, r.fault(node, "logsource", err.Error())
	}
	return class, nil
}

func (r *reader) detection(held *mapping) (detection.Expression, detection.Count, error) {
	var count detection.Count

	node, given := held.take("detection")
	if !given {
		return nil, count, r.fault(held.at("detection"), "detection", "is missing, and it is what the rule looks for")
	}
	written, refused := fieldsOf(node)
	if refused != "" {
		return nil, count, r.fault(node, "detection", refused)
	}

	condition, err := r.words(&written, "detection.condition", "condition")
	if err != nil {
		return nil, count, err
	}
	if strings.TrimSpace(condition) == "" {
		return nil, count, r.fault(written.at("condition"), "detection.condition", "is missing, and it is what puts the selections together")
	}
	within, err := r.timeframe(&written)
	if err != nil {
		return nil, count, err
	}

	read := &parser{read: r, node: written.at("condition"), part: "detection.condition", tokens: tokensOf(condition), terms: map[string]detection.Expression{}, used: map[string]struct{}{}}
	for _, name := range written.rest() {
		selection, err := r.selection("detection."+name, written.value[name])
		if err != nil {
			return nil, count, err
		}
		written.take(name)
		read.terms[name] = selection
		read.names = append(read.names, name)
	}
	if len(read.names) == 0 {
		return nil, count, r.fault(node, "detection", "holds a condition and nothing for it to put together")
	}

	match, err := read.expression(0)
	if err != nil {
		return nil, count, err
	}
	if count, err = r.threshold(read, within); err != nil {
		return nil, count, err
	}
	return match, count, r.every(read)
}

// A selection nothing in the condition names is a selection that changes
// nothing, and the common way that happens is a filter left out of a condition
// somebody edited: the rule then fires on exactly what its author wrote it to
// ignore.
func (r *reader) every(read *parser) error {
	for _, name := range read.names {
		if _, used := read.used[name]; !used {
			return r.fault(read.node, "detection."+name, "is written and the condition never names it, so it decides nothing")
		}
	}
	return nil
}

func (r *reader) threshold(read *parser, within time.Duration) (detection.Count, error) {
	var count detection.Count

	if read.peek() == "" {
		if within != 0 {
			return count, r.fault(read.node, "detection.timeframe", "is written and the condition counts nothing, so there is no window for it to scope")
		}
		return count, nil
	}

	count, err := read.aggregation()
	if err != nil {
		return detection.Count{}, err
	}
	if within == 0 {
		return detection.Count{}, r.fault(read.node, "detection.timeframe", "is missing, and a count is how many events happened inside a window")
	}
	count.Within = within
	return count, nil
}

func (r *reader) timeframe(written *mapping) (time.Duration, error) {
	node, given := written.take("timeframe")
	if !given {
		return 0, nil
	}
	if node.Kind != yaml.ScalarNode {
		return 0, r.fault(node, "detection.timeframe", "is not a window")
	}

	within, err := window(node.Value)
	if err != nil {
		return 0, r.fault(node, "detection.timeframe", fmt.Sprintf("is %q, and a window reads like 30s, 15m, 2h or 1d", node.Value))
	}
	return within, nil
}

var units = map[string]time.Duration{
	"s": time.Second,
	"m": time.Minute,
	"h": time.Hour,
	"d": 24 * time.Hour,
}

func window(written string) (time.Duration, error) {
	trimmed := strings.TrimSpace(written)
	if len(trimmed) < 2 {
		return 0, fmt.Errorf("a window is a number and a unit")
	}

	unit, known := units[strings.ToLower(trimmed[len(trimmed)-1:])]
	if !known {
		return 0, fmt.Errorf("a window is counted in s, m, h or d")
	}
	quantity, err := strconv.Atoi(trimmed[:len(trimmed)-1])
	if err != nil || quantity <= 0 {
		return 0, fmt.Errorf("a window lasts a whole number of units")
	}
	return time.Duration(quantity) * unit, nil
}

package hunt

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventory"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the read plane lists rather than hunts: the state the platform holds now,
// as its owners stored it, asked of by its own key and never by a window.
const (
	Assets         Dataset = "assets"
	Items          Dataset = "items"
	Findings       Dataset = "findings"
	FindingHistory Dataset = "finding_history"
	Assessments    Dataset = "assessments"
	Advisories     Dataset = "advisories"
)

func listed(dataset Dataset) bool {
	return slices.Contains([]Dataset{Advisories, Assessments, Assets, FindingHistory, Findings, Items}, dataset)
}

const (
	AssetsPath         = "/v1/inventory/assets"
	ItemsPath          = "/v1/inventory/items"
	FindingsPath       = "/v1/vulnerabilities/findings"
	FindingHistoryPath = "/v1/vulnerabilities/findings/history"
	AssessmentsPath    = "/v1/vulnerabilities/assessments"
	AdvisoriesPath     = "/v1/vulnerabilities/advisories"

	CodeMissingField = "missing_field"
	CodeUnknownKind  = "unknown_kind"
	CodeUnknownState = "unknown_state"
)

type listing struct {
	dataset     Dataset
	scope       Scope
	limit       int
	after       []string
	limits      Limits
	fingerprint [sha256.Size]byte
}

func (l listing) Dataset() Dataset       { return l.dataset }
func (l listing) Scope() Scope           { return l.scope }
func (l listing) Limit() int             { return l.limit }
func (l listing) After() []string        { return slices.Clone(l.after) }
func (l listing) Timeout() time.Duration { return l.limits.Timeout }
func (l listing) MaxRowsRead() uint64    { return l.limits.MaxRowsRead }

type AssetQuestion struct {
	listing
	agents        []string
	scannedBefore time.Time
}

func (q AssetQuestion) Agents() []string { return slices.Clone(q.agents) }

func (q AssetQuestion) ScannedBefore() (time.Time, bool) {
	return q.scannedBefore, !q.scannedBefore.IsZero()
}

type ItemQuestion struct {
	listing
	agent string
	kind  inventoryv1.Kind
	name  string
}

func (q ItemQuestion) Agent() string          { return q.agent }
func (q ItemQuestion) Kind() inventoryv1.Kind { return q.kind }
func (q ItemQuestion) Name() (string, bool)   { return q.name, q.name != "" }

type FindingQuestion struct {
	listing
	agents          []string
	vulnerabilities []string
	states          []vulnerabilityv1.FindingState
	packages        []string
}

func (q FindingQuestion) Agents() []string          { return slices.Clone(q.agents) }
func (q FindingQuestion) Vulnerabilities() []string { return slices.Clone(q.vulnerabilities) }
func (q FindingQuestion) Packages() []string        { return slices.Clone(q.packages) }

func (q FindingQuestion) States() []vulnerabilityv1.FindingState { return slices.Clone(q.states) }

type HistoryQuestion struct {
	listing
	agent         string
	item          string
	vulnerability string
}

func (q HistoryQuestion) Agent() string         { return q.agent }
func (q HistoryQuestion) Item() string          { return q.item }
func (q HistoryQuestion) Vulnerability() string { return q.vulnerability }

type AssessmentQuestion struct {
	listing
	agents []string
}

func (q AssessmentQuestion) Agents() []string { return slices.Clone(q.agents) }

type AdvisoryQuestion struct {
	listing
	source    string
	id        string
	ecosystem string
	name      string
	withdrawn bool
}

// Exactly one of the two is asked: every version of one advisory by its name,
// or the newest version of every advisory naming one package.
func (q AdvisoryQuestion) Advisory() (string, string, bool) { return q.source, q.id, q.id != "" }
func (q AdvisoryQuestion) Package() (string, string, bool) {
	return q.ecosystem, q.name, q.name != ""
}
func (q AdvisoryQuestion) Withdrawn() bool { return q.withdrawn }

func (c *Compiler) Assets(scope Scope, asked *inventoryv1.AssetQuery) (AssetQuestion, error) {
	agents, err := identifiers("agent_ids", asked.GetAgentIds())
	if err != nil {
		return AssetQuestion{}, err
	}
	question := AssetQuestion{agents: agents}
	if before := asked.GetScannedBefore(); before != nil {
		if err := before.CheckValid(); err != nil {
			return AssetQuestion{}, refusal(CodeUnreadableValue, "scanned_before", "%s", err)
		}
		question.scannedBefore = before.AsTime().UTC()
	}
	question.listing, err = c.list(Assets, scope, asked.GetLimit(), asked.GetCursor(),
		strings.Join(agents, ","), instantOf(question.scannedBefore))
	return question, err
}

func (c *Compiler) Items(scope Scope, asked *inventoryv1.ItemQuery) (ItemQuestion, error) {
	agent, err := identifier("agent_id", asked.GetAgentId())
	if err != nil {
		return ItemQuestion{}, err
	}
	kind := asked.GetKind()
	if _, declared := inventoryv1.Kind_name[int32(kind)]; !declared || kind == inventoryv1.Kind_KIND_UNSPECIFIED || !inventory.Shaped(kind) {
		return ItemQuestion{}, refusal(CodeUnknownKind, "kind", "%s is not a kind of item an inventory holds", kind)
	}
	question := ItemQuestion{agent: agent, kind: kind}
	if name := asked.GetName(); name != "" {
		if !named(kind) {
			return ItemQuestion{}, refusal(CodeUnknownField, "name", "an item of %s carries no name to ask by", inventory.KindName(kind))
		}
		if !readable(name) {
			return ItemQuestion{}, refusal(CodeUnreadableValue, "name", "a name is printable text of at most %d bytes", maxValueBytes)
		}
		question.name = name
	}
	question.listing, err = c.list(Items, scope, asked.GetLimit(), asked.GetCursor(),
		agent, strconv.Itoa(int(kind)), question.name)
	return question, err
}

func (c *Compiler) Findings(scope Scope, asked *vulnerabilityv1.FindingQuery) (FindingQuestion, error) {
	agents, err := identifiers("agent_ids", asked.GetAgentIds())
	if err != nil {
		return FindingQuestion{}, err
	}
	vulnerabilities, err := texts("vulnerability_ids", asked.GetVulnerabilityIds())
	if err != nil {
		return FindingQuestion{}, err
	}
	packages, err := texts("package_names", asked.GetPackageNames())
	if err != nil {
		return FindingQuestion{}, err
	}
	states, err := findingStates(asked.GetStates())
	if err != nil {
		return FindingQuestion{}, err
	}
	question := FindingQuestion{agents: agents, vulnerabilities: vulnerabilities, states: states, packages: packages}
	written := make([]string, len(states))
	for index, state := range states {
		written[index] = strconv.Itoa(int(state))
	}
	question.listing, err = c.list(Findings, scope, asked.GetLimit(), asked.GetCursor(),
		strings.Join(agents, ","), strings.Join(vulnerabilities, ","), strings.Join(written, ","), strings.Join(packages, ","))
	return question, err
}

func (c *Compiler) History(scope Scope, asked *vulnerabilityv1.FindingHistoryQuery) (HistoryQuestion, error) {
	agent, err := identifier("agent_id", asked.GetAgentId())
	if err != nil {
		return HistoryQuestion{}, err
	}
	item, err := identifier("item_id", asked.GetItemId())
	if err != nil {
		return HistoryQuestion{}, err
	}
	vulnerability, err := text("vulnerability_id", asked.GetVulnerabilityId())
	if err != nil {
		return HistoryQuestion{}, err
	}
	question := HistoryQuestion{agent: agent, item: item, vulnerability: vulnerability}
	question.listing, err = c.list(FindingHistory, scope, asked.GetLimit(), asked.GetCursor(), agent, item, vulnerability)
	return question, err
}

func (c *Compiler) Assessments(scope Scope, asked *vulnerabilityv1.AssessmentQuery) (AssessmentQuestion, error) {
	agents, err := identifiers("agent_ids", asked.GetAgentIds())
	if err != nil {
		return AssessmentQuestion{}, err
	}
	question := AssessmentQuestion{agents: agents}
	question.listing, err = c.list(Assessments, scope, asked.GetLimit(), asked.GetCursor(), strings.Join(agents, ","))
	return question, err
}

func (c *Compiler) Advisories(scope Scope, asked *vulnerabilityv1.AdvisoryQuery) (AdvisoryQuestion, error) {
	question := AdvisoryQuestion{withdrawn: asked.GetWithdrawn()}
	var err error
	switch form := asked.GetQuestion().(type) {
	case *vulnerabilityv1.AdvisoryQuery_Advisory:
		if question.source, err = text("advisory.source", form.Advisory.GetSource()); err != nil {
			return AdvisoryQuestion{}, err
		}
		if question.id, err = text("advisory.id", form.Advisory.GetId()); err != nil {
			return AdvisoryQuestion{}, err
		}
	case *vulnerabilityv1.AdvisoryQuery_Package:
		if question.ecosystem, err = text("package.ecosystem", form.Package.GetEcosystem()); err != nil {
			return AdvisoryQuestion{}, err
		}
		if question.name, err = text("package.name", form.Package.GetName()); err != nil {
			return AdvisoryQuestion{}, err
		}
	default:
		return AdvisoryQuestion{}, refusal(CodeMissingField, "question", "an advisory is asked for by its name or by a package it names")
	}
	question.listing, err = c.list(Advisories, scope, asked.GetLimit(), asked.GetCursor(),
		question.source, question.id, question.ecosystem, question.name, strconv.FormatBool(question.withdrawn))
	return question, err
}

// Everything that decides which records a page holds and in which order is
// signed with its position, so a cursor is spent only on the question, and the
// grant, it came from.
func (c *Compiler) list(dataset Dataset, scope Scope, limit uint32, cursor string, parts ...string) (listing, error) {
	if scope.Empty() {
		return listing{}, refusal(CodeUnscoped, "", "a listing is answered within a scope and this caller has none")
	}
	page, err := c.page(limit)
	if err != nil {
		return listing{}, err
	}
	written := strings.Builder{}
	fmt.Fprintf(&written, "%s\n%s\n%d\n", dataset, strings.Join(scope.Tenants(), ","), page)
	for _, part := range parts {
		fmt.Fprintf(&written, "%d:%s\n", len(part), part)
	}
	question := listing{dataset: dataset, scope: scope, limit: page, limits: c.limits, fingerprint: sha256.Sum256([]byte(written.String()))}
	if cursor != "" {
		after, err := decodePosition(c.key, question.fingerprint, cursor)
		if err != nil {
			return listing{}, refusal(CodeInvalidCursor, "cursor", "%s", err)
		}
		question.after = after
	}
	return question, nil
}

func (c *Compiler) resume(question listing, last []string) (string, error) {
	return encodePosition(c.key, question.fingerprint, last)
}

func identifier(field, value string) (string, error) {
	if value == "" {
		return "", refusal(CodeMissingField, field, "the question names no %s", field)
	}
	if !event.ValidIdentifier(value) {
		return "", refusal(CodeUnreadableValue, field, "%q is not an identifier the platform issues", value)
	}
	return value, nil
}

func identifiers(field string, values []string) ([]string, error) {
	return many(field, values, func(value string) bool { return event.ValidIdentifier(value) }, "an identifier the platform issues")
}

func text(field, value string) (string, error) {
	if value == "" {
		return "", refusal(CodeMissingField, field, "the question names no %s", field)
	}
	if !readable(value) {
		return "", refusal(CodeUnreadableValue, field, "%s is printable text of at most %d bytes", field, maxValueBytes)
	}
	return value, nil
}

func texts(field string, values []string) ([]string, error) {
	return many(field, values, readable, fmt.Sprintf("printable text of at most %d bytes", maxValueBytes))
}

func many(field string, values []string, valid func(string) bool, shape string) ([]string, error) {
	if len(values) > maxValuesPerPredicate {
		return nil, refusal(CodeQueryTooLarge, field, "a question names at most %d of %s", maxValuesPerPredicate, field)
	}
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if !valid(value) {
			return nil, refusal(CodeUnreadableValue, field, "%q is not %s", value, shape)
		}
		if !slices.Contains(kept, value) {
			kept = append(kept, value)
		}
	}
	slices.Sort(kept)
	return kept, nil
}

func readable(value string) bool {
	if value == "" || len(value) > maxValueBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func findingStates(asked []vulnerabilityv1.FindingState) ([]vulnerabilityv1.FindingState, error) {
	kept := make([]vulnerabilityv1.FindingState, 0, len(asked))
	for _, state := range asked {
		if _, declared := vulnerabilityv1.FindingState_name[int32(state)]; !declared || state == vulnerabilityv1.FindingState_FINDING_STATE_UNSPECIFIED {
			return nil, refusal(CodeUnknownState, "states", "%s is not where a finding stands", state)
		}
		if !slices.Contains(kept, state) {
			kept = append(kept, state)
		}
	}
	slices.Sort(kept)
	return kept, nil
}

// A kind is asked about by name when the item the contract declares for it
// carries one; an item's body is the field named after its kind.
func named(kind inventoryv1.Kind) bool {
	body := (&inventoryv1.Item{}).ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(inventory.KindName(kind)))
	return body != nil && body.Message() != nil && body.Message().Fields().ByName("name") != nil
}

func instantOf(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return strconv.FormatInt(at.UnixNano(), 10)
}

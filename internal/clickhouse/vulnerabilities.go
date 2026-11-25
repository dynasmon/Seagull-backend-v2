package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var opened = []vulnerabilityv1.FindingState{
	vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED,
	vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED,
	vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS,
}

func findingStateName(state vulnerabilityv1.FindingState) string {
	return strings.ToLower(strings.TrimPrefix(state.String(), "FINDING_STATE_"))
}

// Where each finding stands is its newest decision, held to the asset's newest
// whole assessment (ADR 49): one made on fresh intelligence of an asset that
// could be assessed decides every open finding again, so an open decision older
// than it is a finding it did not list, and is not open. With no such
// assessment the join reads the zero line, which holds no decision back.
func (h *Hunter) Findings(ctx context.Context, asked hunt.FindingQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	tenants := asked.Scope().Tenants()
	ctx = budgeted(ctx, asked.Timeout(), asked.MaxRowsRead())

	within := []string{"tenant_id IN (" + placeholders(len(tenants)) + ")"}
	scoped := valuesOf(tenants)
	if agents := asked.Agents(); len(agents) > 0 {
		within = append(within, "agent_id IN ("+placeholders(len(agents))+")")
		scoped = append(scoped, valuesOf(agents)...)
	}
	conditions, arguments := slices.Clone(within), slices.Clone(scoped)
	if vulnerabilities := asked.Vulnerabilities(); len(vulnerabilities) > 0 {
		conditions = append(conditions, "vulnerability_id IN ("+placeholders(len(vulnerabilities))+")")
		arguments = append(arguments, valuesOf(vulnerabilities)...)
	}
	if packages := asked.Packages(); len(packages) > 0 {
		conditions = append(conditions, "package_name IN ("+placeholders(len(packages))+")")
		arguments = append(arguments, valuesOf(packages)...)
	}
	if after := asked.After(); len(after) > 0 {
		if len(after) != 4 {
			return nil, nil, fmt.Errorf("a position among findings names %d values and a finding is named by 4", len(after))
		}
		conditions = append(conditions, "(tenant_id, agent_id, item_id, vulnerability_id) > (?, ?, ?, ?)")
		arguments = append(arguments, after[0], after[1], after[2], after[3])
	}

	open := make([]any, len(opened))
	for index, state := range opened {
		open[index] = findingStateName(state)
	}
	stands := []string{"NOT (decision.state IN (" + placeholders(len(open)) + ") AND decision.made_on < held.line)"}
	standing := slices.Clone(open)
	if states := asked.States(); len(states) > 0 {
		stands = append(stands, "decision.state IN ("+placeholders(len(states))+")")
		for _, state := range states {
			standing = append(standing, findingStateName(state))
		}
	}

	newest := "(inventory_as_of, intelligence_as_of, decided_at)"
	statement := "SELECT decision.tenant_id, decision.agent_id, decision.item_id, decision.vulnerability_id, decision.record FROM (" +
		"SELECT tenant_id, agent_id, item_id, vulnerability_id, argMax(record, " + newest + ") AS record," +
		" argMax(state, " + newest + ") AS state, argMax((inventory_as_of, intelligence_as_of), " + newest + ") AS made_on" +
		" FROM " + findingTable + " FINAL WHERE " + strings.Join(conditions, " AND ") +
		" GROUP BY tenant_id, agent_id, item_id, vulnerability_id) AS decision LEFT JOIN (" +
		"SELECT tenant_id, agent_id, max((inventory_as_of, intelligence_as_of)) AS line FROM " + findingAssessmentTable + " FINAL" +
		" WHERE scope = 'asset' AND NOT stale AND unassessable = '' AND " + strings.Join(within, " AND ") +
		" GROUP BY tenant_id, agent_id) AS held ON decision.tenant_id = held.tenant_id AND decision.agent_id = held.agent_id" +
		" WHERE " + strings.Join(stands, " AND ") +
		" ORDER BY decision.tenant_id, decision.agent_id, decision.item_id, decision.vulnerability_id LIMIT " + strconv.Itoa(asked.Limit())
	arguments = append(append(arguments, scoped...), standing...)

	rows, err := h.connection.Query(ctx, statement, arguments...)
	if err != nil {
		return nil, nil, fmt.Errorf("list the findings: %w", err)
	}
	page := &vulnerabilityv1.FindingPage{}
	var last []string
	for rows.Next() {
		var tenant, agent, item, vulnerability, body string
		if err := rows.Scan(&tenant, &agent, &item, &vulnerability, &body); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("read a finding: %w", err)
		}
		decided, err := findingOf(body)
		if err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		page.Findings = append(page.Findings, decided)
		last = []string{tenant, agent, item, vulnerability}
	}
	if err := closed(rows); err != nil {
		return nil, nil, fmt.Errorf("list the findings: %w", err)
	}
	return page, last, nil
}

func (h *Hunter) History(ctx context.Context, asked hunt.HistoryQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	tenants := asked.Scope().Tenants()
	ctx = budgeted(ctx, asked.Timeout(), asked.MaxRowsRead())

	conditions := []string{"tenant_id IN (" + placeholders(len(tenants)) + ")", "agent_id = ?", "item_id = ?", "vulnerability_id = ?"}
	arguments := append(valuesOf(tenants), asked.Agent(), asked.Item(), asked.Vulnerability())
	if after := asked.After(); len(after) > 0 {
		if len(after) != 5 {
			return nil, nil, fmt.Errorf("a position in a finding's history names %d values and a decision is placed by 5", len(after))
		}
		instants := make([]any, 4)
		for index := range instants {
			at, err := strconv.ParseInt(after[index], 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("a position in a finding's history holds %q: %w", after[index], err)
			}
			instants[index] = at
		}
		conditions = append(conditions, "(inventory_as_of, intelligence_as_of, decided_at, opened_at, state) < ("+
			strings.Repeat(instantPlaceholder+", ", 4)+"?)")
		arguments = append(append(arguments, instants...), after[4])
	}

	rows, err := h.connection.Query(ctx, "SELECT record, inventory_as_of, intelligence_as_of, decided_at, opened_at, state FROM "+findingTable+
		" FINAL WHERE "+strings.Join(conditions, " AND ")+
		" ORDER BY inventory_as_of DESC, intelligence_as_of DESC, decided_at DESC, opened_at DESC, state DESC LIMIT "+strconv.Itoa(asked.Limit()),
		arguments...)
	if err != nil {
		return nil, nil, fmt.Errorf("read the history of a finding of agent %s: %w", asked.Agent(), err)
	}
	page := &vulnerabilityv1.FindingPage{}
	var last []string
	for rows.Next() {
		var (
			body, state                          string
			inventory, intelligence, decided, at time.Time
		)
		if err := rows.Scan(&body, &inventory, &intelligence, &decided, &at, &state); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("read a decision of agent %s: %w", asked.Agent(), err)
		}
		decision, err := findingOf(body)
		if err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		page.Findings = append(page.Findings, decision)
		last = []string{millis(inventory), millis(intelligence), millis(decided), millis(at), state}
	}
	if err := closed(rows); err != nil {
		return nil, nil, fmt.Errorf("read the history of a finding of agent %s: %w", asked.Agent(), err)
	}
	return page, last, nil
}

func (h *Hunter) Assessments(ctx context.Context, asked hunt.AssessmentQuestion) (*vulnerabilityv1.AssessmentPage, []string, error) {
	tenants := asked.Scope().Tenants()
	ctx = budgeted(ctx, asked.Timeout(), asked.MaxRowsRead())

	conditions := []string{"scope = 'asset'", "tenant_id IN (" + placeholders(len(tenants)) + ")"}
	arguments := valuesOf(tenants)
	if agents := asked.Agents(); len(agents) > 0 {
		conditions = append(conditions, "agent_id IN ("+placeholders(len(agents))+")")
		arguments = append(arguments, valuesOf(agents)...)
	}
	if after := asked.After(); len(after) > 0 {
		if len(after) != 2 {
			return nil, nil, fmt.Errorf("a position among assessments names %d values and an asset is named by 2", len(after))
		}
		conditions = append(conditions, "(tenant_id, agent_id) > (?, ?)")
		arguments = append(arguments, after[0], after[1])
	}

	rows, err := h.connection.Query(ctx, "SELECT tenant_id, agent_id, argMax(record, (inventory_as_of, intelligence_as_of, decided_at)) FROM "+
		findingAssessmentTable+" FINAL WHERE "+strings.Join(conditions, " AND ")+
		" GROUP BY tenant_id, agent_id ORDER BY tenant_id, agent_id LIMIT "+strconv.Itoa(asked.Limit()), arguments...)
	if err != nil {
		return nil, nil, fmt.Errorf("list the assessments: %w", err)
	}
	page := &vulnerabilityv1.AssessmentPage{}
	var last []string
	for rows.Next() {
		var tenant, agent, body string
		if err := rows.Scan(&tenant, &agent, &body); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("read an assessment: %w", err)
		}
		var record vulnerabilityv1.FindingRecord
		if err := proto.Unmarshal([]byte(body), &record); err != nil || record.GetAssessment() == nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("an assessment of agent %s is stored as something that is not one", agent)
		}
		page.Assessments = append(page.Assessments, record.GetAssessment())
		last = []string{tenant, agent}
	}
	if err := closed(rows); err != nil {
		return nil, nil, fmt.Errorf("list the assessments: %w", err)
	}
	return page, last, nil
}

// By name, every version of one advisory, newest first; by package, the newest
// version of every advisory whose newest version names it. A withdrawal is a
// newer version, so an advisory whose newest version withdrew it is left out
// unless asked for, never answered by the versions before it.
func (h *Hunter) Advisories(ctx context.Context, asked hunt.AdvisoryQuestion) (*vulnerabilityv1.AdvisoryPage, []string, error) {
	ctx = budgeted(ctx, asked.Timeout(), asked.MaxRowsRead())
	if source, id, named := asked.Advisory(); named {
		return h.versions(ctx, asked, source, id)
	}
	ecosystem, name, _ := asked.Package()
	return h.naming(ctx, asked, ecosystem, name)
}

func (h *Hunter) versions(ctx context.Context, asked hunt.AdvisoryQuestion, source, id string) (*vulnerabilityv1.AdvisoryPage, []string, error) {
	page := &vulnerabilityv1.AdvisoryPage{}
	if !asked.Withdrawn() {
		var withdrawn time.Time
		if err := h.connection.QueryRow(ctx, "SELECT argMax(withdrawn, (modified, normalization)) FROM "+advisoryTable+
			" WHERE source = ? AND advisory_id = ?", source, id).Scan(&withdrawn); err != nil {
			return nil, nil, fmt.Errorf("read whether advisory %s was withdrawn: %w", id, err)
		}
		if withdrawn.After(epochInstant) {
			return page, nil, nil
		}
	}
	conditions := []string{"source = ?", "advisory_id = ?"}
	arguments := []any{source, id}
	if after := asked.After(); len(after) > 0 {
		at, normalization, err := versionAt(after)
		if err != nil {
			return nil, nil, err
		}
		conditions = append(conditions, "(modified, normalization) < ("+versionPlaceholder+", ?)")
		arguments = append(arguments, at, normalization)
	}
	versions, err := h.advisoryRows(ctx, "SELECT "+strings.Join(advisoryColumns, ", ")+" FROM "+advisoryTable+" FINAL WHERE "+
		strings.Join(conditions, " AND ")+" ORDER BY modified DESC, normalization DESC LIMIT "+strconv.Itoa(asked.Limit()), arguments...)
	if err != nil || len(versions) == 0 {
		return page, nil, err
	}
	if err := h.restore(ctx, page, versions); err != nil {
		return nil, nil, err
	}
	newest := versions[len(versions)-1]
	return page, []string{strconv.FormatInt(newest.Modified.UnixNano(), 10), strconv.FormatUint(uint64(newest.Normalization), 10)}, nil
}

func (h *Hunter) naming(ctx context.Context, asked hunt.AdvisoryQuestion, ecosystem, name string) (*vulnerabilityv1.AdvisoryPage, []string, error) {
	inner := []string{"(source, advisory_id) IN (SELECT source, advisory_id FROM " + affectedTable + " WHERE ecosystem = ? AND package = ?)"}
	arguments := []any{ecosystem, name}
	if after := asked.After(); len(after) > 0 {
		if len(after) != 2 {
			return nil, nil, fmt.Errorf("a position among advisories names %d values and an advisory is named by 2", len(after))
		}
		inner = append(inner, "(source, advisory_id) > (?, ?)")
		arguments = append(arguments, after[0], after[1])
	}
	outer := []string{"(source, advisory_id, newest.1, newest.2) IN (SELECT source, advisory_id, modified, normalization FROM " + affectedTable +
		" WHERE ecosystem = ? AND package = ?)"}
	arguments = append(arguments, ecosystem, name)
	if !asked.Withdrawn() {
		outer = append(outer, "withdrawn_at = toDateTime64(0, 3, 'UTC')")
	}
	rows, err := h.connection.Query(ctx, "SELECT source, advisory_id, newest.1, newest.2 FROM (SELECT source, advisory_id,"+
		" max((modified, normalization)) AS newest, argMax(withdrawn, (modified, normalization)) AS withdrawn_at FROM "+advisoryTable+
		" WHERE "+strings.Join(inner, " AND ")+" GROUP BY source, advisory_id) WHERE "+strings.Join(outer, " AND ")+
		" ORDER BY source, advisory_id LIMIT "+strconv.Itoa(asked.Limit()), arguments...)
	if err != nil {
		return nil, nil, fmt.Errorf("list the advisories naming %s in %s: %w", name, ecosystem, err)
	}
	type version struct {
		source, id    string
		modified      time.Time
		normalization uint32
	}
	var named []version
	for rows.Next() {
		var one version
		if err := rows.Scan(&one.source, &one.id, &one.modified, &one.normalization); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("read an advisory naming %s: %w", name, err)
		}
		named = append(named, one)
	}
	if err := closed(rows); err != nil {
		return nil, nil, fmt.Errorf("list the advisories naming %s in %s: %w", name, ecosystem, err)
	}
	page := &vulnerabilityv1.AdvisoryPage{}
	if len(named) == 0 {
		return page, nil, nil
	}

	pairs := make([]string, len(named))
	pairArguments := make([]any, 0, 2*len(named))
	for index, one := range named {
		pairs[index] = "(?, ?)"
		pairArguments = append(pairArguments, one.source, one.id)
	}
	stored, err := h.advisoryRows(ctx, "SELECT "+strings.Join(advisoryColumns, ", ")+" FROM "+advisoryTable+" FINAL WHERE (source, advisory_id) IN ("+
		strings.Join(pairs, ", ")+")", pairArguments...)
	if err != nil {
		return nil, nil, err
	}
	versions := make([]advisorystore.AdvisoryRow, 0, len(named))
	for _, one := range named {
		for _, row := range stored {
			if row.Source == one.source && row.AdvisoryID == one.id && row.Modified.Equal(one.modified) && row.Normalization == one.normalization {
				versions = append(versions, row)
				break
			}
		}
	}
	if err := h.restore(ctx, page, versions); err != nil {
		return nil, nil, err
	}
	last := named[len(named)-1]
	return page, []string{last.source, last.id}, nil
}

func (h *Hunter) advisoryRows(ctx context.Context, statement string, arguments ...any) ([]advisorystore.AdvisoryRow, error) {
	rows, err := h.connection.Query(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("read advisories: %w", err)
	}
	var read []advisorystore.AdvisoryRow
	for rows.Next() {
		var row advisorystore.AdvisoryRow
		if err := rows.Scan(advisoryPointers(&row)...); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read an advisory: %w", err)
		}
		row.Modified = row.Modified.UTC()
		read = append(read, row)
	}
	return read, closed(rows)
}

// Each version is read back with the packages it names, those of that version
// alone: an older version's entries are rows of the same advisory.
func (h *Hunter) restore(ctx context.Context, page *vulnerabilityv1.AdvisoryPage, versions []advisorystore.AdvisoryRow) error {
	pairs := make([]string, 0, len(versions))
	arguments := make([]any, 0, 2*len(versions))
	for _, version := range versions {
		pairs = append(pairs, "(?, ?)")
		arguments = append(arguments, version.Source, version.AdvisoryID)
	}
	rows, err := h.connection.Query(ctx, "SELECT "+strings.Join(affectedColumns, ", ")+" FROM "+affectedTable+" FINAL WHERE (source, advisory_id) IN ("+
		strings.Join(pairs, ", ")+") ORDER BY source, advisory_id, modified, normalization, entry", arguments...)
	if err != nil {
		return fmt.Errorf("read the packages %d advisories name: %w", len(versions), err)
	}
	byVersion := map[string][]advisorystore.AffectedRow{}
	for rows.Next() {
		var row advisorystore.AffectedRow
		if err := rows.Scan(affectedPointers(&row)...); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read a package an advisory names: %w", err)
		}
		key := versionKey(row.Source, row.AdvisoryID, row.Modified, row.Normalization)
		byVersion[key] = append(byVersion[key], row)
	}
	if err := closed(rows); err != nil {
		return fmt.Errorf("read the packages %d advisories name: %w", len(versions), err)
	}
	for _, version := range versions {
		advisory, err := advisorystore.Restore(version, byVersion[versionKey(version.Source, version.AdvisoryID, version.Modified, version.Normalization)])
		if err != nil {
			return err
		}
		page.Advisories = append(page.Advisories, advisory)
	}
	return nil
}

func versionKey(source, id string, modified time.Time, normalization uint32) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d|%d", len(source), source, len(id), id, modified.UTC().UnixNano(), normalization)
}

func versionAt(position []string) (int64, uint32, error) {
	if len(position) != 2 {
		return 0, 0, fmt.Errorf("a position among versions names %d values and a version is placed by 2", len(position))
	}
	at, err := strconv.ParseInt(position[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("a position among versions holds %q: %w", position[0], err)
	}
	normalization, err := strconv.ParseUint(position[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("a position among versions holds %q: %w", position[1], err)
	}
	return at, uint32(normalization), nil
}

func findingOf(body string) (*vulnerabilityv1.Finding, error) {
	var record vulnerabilityv1.FindingRecord
	if err := proto.Unmarshal([]byte(body), &record); err != nil || record.GetFinding() == nil {
		return nil, fmt.Errorf("a finding is stored as something that is not one")
	}
	return record.GetFinding(), nil
}

func millis(at time.Time) string { return strconv.FormatInt(at.UnixMilli(), 10) }

var epochInstant = time.Unix(0, 0).UTC()

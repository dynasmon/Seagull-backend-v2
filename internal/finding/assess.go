package finding

import (
	"cmp"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// How old the last complete reading of a feed may be, measured from the
// inventory an evaluation reads and never from the clock, so evaluating the
// same inventory again is as fresh as it was the first time.
type Policy struct {
	Freshness time.Duration
}

// An asset as the inventory store holds it when it is read: its operating
// system, the packages current against the newest scan, that scan, and the
// newest observation among them.
type Asset struct {
	TenantID string
	AgentID  string
	System   *inventoryv1.OperatingSystem
	Packages []Item
	Scan     Scan
	AsOf     time.Time
}

type Item struct {
	ID       string
	Package  *inventoryv1.Package
	RecordID string
	LastSeen time.Time
}

type Scan struct {
	RecordID  string
	ScannedAt time.Time
}

type Intelligence struct {
	Advisories []Advisory
	Feed       Feed
	AsOf       time.Time
}

type Feed struct {
	Source   string
	Name     string
	SyncedAt time.Time
}

type Advisory struct {
	Source        string
	ID            string
	Modified      time.Time
	Normalization uint32
	Aliases       []string
	Upstream      []string
	Severities    []*vulnerabilityv1.Severity
	Affected      []*vulnerabilityv1.Affected
}

type Name struct {
	ItemID          string
	VulnerabilityID string
}

type Evaluation struct {
	Findings   []*vulnerabilityv1.Finding
	Assessment *vulnerabilityv1.Assessment
}

func Assess(asset Asset, intelligence Intelligence, previous map[Name]*vulnerabilityv1.Finding, decidedAt time.Time, policy Policy) Evaluation {
	e := newEvaluation(asset, intelligence, previous, decidedAt, policy)
	if unplaced := e.place(); unplaced != vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED {
		return e.done(vulnerabilityv1.Assessment_SCOPE_ASSET, unplaced)
	}
	current := make(map[string]bool, len(asset.Packages))
	for _, item := range asset.Packages {
		current[item.ID] = true
		e.item(item)
	}
	for _, name := range e.named {
		if decided := previous[name]; !current[name.ItemID] && opened(decided) {
			e.close(decided, vulnerabilityv1.FindingState_FINDING_STATE_REMOVED, vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED, nil)
		}
	}
	return e.done(vulnerabilityv1.Assessment_SCOPE_ASSET, vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED)
}

// Judges again only the packages an advisory names, as advisories name them,
// and says nothing of the rest: a package it did not name keeps the decisions
// it had, so nothing here is closed for being absent.
func AssessPackages(asset Asset, intelligence Intelligence, previous map[Name]*vulnerabilityv1.Finding, advised []string, decidedAt time.Time, policy Policy) Evaluation {
	e := newEvaluation(asset, intelligence, previous, decidedAt, policy)
	if unplaced := e.place(); unplaced != vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED {
		return e.done(vulnerabilityv1.Assessment_SCOPE_PACKAGES, unplaced)
	}
	for _, item := range asset.Packages {
		placed, err := vulnerability.PackageOf(asset.System, item.Package)
		if err == nil && slices.Contains(advised, placed.Key.Package) {
			e.item(item)
		}
	}
	return e.done(vulnerabilityv1.Assessment_SCOPE_PACKAGES, vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED)
}

type citation struct {
	advisory *Advisory
	entry    *vulnerabilityv1.Affected
}

type evaluation struct {
	asset        Asset
	intelligence Intelligence
	previous     map[Name]*vulnerabilityv1.Finding
	decidedAt    time.Time
	policy       Policy

	named  []Name
	byItem map[string][]Name

	ecosystem  string
	stale      bool
	cited      map[string]map[string][]citation
	findings   []*vulnerabilityv1.Finding
	open       uint32
	closed     uint32
	unassessed map[vulnerabilityv1.Unassessable]uint32
}

func newEvaluation(asset Asset, intelligence Intelligence, previous map[Name]*vulnerabilityv1.Finding, decidedAt time.Time, policy Policy) *evaluation {
	e := &evaluation{
		asset:        asset,
		intelligence: intelligence,
		previous:     previous,
		decidedAt:    decidedAt,
		policy:       policy,
		byItem:       map[string][]Name{},
		unassessed:   map[vulnerabilityv1.Unassessable]uint32{},
	}
	for name := range previous {
		e.named = append(e.named, name)
	}
	slices.SortFunc(e.named, func(a, b Name) int {
		return cmp.Or(cmp.Compare(a.ItemID, b.ItemID), cmp.Compare(a.VulnerabilityID, b.VulnerabilityID))
	})
	for _, name := range e.named {
		e.byItem[name.ItemID] = append(e.byItem[name.ItemID], name)
	}
	return e
}

func (e *evaluation) place() vulnerabilityv1.Unassessable {
	if e.asset.System == nil {
		return vulnerabilityv1.Unassessable_UNASSESSABLE_NO_OPERATING_SYSTEM
	}
	ecosystem, err := vulnerability.EcosystemOf(e.asset.System)
	switch {
	case errors.Is(err, vulnerability.ErrUnknownRelease):
		return vulnerabilityv1.Unassessable_UNASSESSABLE_UNKNOWN_RELEASE
	case err != nil:
		return vulnerabilityv1.Unassessable_UNASSESSABLE_UNKNOWN_DISTRIBUTION
	case e.intelligence.Feed.SyncedAt.IsZero():
		return vulnerabilityv1.Unassessable_UNASSESSABLE_STALE_INTELLIGENCE
	}
	e.ecosystem = ecosystem
	e.stale = e.asset.AsOf.Sub(e.intelligence.Feed.SyncedAt) > e.policy.Freshness
	e.cited = map[string]map[string][]citation{}
	for index := range e.intelligence.Advisories {
		advisory := &e.intelligence.Advisories[index]
		for _, entry := range advisory.Affected {
			if entry.GetEcosystem() != ecosystem {
				continue
			}
			if e.cited[entry.GetName()] == nil {
				e.cited[entry.GetName()] = map[string][]citation{}
			}
			for _, vulnerabilityID := range vulnerabilitiesOf(advisory) {
				e.cited[entry.GetName()][vulnerabilityID] = append(e.cited[entry.GetName()][vulnerabilityID], citation{advisory: advisory, entry: entry})
			}
		}
	}
	return vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED
}

func (e *evaluation) item(item Item) {
	placed, err := vulnerability.PackageOf(e.asset.System, item.Package)
	if err != nil {
		e.unassess(item, unplaced(err))
		return
	}
	if _, err := vulnerability.Compare(placed.Key.Ecosystem, placed.Version, placed.Version); err != nil {
		e.unassess(item, vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_VERSION)
		return
	}

	cited := e.cited[placed.Key.Package]
	judged := make([]string, 0, len(cited))
	for vulnerabilityID := range cited {
		judged = append(judged, vulnerabilityID)
	}
	for _, name := range e.byItem[item.ID] {
		if opened(e.previous[name]) && cited[name.VulnerabilityID] == nil {
			judged = append(judged, name.VulnerabilityID)
		}
	}
	slices.Sort(judged)

	for _, vulnerabilityID := range judged {
		citations := cited[vulnerabilityID]
		entries := make([]*vulnerabilityv1.Affected, 0, len(citations))
		for _, cite := range citations {
			entries = append(entries, cite.entry)
		}
		judgement := vulnerability.Judge(placed.Key.Ecosystem, placed.Version, entries...)
		e.decide(item, placed, vulnerabilityID, citations, judgement)
	}
}

func (e *evaluation) decide(item Item, placed vulnerability.Installed, vulnerabilityID string, citations []citation, judgement vulnerability.Judgement) {
	previous := e.previous[Name{ItemID: item.ID, VulnerabilityID: vulnerabilityID}]
	made := e.made(item, placed, vulnerabilityID, citations)
	switch judgement.Verdict {
	case vulnerability.Affected:
		made.State, made.OpenedAt = e.opening(previous)
		made.Fix = judgement.Fix
		e.open++
	case vulnerability.CannotAssess:
		made.State = vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS
		made.Unassessable = vulnerabilityv1.Unassessable_UNASSESSABLE_UNREADABLE_ADVISORY
		made.OpenedAt = episodeOf(previous)
	case vulnerability.Fixed, vulnerability.NotAffected:
		if !opened(previous) || e.stale {
			return
		}
		made.State = vulnerabilityv1.FindingState_FINDING_STATE_NOT_AFFECTED
		if judgement.Verdict == vulnerability.Fixed {
			made.State, made.Fix = vulnerabilityv1.FindingState_FINDING_STATE_FIXED, judgement.Fix
		}
		made.OpenedAt = previous.GetOpenedAt()
		e.closed++
	}
	e.findings = append(e.findings, made)
}

// A package that can no longer be judged keeps every open finding it had, as
// one that cannot be assessed and says why: a gap is never an answer.
func (e *evaluation) unassess(item Item, reason vulnerabilityv1.Unassessable) {
	e.unassessed[reason]++
	for _, name := range e.byItem[item.ID] {
		if previous := e.previous[name]; opened(previous) {
			e.close(previous, vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS, reason, &item)
		}
	}
}

func (e *evaluation) close(previous *vulnerabilityv1.Finding, state vulnerabilityv1.FindingState, reason vulnerabilityv1.Unassessable, item *Item) {
	if state != vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS && e.stale {
		return
	}
	made := &vulnerabilityv1.Finding{
		SchemaVersion:   SchemaVersion,
		TenantId:        e.asset.TenantID,
		AgentId:         e.asset.AgentID,
		ItemId:          previous.GetItemId(),
		VulnerabilityId: previous.GetVulnerabilityId(),
		State:           state,
		Unassessable:    reason,
		Package:         previous.GetPackage(),
		Advised:         previous.GetAdvised(),
		ComparedVersion: previous.GetComparedVersion(),
		Citations:       previous.GetCitations(),
		Rating:          previous.GetRating(),
		OpenedAt:        previous.GetOpenedAt(),
		Inventory:       e.inventoryBasis(previous.GetInventory().GetRecordId(), previous.GetInventory().GetLastSeen().AsTime()),
		Intelligence:    e.intelligenceBasis(),
		DecidedAt:       timestamppb.New(e.decidedAt),
	}
	if item != nil {
		made.Inventory = e.inventoryBasis(item.RecordID, item.LastSeen)
	}
	if state != vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS {
		e.closed++
	}
	e.findings = append(e.findings, made)
}

func (e *evaluation) made(item Item, placed vulnerability.Installed, vulnerabilityID string, citations []citation) *vulnerabilityv1.Finding {
	return &vulnerabilityv1.Finding{
		SchemaVersion:   SchemaVersion,
		TenantId:        e.asset.TenantID,
		AgentId:         e.asset.AgentID,
		ItemId:          item.ID,
		VulnerabilityId: vulnerabilityID,
		Package:         item.Package,
		Advised:         &vulnerabilityv1.AdvisedPackage{Ecosystem: placed.Key.Ecosystem, Name: placed.Key.Package},
		ComparedVersion: placed.Version,
		Citations:       cite(citations),
		Rating:          rate(citations),
		Inventory:       e.inventoryBasis(item.RecordID, item.LastSeen),
		Intelligence:    e.intelligenceBasis(),
		DecidedAt:       timestamppb.New(e.decidedAt),
	}
}

func (e *evaluation) opening(previous *vulnerabilityv1.Finding) (vulnerabilityv1.FindingState, *timestamppb.Timestamp) {
	switch {
	case opened(previous) && previous.GetState() == vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED:
		return vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED, previous.GetOpenedAt()
	case opened(previous):
		return vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, previous.GetOpenedAt()
	case closed(previous):
		return vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED, timestamppb.New(e.asset.AsOf)
	}
	return vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, timestamppb.New(e.asset.AsOf)
}

func (e *evaluation) inventoryBasis(recordID string, lastSeen time.Time) *vulnerabilityv1.InventoryBasis {
	return &vulnerabilityv1.InventoryBasis{
		RecordId:     recordID,
		LastSeen:     timestamppb.New(lastSeen),
		ScanRecordId: e.asset.Scan.RecordID,
		ScannedAt:    stamped(e.asset.Scan.ScannedAt),
		AsOf:         timestamppb.New(e.asset.AsOf),
	}
}

func (e *evaluation) intelligenceBasis() *vulnerabilityv1.IntelligenceBasis {
	return &vulnerabilityv1.IntelligenceBasis{
		Source:   e.intelligence.Feed.Source,
		Feed:     e.intelligence.Feed.Name,
		SyncedAt: stamped(e.intelligence.Feed.SyncedAt),
		AsOf:     timestamppb.New(e.intelligence.AsOf),
	}
}

func (e *evaluation) done(scope vulnerabilityv1.Assessment_Scope, unassessable vulnerabilityv1.Unassessable) Evaluation {
	slices.SortStableFunc(e.findings, func(a, b *vulnerabilityv1.Finding) int {
		return cmp.Or(cmp.Compare(a.GetItemId(), b.GetItemId()), cmp.Compare(a.GetVulnerabilityId(), b.GetVulnerabilityId()))
	})
	assessed := &vulnerabilityv1.Assessment{
		SchemaVersion: SchemaVersion,
		TenantId:      e.asset.TenantID,
		AgentId:       e.asset.AgentID,
		Scope:         scope,
		Stale:         e.stale,
		Unassessable:  unassessable,
		Inventory:     &vulnerabilityv1.InventoryBasis{ScanRecordId: e.asset.Scan.RecordID, ScannedAt: stamped(e.asset.Scan.ScannedAt), AsOf: timestamppb.New(e.asset.AsOf)},
		Intelligence:  e.intelligenceBasis(),
		Open:          e.open,
		Closed:        e.closed,
		DecidedAt:     timestamppb.New(e.decidedAt),
	}
	for reason, packages := range e.unassessed {
		assessed.Unassessed = append(assessed.Unassessed, &vulnerabilityv1.Assessment_Unassessed{Reason: reason, Packages: packages})
	}
	slices.SortFunc(assessed.Unassessed, func(a, b *vulnerabilityv1.Assessment_Unassessed) int {
		return cmp.Compare(a.GetReason(), b.GetReason())
	})
	return Evaluation{Findings: e.findings, Assessment: assessed}
}

func unplaced(err error) vulnerabilityv1.Unassessable {
	switch {
	case errors.Is(err, vulnerability.ErrForeignManager):
		return vulnerabilityv1.Unassessable_UNASSESSABLE_FOREIGN_MANAGER
	case errors.Is(err, vulnerability.ErrUnnamedPackage):
		return vulnerabilityv1.Unassessable_UNASSESSABLE_UNNAMED_PACKAGE
	case errors.Is(err, vulnerability.ErrUnversionedPackage):
		return vulnerabilityv1.Unassessable_UNASSESSABLE_UNVERSIONED_PACKAGE
	case errors.Is(err, vulnerability.ErrUnsourcedVersion):
		return vulnerabilityv1.Unassessable_UNASSESSABLE_UNSOURCED_VERSION
	}
	return vulnerabilityv1.Unassessable_UNASSESSABLE_UNKNOWN_DISTRIBUTION
}

func opened(decided *vulnerabilityv1.Finding) bool {
	switch decided.GetState() {
	case vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, vulnerabilityv1.FindingState_FINDING_STATE_REINTRODUCED:
		return true
	case vulnerabilityv1.FindingState_FINDING_STATE_CANNOT_ASSESS:
		return decided.GetOpenedAt() != nil
	}
	return false
}

func closed(decided *vulnerabilityv1.Finding) bool {
	switch decided.GetState() {
	case vulnerabilityv1.FindingState_FINDING_STATE_FIXED, vulnerabilityv1.FindingState_FINDING_STATE_NOT_AFFECTED, vulnerabilityv1.FindingState_FINDING_STATE_REMOVED:
		return true
	}
	return false
}

func episodeOf(decided *vulnerabilityv1.Finding) *timestamppb.Timestamp {
	if opened(decided) {
		return decided.GetOpenedAt()
	}
	return nil
}

func stamped(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() {
		return nil
	}
	return timestamppb.New(at)
}

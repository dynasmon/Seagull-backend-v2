package advisorystore

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// An instant a record does not carry is the epoch rather than the year one,
// which the columns cannot hold. Every instant a record does carry is one the
// contract already bounded to what they can.
var epoch = time.Unix(0, 0).UTC()

// One version of one advisory. The version is the modification time the source
// gave it together with the rules the platform read it with, so a newer reading
// of the same version is a row of its own rather than one that replaces it.
type AdvisoryRow struct {
	Source            string
	AdvisoryID        string
	Modified          time.Time
	Normalization     uint32
	SchemaVersion     uint32
	Published         time.Time
	Withdrawn         time.Time
	Aliases           []string
	Upstream          []string
	Related           []string
	Summary           string
	Details           string
	SeverityTypes     []string
	SeverityScores    []string
	SeverityAssessors []string
	Affected          uint32
	Feed              string
	FeedVersion       string
	Location          string
	FetchedAt         time.Time
	Digest            string
	Format            string
}

// One package a version of an advisory affects, keyed by what a matcher looks
// it up by. Ranges and their events are parallel arrays: EventRanges says which
// range each event belongs to, and the order is the order the source wrote.
type AffectedRow struct {
	Ecosystem         string
	Package           string
	Source            string
	AdvisoryID        string
	Modified          time.Time
	Normalization     uint32
	Entry             uint32
	RangeTypes        []string
	EventRanges       []uint32
	EventKinds        []string
	EventVersions     []string
	Versions          []string
	SeverityTypes     []string
	SeverityScores    []string
	SeverityAssessors []string
	Withdrawn         time.Time
}

type SyncRow struct {
	Source       string
	Feed         string
	CheckedAt    time.Time
	Outcome      string
	SyncedAt     time.Time
	NewestListed time.Time
	FeedVersion  string
	Listed       uint32
	Held         uint32
	Published    uint32
	Refused      uint32
	Failure      string
}

type Projection struct {
	Advisories []AdvisoryRow
	Affected   []AffectedRow
	Syncs      []SyncRow
}

func (p *Projection) add(more Projection) {
	p.Advisories = append(p.Advisories, more.Advisories...)
	p.Affected = append(p.Affected, more.Affected...)
	p.Syncs = append(p.Syncs, more.Syncs...)
}

func (p Projection) empty() bool {
	return len(p.Advisories) == 0 && len(p.Affected) == 0 && len(p.Syncs) == 0
}

var carried = []string{
	"advisory.affected.ecosystem",
	"advisory.affected.name",
	"advisory.affected.ranges.events.fixed",
	"advisory.affected.ranges.events.introduced",
	"advisory.affected.ranges.events.last_affected",
	"advisory.affected.ranges.events.limit",
	"advisory.affected.ranges.type",
	"advisory.affected.severities.assessed_by",
	"advisory.affected.severities.score",
	"advisory.affected.severities.type",
	"advisory.affected.versions",
	"advisory.aliases",
	"advisory.details",
	"advisory.id",
	"advisory.modified",
	"advisory.provenance.digest",
	"advisory.provenance.feed",
	"advisory.provenance.feed_version",
	"advisory.provenance.fetched_at",
	"advisory.provenance.format",
	"advisory.provenance.location",
	"advisory.provenance.normalization",
	"advisory.published",
	"advisory.related",
	"advisory.schema_version",
	"advisory.severities.assessed_by",
	"advisory.severities.score",
	"advisory.severities.type",
	"advisory.source",
	"advisory.summary",
	"advisory.upstream",
	"advisory.withdrawn",
	"sync.checked_at",
	"sync.failure",
	"sync.feed",
	"sync.feed_version",
	"sync.held",
	"sync.listed",
	"sync.newest_listed",
	"sync.outcome",
	"sync.published",
	"sync.refused",
	"sync.source",
	"sync.synced_at",
}

func Project(record *vulnerabilityv1.Record) Projection {
	switch body := record.GetRecord().(type) {
	case *vulnerabilityv1.Record_Advisory:
		return projectAdvisory(body.Advisory)
	case *vulnerabilityv1.Record_Sync:
		return Projection{Syncs: []SyncRow{projectSync(body.Sync)}}
	default:
		return Projection{}
	}
}

func projectAdvisory(advisory *vulnerabilityv1.Advisory) Projection {
	provenance := advisory.GetProvenance()
	types, scores, assessors := rated(advisory.GetSeverities())
	version := AdvisoryRow{
		Source:            advisory.GetSource(),
		AdvisoryID:        advisory.GetId(),
		Modified:          instant(advisory.GetModified()),
		Normalization:     provenance.GetNormalization(),
		SchemaVersion:     advisory.GetSchemaVersion(),
		Published:         instant(advisory.GetPublished()),
		Withdrawn:         instant(advisory.GetWithdrawn()),
		Aliases:           listed(advisory.GetAliases()),
		Upstream:          listed(advisory.GetUpstream()),
		Related:           listed(advisory.GetRelated()),
		Summary:           advisory.GetSummary(),
		Details:           advisory.GetDetails(),
		SeverityTypes:     types,
		SeverityScores:    scores,
		SeverityAssessors: assessors,
		Affected:          uint32(len(advisory.GetAffected())),
		Feed:              provenance.GetFeed(),
		FeedVersion:       provenance.GetFeedVersion(),
		Location:          provenance.GetLocation(),
		FetchedAt:         instant(provenance.GetFetchedAt()),
		Digest:            provenance.GetDigest(),
		Format:            provenance.GetFormat(),
	}

	projected := Projection{Advisories: []AdvisoryRow{version}}
	for entry, affected := range advisory.GetAffected() {
		types, scores, assessors := rated(affected.GetSeverities())
		row := AffectedRow{
			Ecosystem:         affected.GetEcosystem(),
			Package:           affected.GetName(),
			Source:            version.Source,
			AdvisoryID:        version.AdvisoryID,
			Modified:          version.Modified,
			Normalization:     version.Normalization,
			Entry:             uint32(entry),
			RangeTypes:        []string{},
			EventRanges:       []uint32{},
			EventKinds:        []string{},
			EventVersions:     []string{},
			Versions:          listed(affected.GetVersions()),
			SeverityTypes:     types,
			SeverityScores:    scores,
			SeverityAssessors: assessors,
			Withdrawn:         version.Withdrawn,
		}
		for position, span := range affected.GetRanges() {
			row.RangeTypes = append(row.RangeTypes, named(span.GetType().String(), "TYPE_"))
			for _, boundary := range span.GetEvents() {
				kind, at := bound(boundary)
				row.EventRanges = append(row.EventRanges, uint32(position))
				row.EventKinds = append(row.EventKinds, kind)
				row.EventVersions = append(row.EventVersions, at)
			}
		}
		projected.Affected = append(projected.Affected, row)
	}
	return projected
}

func projectSync(sync *vulnerabilityv1.FeedSync) SyncRow {
	return SyncRow{
		Source:       sync.GetSource(),
		Feed:         sync.GetFeed(),
		CheckedAt:    instant(sync.GetCheckedAt()),
		Outcome:      named(sync.GetOutcome().String(), "OUTCOME_"),
		SyncedAt:     instant(sync.GetSyncedAt()),
		NewestListed: instant(sync.GetNewestListed()),
		FeedVersion:  sync.GetFeedVersion(),
		Listed:       sync.GetListed(),
		Held:         sync.GetHeld(),
		Published:    sync.GetPublished(),
		Refused:      sync.GetRefused(),
		Failure:      sync.GetFailure(),
	}
}

func rated(severities []*vulnerabilityv1.Severity) ([]string, []string, []string) {
	types, scores, assessors := []string{}, []string{}, []string{}
	for _, severity := range severities {
		types = append(types, named(severity.GetType().String(), "TYPE_"))
		scores = append(scores, severity.GetScore())
		assessors = append(assessors, severity.GetAssessedBy())
	}
	return types, scores, assessors
}

func bound(boundary *vulnerabilityv1.Event) (string, string) {
	switch set := boundary.GetBoundary().(type) {
	case *vulnerabilityv1.Event_Introduced:
		return "introduced", set.Introduced
	case *vulnerabilityv1.Event_Fixed:
		return "fixed", set.Fixed
	case *vulnerabilityv1.Event_LastAffected:
		return "last_affected", set.LastAffected
	case *vulnerabilityv1.Event_Limit:
		return "limit", set.Limit
	default:
		return "", ""
	}
}

func named(value, prefix string) string {
	trimmed := strings.TrimPrefix(value, prefix)
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

func listed(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func instant(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return epoch
	}
	return value.AsTime().UTC()
}

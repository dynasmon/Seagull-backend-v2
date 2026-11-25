package advisorystore

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// The inverse of projectAdvisory: a reader is handed the advisory the platform
// translated, never its rows. Entries are placed by the position they were
// written at, and a row whose parallel arrays disagree is refused rather than
// read back as an advisory that says less than the source did.
func Restore(version AdvisoryRow, affected []AffectedRow) (*vulnerabilityv1.Advisory, error) {
	restored := &vulnerabilityv1.Advisory{
		SchemaVersion: version.SchemaVersion,
		Source:        version.Source,
		Id:            version.AdvisoryID,
		Modified:      given(version.Modified),
		Published:     given(version.Published),
		Withdrawn:     given(version.Withdrawn),
		Aliases:       version.Aliases,
		Upstream:      version.Upstream,
		Related:       version.Related,
		Summary:       version.Summary,
		Details:       version.Details,
		Severities:    severities(version.SeverityTypes, version.SeverityScores, version.SeverityAssessors),
		Provenance: &vulnerabilityv1.Provenance{
			Feed:          version.Feed,
			FeedVersion:   version.FeedVersion,
			Location:      version.Location,
			FetchedAt:     given(version.FetchedAt),
			Digest:        version.Digest,
			Format:        version.Format,
			Normalization: version.Normalization,
		},
	}

	entries := slices.Clone(affected)
	slices.SortFunc(entries, func(a, b AffectedRow) int { return int(a.Entry) - int(b.Entry) })
	for _, row := range entries {
		entry := &vulnerabilityv1.Affected{
			Ecosystem:  row.Ecosystem,
			Name:       row.Package,
			Versions:   row.Versions,
			Severities: severities(row.SeverityTypes, row.SeverityScores, row.SeverityAssessors),
		}
		for _, spelled := range row.RangeTypes {
			entry.Ranges = append(entry.Ranges, &vulnerabilityv1.Range{
				Type: vulnerabilityv1.Range_Type(vulnerabilityv1.Range_Type_value["TYPE_"+strings.ToUpper(spelled)]),
			})
		}
		if len(row.EventRanges) != len(row.EventKinds) || len(row.EventKinds) != len(row.EventVersions) {
			return nil, fmt.Errorf("advisory %s names events of %d ranges, %d kinds and %d versions",
				version.AdvisoryID, len(row.EventRanges), len(row.EventKinds), len(row.EventVersions))
		}
		for index, position := range row.EventRanges {
			if int(position) >= len(entry.Ranges) {
				return nil, fmt.Errorf("advisory %s names an event of range %d among %d", version.AdvisoryID, position, len(entry.Ranges))
			}
			boundary, err := eventOf(row.EventKinds[index], row.EventVersions[index])
			if err != nil {
				return nil, fmt.Errorf("advisory %s: %w", version.AdvisoryID, err)
			}
			entry.Ranges[position].Events = append(entry.Ranges[position].Events, boundary)
		}
		restored.Affected = append(restored.Affected, entry)
	}
	return restored, nil
}

func eventOf(kind, version string) (*vulnerabilityv1.Event, error) {
	switch kind {
	case "introduced":
		return &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: version}}, nil
	case "fixed":
		return &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: version}}, nil
	case "last_affected":
		return &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_LastAffected{LastAffected: version}}, nil
	case "limit":
		return &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Limit{Limit: version}}, nil
	}
	return nil, fmt.Errorf("an event of kind %q", kind)
}

func severities(types, scores, assessors []string) []*vulnerabilityv1.Severity {
	rated := make([]*vulnerabilityv1.Severity, 0, len(types))
	for index, spelled := range types {
		if index >= len(scores) || index >= len(assessors) {
			break
		}
		rated = append(rated, &vulnerabilityv1.Severity{
			Type:       vulnerabilityv1.Severity_Type(vulnerabilityv1.Severity_Type_value["TYPE_"+strings.ToUpper(spelled)]),
			Score:      scores[index],
			AssessedBy: assessors[index],
		})
	}
	return rated
}

func given(at time.Time) *timestamppb.Timestamp {
	if !at.After(epoch) {
		return nil
	}
	return timestamppb.New(at)
}

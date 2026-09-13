package osv

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const (
	Source        = "osv"
	Normalization = 1

	// What the format says to assume of a record that declares no version.
	assumedFormat = "1.0.0"
)

type record struct {
	SchemaVersion string     `json:"schema_version"`
	ID            string     `json:"id"`
	Modified      string     `json:"modified"`
	Published     string     `json:"published"`
	Withdrawn     string     `json:"withdrawn"`
	Aliases       []string   `json:"aliases"`
	Upstream      []string   `json:"upstream"`
	Related       []string   `json:"related"`
	Summary       string     `json:"summary"`
	Details       string     `json:"details"`
	Severity      []severity `json:"severity"`
	Affected      []affected `json:"affected"`
}

type severity struct {
	Type   string `json:"type"`
	Score  string `json:"score"`
	Source string `json:"source"`
}

type affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Severity []severity     `json:"severity"`
	Ranges   []versionRange `json:"ranges"`
	Versions []string       `json:"versions"`
}

type versionRange struct {
	Type   string     `json:"type"`
	Events []boundary `json:"events"`
}

type boundary struct {
	Introduced   *string `json:"introduced"`
	Fixed        *string `json:"fixed"`
	LastAffected *string `json:"last_affected"`
	Limit        *string `json:"limit"`
}

var severityTypes = map[string]vulnerabilityv1.Severity_Type{
	"CVSS_V2": vulnerabilityv1.Severity_TYPE_CVSS_V2,
	"CVSS_V3": vulnerabilityv1.Severity_TYPE_CVSS_V3,
	"CVSS_V4": vulnerabilityv1.Severity_TYPE_CVSS_V4,
	"Ubuntu":  vulnerabilityv1.Severity_TYPE_UBUNTU,
}

var rangeTypes = map[string]vulnerabilityv1.Range_Type{
	"ECOSYSTEM": vulnerabilityv1.Range_TYPE_ECOSYSTEM,
	"SEMVER":    vulnerabilityv1.Range_TYPE_SEMVER,
}

func Translate(raw []byte) (*vulnerabilityv1.Advisory, error) {
	var read record
	if err := json.Unmarshal(raw, &read); err != nil {
		return nil, fmt.Errorf("the record is not OSV JSON: %w", err)
	}

	format := strings.TrimSpace(read.SchemaVersion)
	if format == "" {
		format = assumedFormat
	}
	if major, _, _ := strings.Cut(format, "."); major != "1" {
		return nil, fmt.Errorf("the record is OSV %s and this build reads OSV 1", format)
	}

	id := strings.TrimSpace(read.ID)
	if !vulnerability.Identifier(id) {
		return nil, fmt.Errorf("the record names itself %q, which is not an identifier", read.ID)
	}
	modified, err := instant("modified", read.Modified, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	published, err := instant("published", read.Published, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	withdrawn, err := instant("withdrawn", read.Withdrawn, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	entries, err := affectedEntries(read.Affected)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}

	return &vulnerabilityv1.Advisory{
		SchemaVersion: vulnerability.SchemaVersion,
		Source:        Source,
		Id:            id,
		Modified:      modified,
		Published:     published,
		Withdrawn:     withdrawn,
		Aliases:       names(read.Aliases, id),
		Upstream:      names(read.Upstream, id),
		Related:       names(read.Related, id),
		Summary:       fit(read.Summary, vulnerability.MaxSummaryLength),
		Details:       fit(read.Details, vulnerability.MaxDetailsLength),
		Severities:    severities(read.Severity),
		Affected:      entries,
		Provenance:    &vulnerabilityv1.Provenance{Format: "osv " + format, Normalization: Normalization},
	}, nil
}

// An entry in an ecosystem no asset can be placed in is left out rather than
// refused, and so is one whose ranges are all commits: neither states anything
// a package installed on an asset could be compared against, and the rest of
// the advisory still does.
func affectedEntries(listed []affected) ([]*vulnerabilityv1.Affected, error) {
	var kept []*vulnerabilityv1.Affected
	for index, entry := range listed {
		ecosystem, err := vulnerability.Ecosystem(strings.TrimSpace(entry.Package.Ecosystem))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(entry.Package.Name)
		if name == "" {
			return nil, fmt.Errorf("affected[%d] names no package in %s", index, ecosystem)
		}
		ranges, err := spans(entry.Ranges)
		if err != nil {
			return nil, fmt.Errorf("affected[%d].%w", index, err)
		}
		versions := trimmed(entry.Versions)
		if len(ranges) == 0 && len(versions) == 0 {
			continue
		}
		kept = append(kept, &vulnerabilityv1.Affected{
			Ecosystem:  ecosystem,
			Name:       name,
			Ranges:     ranges,
			Versions:   versions,
			Severities: severities(entry.Severity),
		})
	}
	return kept, nil
}

func spans(listed []versionRange) ([]*vulnerabilityv1.Range, error) {
	var kept []*vulnerabilityv1.Range
	for index, span := range listed {
		kind, readable := rangeTypes[strings.TrimSpace(span.Type)]
		if !readable {
			continue
		}
		events := make([]*vulnerabilityv1.Event, 0, len(span.Events))
		for position, bound := range span.Events {
			event, err := bound.event()
			if err != nil {
				return nil, fmt.Errorf("ranges[%d].events[%d] %w", index, position, err)
			}
			events = append(events, event)
		}
		kept = append(kept, &vulnerabilityv1.Range{Type: kind, Events: events})
	}
	return kept, nil
}

func (b boundary) event() (*vulnerabilityv1.Event, error) {
	var set []*vulnerabilityv1.Event
	if b.Introduced != nil {
		set = append(set, &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: strings.TrimSpace(*b.Introduced)}})
	}
	if b.Fixed != nil {
		set = append(set, &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: strings.TrimSpace(*b.Fixed)}})
	}
	if b.LastAffected != nil {
		set = append(set, &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_LastAffected{LastAffected: strings.TrimSpace(*b.LastAffected)}})
	}
	if b.Limit != nil {
		set = append(set, &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Limit{Limit: strings.TrimSpace(*b.Limit)}})
	}
	if len(set) != 1 {
		return nil, fmt.Errorf("sets %d boundaries and an event sets exactly one", len(set))
	}
	return set[0], nil
}

func severities(listed []severity) []*vulnerabilityv1.Severity {
	var kept []*vulnerabilityv1.Severity
	for _, rated := range listed {
		kind, readable := severityTypes[strings.TrimSpace(rated.Type)]
		score := strings.TrimSpace(rated.Score)
		if !readable || score == "" {
			continue
		}
		kept = append(kept, &vulnerabilityv1.Severity{Type: kind, Score: score, AssessedBy: strings.TrimSpace(rated.Source)})
		if len(kept) == vulnerability.MaxSeverities {
			break
		}
	}
	return kept
}

func names(listed []string, self string) []string {
	var kept []string
	for _, name := range listed {
		name = strings.TrimSpace(name)
		if upper := strings.ToUpper(name); strings.HasPrefix(upper, "CVE-") {
			name = upper
		}
		if name != self && vulnerability.Identifier(name) {
			kept = append(kept, name)
		}
	}
	slices.Sort(kept)
	return slices.Compact(kept)
}

func trimmed(listed []string) []string {
	var kept []string
	for _, value := range listed {
		if value = strings.TrimSpace(value); value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}

func instant(field, spelled string, required bool) (*timestamppb.Timestamp, error) {
	spelled = strings.TrimSpace(spelled)
	if spelled == "" {
		if required {
			return nil, fmt.Errorf("the record has no %s time", field)
		}
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, spelled)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s %q is not an RFC 3339 time", field, spelled)
	case parsed.IsZero() && required:
		return nil, fmt.Errorf("the record's %s time is the zero instant", field)
	case parsed.IsZero():
		return nil, nil
	}
	return timestamppb.New(parsed.UTC()), nil
}

// Prose is cut to fit rather than refused: it names nothing and decides
// nothing, and the whole of it stays at the location the advisory was read
// from. The cut never splits a character.
func fit(prose string, maximum int) string {
	prose = strings.TrimSpace(prose)
	if len(prose) <= maximum {
		return prose
	}
	cut := maximum
	for cut > 0 && !utf8.RuneStart(prose[cut]) {
		cut--
	}
	return prose[:cut]
}

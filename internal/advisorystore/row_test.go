package advisorystore

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const wellKnown = "google.protobuf."

var (
	modified = time.Date(2026, time.September, 12, 11, 0, 5, 986201214, time.UTC)
	fetched  = time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
)

func advisory() *vulnerabilityv1.Advisory {
	return &vulnerabilityv1.Advisory{
		SchemaVersion: 1,
		Source:        "osv",
		Id:            "DEBIAN-CVE-2024-58382",
		Modified:      timestamppb.New(modified),
		Published:     timestamppb.New(modified.Add(-72 * time.Hour)),
		Aliases:       []string{"GHSA-vp9c-fpxx-744v"},
		Upstream:      []string{"CVE-2024-58382"},
		Related:       []string{"DSA-6189-1"},
		Summary:       "php-league-commonmark - denial of service",
		Details:       "league/commonmark versions before 2.6.0 contain polynomial time complexity vulnerabilities",
		Severities: []*vulnerabilityv1.Severity{
			{Type: vulnerabilityv1.Severity_TYPE_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"},
			{Type: vulnerabilityv1.Severity_TYPE_UBUNTU, Score: "medium", AssessedBy: "SELF"},
		},
		Affected: []*vulnerabilityv1.Affected{
			{
				Ecosystem: "Debian:12",
				Name:      "php-league-commonmark",
				Ranges: []*vulnerabilityv1.Range{
					{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
						{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "0"}},
						{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: "2.6.0-1"}},
					}},
					{Type: vulnerabilityv1.Range_TYPE_SEMVER, Events: []*vulnerabilityv1.Event{
						{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "3.0.0"}},
						{Boundary: &vulnerabilityv1.Event_LastAffected{LastAffected: "3.1.0"}},
						{Boundary: &vulnerabilityv1.Event_Limit{Limit: "4.0.0"}},
					}},
				},
				Versions:   []string{"2.3.9-1"},
				Severities: []*vulnerabilityv1.Severity{{Type: vulnerabilityv1.Severity_TYPE_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", AssessedBy: "NVD"}},
			},
			{
				Ecosystem: "Debian:13",
				Name:      "php-league-commonmark",
				Ranges: []*vulnerabilityv1.Range{{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
					{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "0"}},
				}}},
			},
		},
		Provenance: &vulnerabilityv1.Provenance{
			Feed:          "Debian",
			FeedVersion:   `"CIKvrM3365YDEAE="`,
			Location:      "https://osv-vulnerabilities.storage.googleapis.com/Debian/DEBIAN-CVE-2024-58382.json",
			FetchedAt:     timestamppb.New(fetched),
			Digest:        strings.Repeat("ab", 32),
			Format:        "osv 1.9.0",
			Normalization: 1,
		},
	}
}

func sync() *vulnerabilityv1.FeedSync {
	return &vulnerabilityv1.FeedSync{
		Source:       "osv",
		Feed:         "Debian",
		FeedVersion:  `"CIKvrM3365YDEAE="`,
		Outcome:      vulnerabilityv1.FeedSync_OUTCOME_PARTIAL,
		CheckedAt:    timestamppb.New(fetched),
		NewestListed: timestamppb.New(modified),
		Listed:       66660,
		Held:         66659,
		Published:    12,
		Refused:      1,
		Failure:      "some advisories are still owed: osv.example answered 503",
	}
}

func advised(made *vulnerabilityv1.Advisory) *vulnerabilityv1.Record {
	return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Advisory{Advisory: made}}
}

func synced(made *vulnerabilityv1.FeedSync) *vulnerabilityv1.Record {
	return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Sync{Sync: made}}
}

// From the contract towards the store and never the other way: a feed cannot
// start saying something and have it quietly stop being kept.
func TestTheContractCannotGrowWithoutTheAdvisoryStoreNoticing(t *testing.T) {
	walked := leaves((&vulnerabilityv1.Record{}).ProtoReflect().Descriptor(), "")
	slices.Sort(walked)

	kept := slices.Clone(carried)
	slices.Sort(kept)

	for _, path := range walked {
		if !slices.Contains(kept, path) {
			t.Errorf("a record carries %s and the store does not keep it", path)
		}
	}
	for _, path := range kept {
		if !slices.Contains(walked, path) {
			t.Errorf("the store claims to keep %s and the contract has no such field", path)
		}
	}
}

func leaves(message protoreflect.MessageDescriptor, prefix string) []string {
	var paths []string
	fields := message.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		path := prefix + string(field.Name())
		if field.Kind() == protoreflect.MessageKind && !strings.HasPrefix(string(field.Message().FullName()), wellKnown) {
			paths = append(paths, leaves(field.Message(), path+".")...)
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func TestAnAdvisoryIsOneRowForTheVersionAndOneForEachPackageItAffects(t *testing.T) {
	projected := Project(advised(advisory()))
	if len(projected.Advisories) != 1 || len(projected.Affected) != 2 || len(projected.Syncs) != 0 {
		t.Fatalf("projected %d advisories, %d affected and %d syncs", len(projected.Advisories), len(projected.Affected), len(projected.Syncs))
	}

	version := projected.Advisories[0]
	switch {
	case version.Source != "osv" || version.AdvisoryID != "DEBIAN-CVE-2024-58382" || !version.Modified.Equal(modified) || version.Normalization != 1:
		t.Errorf("the version is named %s %s %v %d", version.Source, version.AdvisoryID, version.Modified, version.Normalization)
	case !version.Published.Equal(modified.Add(-72*time.Hour)) || !version.Withdrawn.Equal(epoch):
		t.Errorf("published %v and withdrawn %v", version.Published, version.Withdrawn)
	case !slices.Equal(version.Aliases, []string{"GHSA-vp9c-fpxx-744v"}) || !slices.Equal(version.Upstream, []string{"CVE-2024-58382"}) ||
		!slices.Equal(version.Related, []string{"DSA-6189-1"}):
		t.Errorf("names %v %v %v", version.Aliases, version.Upstream, version.Related)
	case !slices.Equal(version.SeverityTypes, []string{"cvss_v4", "ubuntu"}) || !slices.Equal(version.SeverityAssessors, []string{"", "SELF"}) ||
		version.SeverityScores[1] != "medium":
		t.Errorf("severities %v %v %v", version.SeverityTypes, version.SeverityScores, version.SeverityAssessors)
	case version.Affected != 2 || version.Feed != "Debian" || version.FeedVersion != `"CIKvrM3365YDEAE="` || version.Digest != strings.Repeat("ab", 32) ||
		version.Format != "osv 1.9.0" || !version.FetchedAt.Equal(fetched) || !strings.HasSuffix(version.Location, "/DEBIAN-CVE-2024-58382.json"):
		t.Errorf("provenance %+v", version)
	}

	first, second := projected.Affected[0], projected.Affected[1]
	if first.Ecosystem != "Debian:12" || first.Package != "php-league-commonmark" || first.Entry != 0 || second.Entry != 1 ||
		first.AdvisoryID != version.AdvisoryID || !first.Modified.Equal(modified) || first.Normalization != 1 || !first.Withdrawn.Equal(epoch) {
		t.Errorf("the affected rows are %+v and %+v", first, second)
	}
	if !slices.Equal(first.Versions, []string{"2.3.9-1"}) || !slices.Equal(first.SeverityTypes, []string{"cvss_v3"}) || first.SeverityAssessors[0] != "NVD" {
		t.Errorf("the first entry keeps versions %v and severities %v", first.Versions, first.SeverityTypes)
	}
}

func TestEveryRangeIsKeptWithItsEventsInTheOrderTheSourceWroteThem(t *testing.T) {
	entry := Project(advised(advisory())).Affected[0]

	if !slices.Equal(entry.RangeTypes, []string{"ecosystem", "semver"}) {
		t.Errorf("range types %v", entry.RangeTypes)
	}
	if !slices.Equal(entry.EventRanges, []uint32{0, 0, 1, 1, 1}) {
		t.Errorf("events belong to ranges %v", entry.EventRanges)
	}
	if !slices.Equal(entry.EventKinds, []string{"introduced", "fixed", "introduced", "last_affected", "limit"}) {
		t.Errorf("event kinds %v", entry.EventKinds)
	}
	if !slices.Equal(entry.EventVersions, []string{"0", "2.6.0-1", "3.0.0", "3.1.0", "4.0.0"}) {
		t.Errorf("event versions %v", entry.EventVersions)
	}
}

func TestAWithdrawnAdvisoryIsKeptAndEveryPackageItNamedSaysSo(t *testing.T) {
	withdrawn := advisory()
	withdrawn.Withdrawn = timestamppb.New(fetched)

	projected := Project(advised(withdrawn))
	if !projected.Advisories[0].Withdrawn.Equal(fetched) {
		t.Errorf("the version was withdrawn at %v", projected.Advisories[0].Withdrawn)
	}
	for _, entry := range projected.Affected {
		if !entry.Withdrawn.Equal(fetched) {
			t.Errorf("%s still reads as current", entry.Ecosystem)
		}
	}
}

func TestAFeedSyncIsOneRow(t *testing.T) {
	projected := Project(synced(sync()))
	if len(projected.Syncs) != 1 || len(projected.Advisories) != 0 || len(projected.Affected) != 0 {
		t.Fatalf("projected %d syncs", len(projected.Syncs))
	}
	row := projected.Syncs[0]
	if row.Source != "osv" || row.Feed != "Debian" || row.Outcome != "partial" || !row.CheckedAt.Equal(fetched) ||
		!row.SyncedAt.Equal(epoch) || !row.NewestListed.Equal(modified) || row.Listed != 66660 || row.Held != 66659 ||
		row.Published != 12 || row.Refused != 1 || row.Failure == "" || row.FeedVersion != `"CIKvrM3365YDEAE="` {
		t.Errorf("the sync is %+v", row)
	}
}

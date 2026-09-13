package osv

import (
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const debianRecord = `{
  "schema_version": "1.9.0",
  "id": "DEBIAN-CVE-2024-58382",
  "published": "2026-09-09T14:17:10.327Z",
  "modified": "2026-09-12T11:00:05.986201214Z",
  "upstream": ["CVE-2024-58382"],
  "details": "league/commonmark versions before 2.6.0 contain polynomial time complexity vulnerabilities in Markdown parsing.",
  "affected": [
    {
      "package": {"name": "php-league-commonmark", "ecosystem": "Debian:12", "purl": "pkg:deb/debian/php-league-commonmark?arch=source&distro=bookworm"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
      "versions": ["2.3.9-1", "2.3.9-1+deb12u1"],
      "ecosystem_specific": {"urgency": "not yet assigned"},
      "database_specific": {"source": "https://storage.googleapis.com/debian-osv/debian-cve-osv/DEBIAN-CVE-2024-58382.json"}
    },
    {
      "package": {"name": "php-league-commonmark", "ecosystem": "Debian:13", "purl": "pkg:deb/debian/php-league-commonmark?arch=source&distro=trixie"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.6.0-1"}]}]
    }
  ],
  "references": [{"type": "ADVISORY", "url": "https://security-tracker.debian.org/tracker/CVE-2024-58382"}],
  "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}]
}`

const ubuntuRecord = `{
  "schema_version": "1.9.0",
  "id": "UBUNTU-CVE-2025-29769",
  "published": "2025-04-07T20:15:00Z",
  "modified": "2026-09-12T19:00:05.029622990Z",
  "upstream": ["CVE-2025-29769"],
  "severity": [
    {"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", "source": "NVD"},
    {"type": "Ubuntu", "score": "medium"}
  ],
  "affected": [
    {
      "package": {"name": "vips", "ecosystem": "Ubuntu:22.04:LTS", "purl": "pkg:deb/ubuntu/vips?arch=source&distro=jammy"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
      "versions": ["8.12.1-1"],
      "ecosystem_specific": {"binaries": [{"binary_name": "libvips42", "binary_version": "8.12.1-1"}]}
    },
    {
      "package": {"name": "vips", "ecosystem": "Ubuntu:Pro:22.04:LTS", "purl": "pkg:deb/ubuntu/vips?arch=source&distro=esm-apps%2Fjammy"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.12.1-1ubuntu0.1~esm1"}]}]
    },
    {
      "package": {"name": "vips", "ecosystem": "Ubuntu:25.10", "purl": "pkg:deb/ubuntu/vips?arch=source&distro=questing"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
      "versions": ["8.16.1-1"]
    }
  ]
}`

const almaRecord = `{
  "schema_version": "1.9.0",
  "id": "ALSA-2026:66392",
  "summary": "Moderate: apr-util security update",
  "modified": "2026-09-11T17:54:44Z",
  "published": "2026-09-11T00:00:00Z",
  "related": ["CVE-2026-34501", "CVE-2025-49506", "CVE-2026-32327"],
  "affected": [
    {
      "package": {"ecosystem": "AlmaLinux:10", "name": "apr-util", "purl": "pkg:rpm/almalinux/apr-util"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.6.3-23.el10_2.1"}]}]
    },
    {
      "package": {"ecosystem": "AlmaLinux:10", "name": "apr-util-devel", "purl": "pkg:rpm/almalinux/apr-util-devel"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.6.3-23.el10_2.1"}]}]
    }
  ]
}`

const rockyRecord = `{
  "schema_version": "1.9.0",
  "id": "RLSA-2026:66203",
  "summary": "Important: python3.12-lxml security update",
  "modified": "2026-09-12T03:30:10.1Z",
  "upstream": ["CVE-2026-49825"],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"}],
  "affected": [
    {
      "package": {"ecosystem": "Rocky Linux:9", "name": "python3.12-lxml", "purl": "pkg:rpm/rocky-linux/python3.12-lxml?distro=rocky-linux-9&epoch=0"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:4.9.3-2.el9_8.1"}]}]
    }
  ],
  "database_specific": {"source_advisory": "RHSA-2026:66203"}
}`

const alpineRecord = `{
  "schema_version": "1.9.0",
  "id": "ALPINE-CVE-2026-80255",
  "modified": "2026-09-12T08:30:03.756478307Z",
  "upstream": ["CVE-2026-80255"],
  "affected": [
    {
      "package": {"name": "curl", "ecosystem": "Alpine:v3.23", "purl": "pkg:apk/alpine/curl?arch=source"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "8.13.0"}, {"fixed": "8.22.0-r0"}]}]
    }
  ]
}`

func stamp(t *testing.T, raw string) *vulnerabilityv1.Advisory {
	t.Helper()
	translated, err := Translate([]byte(raw))
	if err != nil {
		t.Fatalf("the record was refused: %v", err)
	}
	return translated
}

func at(t *testing.T, spelled string) *timestamppb.Timestamp {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, spelled)
	if err != nil {
		t.Fatalf("parse %q: %v", spelled, err)
	}
	return timestamppb.New(parsed)
}

func span(events ...*vulnerabilityv1.Event) []*vulnerabilityv1.Range {
	return []*vulnerabilityv1.Range{{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: events}}
}

func introduced(version string) *vulnerabilityv1.Event {
	return &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: version}}
}

func fixed(version string) *vulnerabilityv1.Event {
	return &vulnerabilityv1.Event{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: version}}
}

func read(format string) *vulnerabilityv1.Provenance {
	return &vulnerabilityv1.Provenance{Format: format, Normalization: Normalization}
}

func same(t *testing.T, got, want *vulnerabilityv1.Advisory) {
	t.Helper()
	if !proto.Equal(got, want) {
		t.Errorf("the translation differs:\n got: %s\nwant: %s", prototext.Format(got), prototext.Format(want))
	}
}

func TestADebianRecordIsKeptWithTheReleasesItScopesTo(t *testing.T) {
	same(t, stamp(t, debianRecord), &vulnerabilityv1.Advisory{
		SchemaVersion: vulnerability.SchemaVersion,
		Source:        "osv",
		Id:            "DEBIAN-CVE-2024-58382",
		Modified:      at(t, "2026-09-12T11:00:05.986201214Z"),
		Published:     at(t, "2026-09-09T14:17:10.327Z"),
		Upstream:      []string{"CVE-2024-58382"},
		Details:       "league/commonmark versions before 2.6.0 contain polynomial time complexity vulnerabilities in Markdown parsing.",
		Severities: []*vulnerabilityv1.Severity{{
			Type:  vulnerabilityv1.Severity_TYPE_CVSS_V4,
			Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
		}},
		Affected: []*vulnerabilityv1.Affected{
			{
				Ecosystem: "Debian:12",
				Name:      "php-league-commonmark",
				Ranges:    span(introduced("0")),
				Versions:  []string{"2.3.9-1", "2.3.9-1+deb12u1"},
			},
			{
				Ecosystem: "Debian:13",
				Name:      "php-league-commonmark",
				Ranges:    span(introduced("0"), fixed("2.6.0-1")),
			},
		},
		Provenance: read("osv 1.9.0"),
	})
}

func TestAnUbuntuRecordKeepsTheStandardReleasesAndLeavesTheProPocketBehind(t *testing.T) {
	same(t, stamp(t, ubuntuRecord), &vulnerabilityv1.Advisory{
		SchemaVersion: vulnerability.SchemaVersion,
		Source:        "osv",
		Id:            "UBUNTU-CVE-2025-29769",
		Modified:      at(t, "2026-09-12T19:00:05.029622990Z"),
		Published:     at(t, "2025-04-07T20:15:00Z"),
		Upstream:      []string{"CVE-2025-29769"},
		Severities: []*vulnerabilityv1.Severity{
			{Type: vulnerabilityv1.Severity_TYPE_CVSS_V4, Score: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
			{Type: vulnerabilityv1.Severity_TYPE_CVSS_V3, Score: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", AssessedBy: "NVD"},
			{Type: vulnerabilityv1.Severity_TYPE_UBUNTU, Score: "medium"},
		},
		Affected: []*vulnerabilityv1.Affected{
			{Ecosystem: "Ubuntu:22.04:LTS", Name: "vips", Ranges: span(introduced("0")), Versions: []string{"8.12.1-1"}},
			{Ecosystem: "Ubuntu:25.10", Name: "vips", Ranges: span(introduced("0")), Versions: []string{"8.16.1-1"}},
		},
		Provenance: read("osv 1.9.0"),
	})
}

func TestAnAlmaLinuxRecordNamesTheBinariesItsAdvisoryLists(t *testing.T) {
	same(t, stamp(t, almaRecord), &vulnerabilityv1.Advisory{
		SchemaVersion: vulnerability.SchemaVersion,
		Source:        "osv",
		Id:            "ALSA-2026:66392",
		Modified:      at(t, "2026-09-11T17:54:44Z"),
		Published:     at(t, "2026-09-11T00:00:00Z"),
		Related:       []string{"CVE-2025-49506", "CVE-2026-32327", "CVE-2026-34501"},
		Summary:       "Moderate: apr-util security update",
		Affected: []*vulnerabilityv1.Affected{
			{Ecosystem: "AlmaLinux:10", Name: "apr-util", Ranges: span(introduced("0"), fixed("1.6.3-23.el10_2.1"))},
			{Ecosystem: "AlmaLinux:10", Name: "apr-util-devel", Ranges: span(introduced("0"), fixed("1.6.3-23.el10_2.1"))},
		},
		Provenance: read("osv 1.9.0"),
	})
}

func TestARockyRecordKeepsTheVersionItWasFixedInAsWritten(t *testing.T) {
	same(t, stamp(t, rockyRecord), &vulnerabilityv1.Advisory{
		SchemaVersion: vulnerability.SchemaVersion,
		Source:        "osv",
		Id:            "RLSA-2026:66203",
		Modified:      at(t, "2026-09-12T03:30:10.1Z"),
		Upstream:      []string{"CVE-2026-49825"},
		Summary:       "Important: python3.12-lxml security update",
		Severities: []*vulnerabilityv1.Severity{{
			Type:  vulnerabilityv1.Severity_TYPE_CVSS_V3,
			Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
		}},
		Affected: []*vulnerabilityv1.Affected{
			{Ecosystem: "Rocky Linux:9", Name: "python3.12-lxml", Ranges: span(introduced("0"), fixed("0:4.9.3-2.el9_8.1"))},
		},
		Provenance: read("osv 1.9.0"),
	})
}

func TestAnAlpineRecordIsScopedToItsReleaseBranch(t *testing.T) {
	same(t, stamp(t, alpineRecord), &vulnerabilityv1.Advisory{
		SchemaVersion: vulnerability.SchemaVersion,
		Source:        "osv",
		Id:            "ALPINE-CVE-2026-80255",
		Modified:      at(t, "2026-09-12T08:30:03.756478307Z"),
		Upstream:      []string{"CVE-2026-80255"},
		Affected: []*vulnerabilityv1.Affected{
			{Ecosystem: "Alpine:v3.23", Name: "curl", Ranges: span(introduced("8.13.0"), fixed("8.22.0-r0"))},
		},
		Provenance: read("osv 1.9.0"),
	})
}

func TestEveryTranslationIsAnAdvisoryOnceItsProvenanceIsWritten(t *testing.T) {
	for _, raw := range []string{debianRecord, ubuntuRecord, almaRecord, rockyRecord, alpineRecord, languageRecord, withdrawnRecord} {
		translated := stamp(t, raw)
		provenance := translated.GetProvenance()
		provenance.Feed = "Debian"
		provenance.FeedVersion = `"CIKvrM3365YDEAE="`
		provenance.Location = "https://osv-vulnerabilities.storage.googleapis.com/Debian/" + translated.GetId() + ".json"
		provenance.FetchedAt = timestamppb.Now()
		provenance.Digest = strings.Repeat("0f", 32)
		if err := vulnerability.Validate(translated); err != nil {
			t.Errorf("%s is not an advisory: %v", translated.GetId(), err)
		}
	}
}

const languageRecord = `{
  "schema_version": "1.7.3",
  "id": "GHSA-vp9c-fpxx-744v",
  "modified": "2026-08-01T10:00:00Z",
  "aliases": ["cve-2024-1111", " CVE-2024-1111 ", "PYSEC-2024-7", "", "not an identifier", "GHSA-vp9c-fpxx-744v"],
  "severity": [{"type": "CVSS_V5", "score": "CVSS:5.0/AV:N"}, {"type": "CVSS_V3", "score": ""}],
  "affected": [
    {
      "package": {"ecosystem": "PyPI", "name": "requests"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]
    },
    {
      "package": {"ecosystem": "Debian:12", "name": "python-requests"},
      "ranges": [{"type": "GIT", "repo": "https://github.com/psf/requests", "events": [{"introduced": "0"}, {"fixed": "a1b2c3"}]}]
    }
  ]
}`

func TestWhatNoAssetCanBeComparedAgainstIsLeftOutAndTheRestIsKept(t *testing.T) {
	translated := stamp(t, languageRecord)
	if len(translated.GetAffected()) != 0 {
		t.Errorf("kept %v, want no entry: one names PyPI and the other states its range in commits", translated.GetAffected())
	}
	if len(translated.GetSeverities()) != 0 {
		t.Errorf("kept severities %v, want none: one names a scale no build reads and the other names no score", translated.GetSeverities())
	}
	if got, want := translated.GetAliases(), []string{"CVE-2024-1111", "PYSEC-2024-7"}; !slices.Equal(got, want) {
		t.Errorf("aliases %q, want %q", got, want)
	}
	if got := translated.GetProvenance().GetFormat(); got != "osv 1.7.3" {
		t.Errorf("the format read is %q", got)
	}
}

const withdrawnRecord = `{
  "id": "ALPINE-CVE-2021-0001",
  "modified": "2026-01-02T03:04:05Z",
  "withdrawn": "2026-01-02T03:04:05Z",
  "summary": "Withdrawn: not a vulnerability in Alpine",
  "affected": []
}`

func TestAWithdrawnRecordIsKeptAndSaysWhenItWasWithdrawn(t *testing.T) {
	translated := stamp(t, withdrawnRecord)
	if !proto.Equal(translated.GetWithdrawn(), at(t, "2026-01-02T03:04:05Z")) {
		t.Errorf("withdrawn at %v", translated.GetWithdrawn())
	}
	if got := translated.GetProvenance().GetFormat(); got != "osv 1.0.0" {
		t.Errorf("a record that declares no schema version was read as %q, which is not the version the format says to assume", got)
	}
}

// Debian's converter writes the zero time of the language it is written in
// where it knows no publication date, and the platform cannot hold the year one.
func TestAPublicationTimeLeftAtTheZeroInstantIsNoTimeAtAll(t *testing.T) {
	translated := stamp(t, `{"id": "DEBIAN-CVE-2014-9586", "modified": "2026-09-01T15:03:25.117873893Z",
		"published": "0001-01-01T00:00:00Z", "withdrawn": "0001-01-01T00:00:00Z"}`)
	if translated.GetPublished() != nil || translated.GetWithdrawn() != nil {
		t.Errorf("published %v and withdrawn %v, want neither", translated.GetPublished(), translated.GetWithdrawn())
	}
	if _, err := Translate([]byte(`{"id": "DEBIAN-CVE-2014-9586", "modified": "0001-01-01T00:00:00Z"}`)); err == nil {
		t.Error("a record whose modification time is the zero instant was translated, and a version needs a time")
	}
}

func TestProseIsCutToFitAndStaysText(t *testing.T) {
	long := "a" + strings.Repeat("é", vulnerability.MaxDetailsLength)
	translated := stamp(t, `{"id": "DSA-6189-1", "modified": "2026-03-31T22:31:29Z", "summary": "`+
		strings.Repeat("s", vulnerability.MaxSummaryLength+10)+`", "details": "`+long+`"}`)

	details := translated.GetDetails()
	if len(details) > vulnerability.MaxDetailsLength || !utf8.ValidString(details) || !strings.HasPrefix(long, details) {
		t.Errorf("details kept %d bytes, valid text %v", len(details), utf8.ValidString(details))
	}
	if len(details) < vulnerability.MaxDetailsLength-utf8.UTFMax {
		t.Errorf("details kept %d bytes, far below the ceiling", len(details))
	}
	if got := len(translated.GetSummary()); got != vulnerability.MaxSummaryLength {
		t.Errorf("summary kept %d bytes", got)
	}
}

func TestARecordThatCannotBeReadIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":                    `{"id": "DSA-1"`,
		"a newer major format":        `{"schema_version": "2.0.0", "id": "DSA-6189-1", "modified": "2026-03-31T22:31:29Z"}`,
		"no modification time":        `{"id": "DSA-6189-1"}`,
		"a time that is not rfc3339":  `{"id": "DSA-6189-1", "modified": "2026-03-31 22:31:29"}`,
		"a published time unreadable": `{"id": "DSA-6189-1", "modified": "2026-03-31T22:31:29Z", "published": "yesterday"}`,
		"an id that is not one":       `{"id": "DSA 6189", "modified": "2026-03-31T22:31:29Z"}`,
		"an event with two bounds": `{"id": "DSA-6189-1", "modified": "2026-03-31T22:31:29Z", "affected": [{"package": {"ecosystem": "Debian:12", "name": "libpng1.6"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "1.6.39-2+deb12u4"}]}]}]}`,
		"an event with no bound": `{"id": "DSA-6189-1", "modified": "2026-03-31T22:31:29Z", "affected": [{"package": {"ecosystem": "Debian:12", "name": "libpng1.6"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"patched": "1.6.39-2+deb12u4"}]}]}]}`,
		"a package with no name": `{"id": "DSA-6189-1", "modified": "2026-03-31T22:31:29Z", "affected": [{"package": {"ecosystem": "Debian:12", "name": " "},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}`,
	} {
		if translated, err := Translate([]byte(raw)); err == nil {
			t.Errorf("%s: translated to %v, want it refused", name, translated)
		}
	}
}

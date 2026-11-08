package finding

import (
	"cmp"
	"slices"
	"strings"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// The version of the rules below. A rating names it, because which of the
// ratings an advisory carries is shown is a choice the platform made.
const RatingPolicy = 1

// A finding is named by a CVE wherever its advisories name one, so a CVE that
// a DSA, a DLA and the CVE's own record all tell is one finding; an advisory
// naming no CVE is a vulnerability of its own.
func vulnerabilitiesOf(advisory *Advisory) []string {
	var named []string
	for _, name := range append(slices.Clone(advisory.Aliases), advisory.Upstream...) {
		if strings.HasPrefix(name, "CVE-") {
			named = append(named, name)
		}
	}
	if len(named) == 0 {
		return []string{advisory.ID}
	}
	slices.Sort(named)
	return slices.Compact(named)
}

func cite(citations []citation) []*vulnerabilityv1.Citation {
	var cited []*vulnerabilityv1.Citation
	for _, cite := range citations {
		cited = append(cited, &vulnerabilityv1.Citation{
			Source:        cite.advisory.Source,
			AdvisoryId:    cite.advisory.ID,
			Modified:      stamped(cite.advisory.Modified),
			Normalization: cite.advisory.Normalization,
		})
	}
	slices.SortFunc(cited, func(a, b *vulnerabilityv1.Citation) int {
		return cmp.Or(cmp.Compare(a.GetSource(), b.GetSource()), cmp.Compare(a.GetAdvisoryId(), b.GetAdvisoryId()))
	})
	return slices.CompactFunc(cited, func(a, b *vulnerabilityv1.Citation) bool {
		return a.GetSource() == b.GetSource() && a.GetAdvisoryId() == b.GetAdvisoryId()
	})
}

// The most specific rating any citing advisory asserted, never a score made
// here: one given for this package before one given for the whole advisory,
// one the publishing database made before another assessor's, the
// distribution's own scale before CVSS and a newer CVSS before an older, then
// advisories in the order of their names and ratings in the order written.
func rate(citations []citation) *vulnerabilityv1.Rating {
	type candidate struct {
		severity *vulnerabilityv1.Severity
		advisory *Advisory
		specific bool
		written  int
	}
	var candidates []candidate
	for _, cite := range citations {
		for index, severity := range cite.entry.GetSeverities() {
			candidates = append(candidates, candidate{severity: severity, advisory: cite.advisory, specific: true, written: index})
		}
		for index, severity := range cite.advisory.Severities {
			candidates = append(candidates, candidate{severity: severity, advisory: cite.advisory, written: index})
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	scale := map[vulnerabilityv1.Severity_Type]int{
		vulnerabilityv1.Severity_TYPE_UBUNTU:  0,
		vulnerabilityv1.Severity_TYPE_CVSS_V4: 1,
		vulnerabilityv1.Severity_TYPE_CVSS_V3: 2,
		vulnerabilityv1.Severity_TYPE_CVSS_V2: 3,
	}
	chosen := slices.MinFunc(candidates, func(a, b candidate) int {
		return cmp.Or(
			compareTrueFirst(a.specific, b.specific),
			compareTrueFirst(a.severity.GetAssessedBy() == "", b.severity.GetAssessedBy() == ""),
			cmp.Compare(scale[a.severity.GetType()], scale[b.severity.GetType()]),
			cmp.Compare(a.advisory.Source, b.advisory.Source),
			cmp.Compare(a.advisory.ID, b.advisory.ID),
			cmp.Compare(a.written, b.written),
		)
	})
	return &vulnerabilityv1.Rating{
		Severity:        chosen.severity,
		Source:          chosen.advisory.Source,
		AdvisoryId:      chosen.advisory.ID,
		PackageSpecific: chosen.specific,
		Policy:          RatingPolicy,
	}
}

func compareTrueFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
}

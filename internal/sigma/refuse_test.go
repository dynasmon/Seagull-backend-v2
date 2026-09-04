package sigma_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/sigma"
)

func refused(t *testing.T, name, document, expected string) {
	t.Helper()

	rule, err := sigma.Translate("rule.yml", []byte(document))
	if err == nil {
		t.Errorf("%s was translated into %q rather than refused", name, rule.ID)
		return
	}
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("%s was refused with %q, which does not say %q", name, err, expected)
	}
}

// Nothing here is translated into something that runs and matches less than the
// rule says. v1 turned a selection it could not read into an inert placeholder,
// so an unsupported rule imported cleanly, compiled, and quietly found nothing.
func TestASigmaConstructThisBuildCannotSayIsRefused(t *testing.T) {
	for name, expected := range map[string]struct{ written, says string }{
		"a field outside the taxonomy": {
			"    selection:\n        CommandLine: whoami\n    condition: selection",
			`names "CommandLine", which this build does not translate`,
		},
		"a regular expression": {
			"    selection:\n        Protocol|re: ss.*\n    condition: selection",
			"matches a regular expression",
		},
		"a network range": {
			"    selection:\n        SourceIp|cidr: 10.0.0.0/8\n    condition: selection",
			"matches a network range",
		},
		"a comparison between two fields": {
			"    selection:\n        Protocol|fieldref: ServiceName\n    condition: selection",
			"compares one field against another",
		},
		"an encoded value": {
			"    selection:\n        Protocol|base64: ssh\n    condition: selection",
			"compares against an encoding of the value",
		},
		"a modifier that is not one": {
			"    selection:\n        Protocol|sideways: ssh\n    condition: selection",
			"is not a Sigma modifier this build reads",
		},
		"a wildcard in the middle of a value": {
			"    selection:\n        Protocol: 's*h'\n    condition: selection",
			"a wildcard is read only at the start or the end of a value",
		},
		"a single-character wildcard": {
			"    selection:\n        Protocol: 'ss?'\n    condition: selection",
			"a wildcard is read only at the start or the end of a value",
		},
		"a value that is only a wildcard": {
			"    selection:\n        Protocol: '*'\n    condition: selection",
			"which every event carrying the field answers",
		},
		"a wildcard beside a modifier that says the same thing": {
			"    selection:\n        Protocol|contains: '*ss*'\n    condition: selection",
			"which says how to match twice",
		},
		"a comparison without case against a field the canonical form keeps the case of": {
			"    selection:\n        TargetUserName: root\n    condition: selection",
			"compares without case, and the canonical form keeps the case of authentication.user.name",
		},
		"a comparison with case against a field the canonical form folded": {
			"    selection:\n        Protocol|cased: ssh\n    condition: selection",
			"the canonical form folded authentication.service.protocol",
		},
		"a comparison with case against an address": {
			"    selection:\n        SourceIp|cased: 10.0.0.5\n    condition: selection",
			"is rewritten to one text form for every address",
		},
		"a keyword searched for anywhere in a record": {
			"    keywords:\n        - Failed password\n    condition: keywords",
			"a keyword searches a whole record",
		},
		"a choice the contract does not declare": {
			"    selection:\n        Outcome: banana\n    condition: selection",
			"the contract declares",
		},
		"text where the field holds a number": {
			"    selection:\n        SourcePort: hello\n    condition: selection",
			"holds a number and is compared against",
		},
		"a selection the condition never names": {
			"    selection:\n        Outcome: failure\n    filter:\n        Protocol: ssh\n    condition: selection",
			"the condition never names it",
		},
		"a condition naming a selection that is not there": {
			"    selection:\n        Outcome: failure\n    condition: whatever",
			`names "whatever", which is not one of`,
		},
		"a condition counting how many terms held": {
			"    selection_a:\n        Outcome: failure\n    selection_b:\n        Protocol: ssh\n    condition: 2 of selection_*",
			"how many of several terms held is not a question the rule language asks",
		},
		"a bracket that is never closed": {
			"    selection:\n        Outcome: failure\n    condition: (selection",
			"opens a bracket it never closes",
		},
		"a count of distinct values": {
			"    selection:\n        Outcome: failure\n    timeframe: 5m\n    condition: selection | count(TargetUserName) by SourceIp > 5",
			"counts distinct",
		},
		"an aggregation that is not a count": {
			"    selection:\n        Outcome: failure\n    timeframe: 5m\n    condition: selection | sum(SourcePort) by SourceIp > 5",
			"this translates count() alone",
		},
		"a threshold nothing can reach by counting up": {
			"    selection:\n        Outcome: failure\n    timeframe: 5m\n    condition: selection | count() by SourceIp < 5",
			"fewer than a threshold is not something a window can answer",
		},
		"a count grouped by a field outside the taxonomy": {
			"    selection:\n        Outcome: failure\n    timeframe: 5m\n    condition: selection | count() by CommandLine > 5",
			`groups its count by "CommandLine", which this build does not translate`,
		},
		"a count grouped by more than one field": {
			"    selection:\n        Outcome: failure\n    timeframe: 5m\n    condition: selection | count() by SourceIp, SourcePort > 5",
			"groups its count by more than one field",
		},
		"every value of a list equalling one field at once": {
			"    selection:\n        Protocol|all:\n            - ssh\n            - rdp\n    condition: selection",
			"which nothing satisfies",
		},
		"a text modifier on a field that holds a number": {
			"    selection:\n        SourcePort|contains: 22\n    condition: selection",
			"holds number, and contains does not ask that",
		},
		"a condition carrying something after it": {
			"    selection:\n        Outcome: failure\n    condition: selection extra",
			"does not read as a condition",
		},
		"a count with no window to count inside": {
			"    selection:\n        Outcome: failure\n    condition: selection | count() by SourceIp > 5",
			"a count is how many events happened inside a window",
		},
		"a window scoping nothing": {
			"    selection:\n        Outcome: failure\n    timeframe: 5m\n    condition: selection",
			"there is no window for it to scope",
		},
		"a window written in a unit this build does not read": {
			"    selection:\n        Outcome: failure\n    timeframe: 5w\n    condition: selection | count() > 5",
			"a window reads like 30s, 15m, 2h or 1d",
		},
	} {
		refused(t, name, document(expected.written), expected.says)
	}
}

func TestASigmaDocumentThisBuildCannotReadIsRefused(t *testing.T) {
	const body = `
logsource:
    product: linux
    service: sshd
detection:
    selection:
        Outcome: failure
    condition: selection
level: medium
`

	for name, expected := range map[string]struct{ written, says string }{
		"a log source this platform collects nothing for": {
			"title: A rule\ndescription: Something.\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        Outcome: failure\n    condition: selection\nlevel: medium\n",
			"this build translates a Sigma rule written for",
		},
		"a rule that says how loud it is nowhere": {
			"title: A rule\ndescription: Something." + strings.TrimSuffix(body, "level: medium\n"),
			"how loud a detection is is a decision rather than a default",
		},
		"a rule its own catalogue has withdrawn": {
			"title: A rule\ndescription: Something.\nstatus: deprecated" + body,
			"importing a rule its own catalogue has withdrawn",
		},
		"a correlation, which names rules rather than events": {
			"title: A rule\ndescription: Something.\ncorrelation:\n    type: event_count" + body,
			"is a Sigma correlation",
		},
		"a document joined to another one": {
			"title: A rule\ndescription: Something.\naction: global" + body,
			"joins several documents into one rule",
		},
		"a key that is not part of a Sigma rule": {
			"title: A rule\ndescription: Something.\nsideways: true" + body,
			"is not part of a Sigma rule this build reads",
		},
		"a file holding more than one rule": {
			"title: A rule\ndescription: Something." + body + "---\ntitle: Another\n",
			"holds more than one document",
		},
		"a rule with no title to be called by": {
			"description: Something." + body,
			"is missing, and it is what the rule is called here",
		},
		"a title nothing can be filed under": {
			"title: '2026'\ndescription: Something." + body,
			"which is not one a rule can carry",
		},
		"a rule that describes itself nowhere": {
			"title: A rule" + body,
			"description is missing",
		},
		"a tag outside the vocabulary a rule is filed in": {
			"title: A rule\ndescription: Something.\ntags:\n    - cve.2021-44228" + body,
			"must be lowercase words joined by . or _",
		},
	} {
		refused(t, name, expected.written, expected.says)
	}
}

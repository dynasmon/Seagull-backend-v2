package sigma_test

import (
	"testing"
)

func document(body string) string {
	return `title: A rule
description: Something the platform should say so.
logsource:
    product: linux
    service: sshd
detection:
` + body + `
level: medium
`
}

func TestWhatASigmaValueBecomes(t *testing.T) {
	for name, expected := range map[string]struct{ written, becomes string }{
		"a choice named the way a person says it": {
			"    selection:\n        Outcome: failure\n    condition: selection",
			"authentication.outcome equals failure",
		},
		"a value on a field the canonical form folds": {
			"    selection:\n        Protocol: SSH\n    condition: selection",
			`authentication.service.protocol equals "ssh"`,
		},
		"a value on a field the canonical form keeps the case of": {
			"    selection:\n        TargetUserName|cased: Root\n    condition: selection",
			`authentication.user.name equals "Root"`,
		},
		"an address in the text form the canonical stage puts it in": {
			"    selection:\n        SourceIp: '::ffff:10.0.0.5'\n    condition: selection",
			`authentication.network.source.ip equals "10.0.0.5"`,
		},
		"a number": {
			"    selection:\n        SourcePort: 22\n    condition: selection",
			"authentication.network.source.port equals 22",
		},
		"a number compared with a modifier": {
			"    selection:\n        SourcePort|gte: 1024\n    condition: selection",
			"authentication.network.source.port at_least 1024",
		},
		"a list of plain values, which is one question with many answers": {
			"    selection:\n        Outcome:\n            - failure\n            - success\n    condition: selection",
			"authentication.outcome one_of [failure, success]",
		},
		"a wildcard at the end": {
			"    selection:\n        Protocol: 'ss*'\n    condition: selection",
			`authentication.service.protocol starts_with "ss"`,
		},
		"a wildcard at the start": {
			"    selection:\n        Protocol: '*sh'\n    condition: selection",
			`authentication.service.protocol ends_with "sh"`,
		},
		"a wildcard at both ends": {
			"    selection:\n        Protocol: '*s*'\n    condition: selection",
			`authentication.service.protocol contains "s"`,
		},
		"a wildcard escaped, which is a value and not a pattern": {
			`    selection:` + "\n" + `        Protocol: 'a\*b'` + "\n    condition: selection",
			`authentication.service.protocol equals "a*b"`,
		},
		"every value of a list holding at once": {
			"    selection:\n        Protocol|contains|all:\n            - s\n            - h\n    condition: selection",
			`(authentication.service.protocol contains "s" and authentication.service.protocol contains "h")`,
		},
		"any value of a list holding": {
			"    selection:\n        Protocol|contains:\n            - s\n            - h\n    condition: selection",
			`(authentication.service.protocol contains "s" or authentication.service.protocol contains "h")`,
		},
		"a field written with nothing after it, which says the event does not carry it": {
			"    selection:\n        Computer: null\n    condition: selection",
			"not origin.host.hostname present",
		},
		"a field asked whether it is there at all": {
			"    selection:\n        Computer|exists: true\n    condition: selection",
			"origin.host.hostname present",
		},
		"a field asked whether it is not there": {
			"    selection:\n        Computer|exists: false\n    condition: selection",
			"not origin.host.hostname present",
		},
		"a list of maps, which is any one of them holding": {
			"    selection:\n        - Outcome: failure\n        - Outcome: success\n    condition: selection",
			"(authentication.outcome equals failure or authentication.outcome equals success)",
		},
	} {
		if got := compiled(t, document(expected.written)).String(); got != expected.becomes {
			t.Errorf("%s became %s", name, got)
		}
	}
}

func TestWhatASigmaConditionBecomes(t *testing.T) {
	const two = "    selection:\n        Outcome: failure\n    other:\n        Protocol: ssh\n"

	for name, expected := range map[string]struct{ written, becomes string }{
		"two selections that both hold": {
			two + "    condition: selection and other",
			`(authentication.outcome equals failure and authentication.service.protocol equals "ssh")`,
		},
		"either of two selections": {
			two + "    condition: selection or other",
			`(authentication.outcome equals failure or authentication.service.protocol equals "ssh")`,
		},
		"one selection and not the other": {
			two + "    condition: selection and not other",
			`(authentication.outcome equals failure and not authentication.service.protocol equals "ssh")`,
		},
		"brackets deciding what binds first": {
			two + "    condition: (selection or other) and selection",
			`((authentication.outcome equals failure or authentication.service.protocol equals "ssh") and authentication.outcome equals failure)`,
		},
		"all of them": {
			two + "    condition: all of them",
			`(authentication.outcome equals failure and authentication.service.protocol equals "ssh")`,
		},
		"one of them": {
			two + "    condition: 1 of them",
			`(authentication.outcome equals failure or authentication.service.protocol equals "ssh")`,
		},
		"one of a pattern": {
			"    selection_a:\n        Outcome: failure\n    selection_b:\n        Protocol: ssh\n    condition: 1 of selection_*",
			`(authentication.outcome equals failure or authentication.service.protocol equals "ssh")`,
		},
		"all of a pattern": {
			"    selection_a:\n        Outcome: failure\n    selection_b:\n        Protocol: ssh\n    condition: all of selection_*",
			`(authentication.outcome equals failure and authentication.service.protocol equals "ssh")`,
		},
	} {
		if got := compiled(t, document(expected.written)).String(); got != expected.becomes {
			t.Errorf("%s became %s", name, got)
		}
	}
}

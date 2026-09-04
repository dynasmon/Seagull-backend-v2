package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/sigma"
)

const supported = `title: Repeated failed SSH passwords from one address
id: 7c2b91d4-1f0a-4c33-8a71-5e9d2a6b0f12
status: experimental
description: Twenty password authentications over SSH failed for one address inside a minute.
references:
    - https://attack.mitre.org/techniques/T1110/001/
tags:
    - attack.credential_access
logsource:
    product: linux
    service: sshd
detection:
    selection:
        Outcome: failure
        Protocol: SSH
    filter:
        SourceIp|startswith: '127.'
    timeframe: 1m
    condition: selection and not filter | count() by SourceIp > 19
falsepositives:
    - A service account retrying a stale credential in a loop
level: high
`

const unsupported = `title: A command line nothing here carries
description: Something.
logsource:
    product: linux
    service: sshd
detection:
    selection:
        CommandLine: whoami
    condition: selection
level: low
`

func written(t *testing.T, documents map[string]string) string {
	t.Helper()

	input := t.TempDir()
	for name, document := range documents {
		if err := os.WriteFile(filepath.Join(input, name), []byte(document), 0o644); err != nil {
			t.Fatalf("the Sigma rule could not be written: %v", err)
		}
	}
	return input
}

// The acceptance the card asks for, end to end: what the translator produces is
// read, validated and compiled by the reader every rule this estate writes goes
// through, and nothing about it is a second way into the engine.
func TestATranslatedRuleIsReadBackByTheRuleFileReader(t *testing.T) {
	output := filepath.Join(t.TempDir(), "imported.yml")

	if err := run(written(t, map[string]string{"repeated.yml": supported}), output, true); err != nil {
		t.Fatalf("the import was refused: %v", err)
	}
	document, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("the import wrote nothing: %v", err)
	}

	programs, err := rulefile.Read(fstest.MapFS{"imported.yml": {Data: document}})
	if err != nil {
		t.Fatalf("the rule file the import wrote was refused: %v", err)
	}
	if len(programs) != 1 {
		t.Fatalf("the import wrote %d rules", len(programs))
	}

	translated, err := sigma.Translate("repeated.yml", []byte(supported))
	if err != nil {
		t.Fatalf("the Sigma rule was refused: %v", err)
	}
	if got := programs[0].Rule(); !reflect.DeepEqual(got, translated) {
		t.Errorf("the rule read back is\n%+v\nrather than\n%+v", got, translated)
	}
}

// An imported rule ships when somebody has written down what it should find,
// and not before: the harness names it as untested, and the suite that holds the
// shipped ruleset to its cases fails on exactly that.
func TestATranslatedRuleShipsWithNothingHoldingItToAnything(t *testing.T) {
	output := filepath.Join(t.TempDir(), "imported.yml")

	if err := run(written(t, map[string]string{"repeated.yml": supported}), output, true); err != nil {
		t.Fatalf("the import was refused: %v", err)
	}
	document, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("the import wrote nothing: %v", err)
	}

	report, err := rulefile.Check(fstest.MapFS{"imported.yml": {Data: document}})
	if err != nil {
		t.Fatalf("the rule file the import wrote was refused: %v", err)
	}
	if len(report.Untested) != 1 || report.Untested[0] != detection.ID("repeated_failed_ssh_passwords_from_one_address") {
		t.Errorf("the harness reports %v as untested", report.Untested)
	}
}

func TestAnImportKeepsWhatTranslatesAndSaysWhatDidNot(t *testing.T) {
	input := written(t, map[string]string{"repeated.yml": supported, "command.yml": unsupported})
	output := filepath.Join(t.TempDir(), "imported.yml")

	if err := run(input, output, true); err == nil {
		t.Error("a document that could not be translated was imported anyway under -strict")
	}
	if err := run(input, output, false); err != nil {
		t.Fatalf("the rules that do translate were not imported: %v", err)
	}

	programs, err := rulefile.Read(os.DirFS(filepath.Dir(output)))
	if err != nil {
		t.Fatalf("the rule file the import wrote was refused: %v", err)
	}
	if len(programs) != 1 {
		t.Errorf("the import wrote %d rules from one document it could read and one it could not", len(programs))
	}
}

func TestAnImportThatTranslatesNothingWritesNothing(t *testing.T) {
	output := filepath.Join(t.TempDir(), "imported.yml")

	if err := run(written(t, map[string]string{"command.yml": unsupported}), output, false); err == nil {
		t.Error("an import that translated nothing was reported as an import")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Error("an import that translated nothing wrote a rule file")
	}
}

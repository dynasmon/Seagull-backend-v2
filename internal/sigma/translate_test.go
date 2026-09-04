package sigma_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/sigma"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const written = `title: A failed SSH password
id: 4b6a3a1e-6d61-4d0f-9f39-2b3f1b7c4a01
status: experimental
description: A password authentication over SSH failed for a session.
author: Somebody
date: 2026/09/04
references:
    - https://attack.mitre.org/techniques/T1110/001/
tags:
    - attack.credential_access
    - attack.t1110.001
falsepositives:
    - An administrator mistyping a password
    - A service account retrying a stale credential
logsource:
    product: linux
    service: sshd
detection:
    selection:
        Outcome: failure
        Protocol: SSH
    condition: selection
level: high
`

func translated(t *testing.T, document string) detection.Rule {
	t.Helper()

	rule, err := sigma.Translate("rule.yml", []byte(document))
	if err != nil {
		t.Fatalf("the Sigma rule was refused: %v", err)
	}
	return rule
}

func compiled(t *testing.T, document string) *detection.Program {
	t.Helper()

	program, err := detection.Compile(translated(t, document))
	if err != nil {
		t.Fatalf("the translated rule did not compile: %v", err)
	}
	return program
}

func TestASupportedSigmaRuleBecomesARuleThePlatformRuns(t *testing.T) {
	rule := translated(t, written)

	switch {
	case rule.ID != "a_failed_ssh_password":
		t.Errorf("the rule is filed under %q", rule.ID)
	case rule.Revision != 1:
		t.Errorf("the rule is revision %d", rule.Revision)
	case rule.Name != "A failed SSH password":
		t.Errorf("the rule is called %q", rule.Name)
	case rule.Class != eventv1.EventClass_EVENT_CLASS_AUTHENTICATION:
		t.Errorf("the rule reads %v", rule.Class)
	case rule.Severity != detection.High:
		t.Errorf("the rule is %q", rule.Severity)
	}
	if got := compiled(t, written).String(); got != `(authentication.outcome equals failure and authentication.service.protocol equals "ssh")` {
		t.Errorf("the rule became %s", got)
	}
}

// A rule this estate has never seen hold against its own telemetry does not
// detect anything until somebody decides it should, and the harness reports it
// as untested until somebody writes the cases that say what it finds.
func TestATranslatedRuleArrivesAsADraft(t *testing.T) {
	rule := translated(t, written)

	if rule.Status != detection.Draft {
		t.Errorf("a translated rule stands as %q", rule.Status)
	}
	if rule.Status.Runs() {
		t.Error("a translated rule is evaluated before anybody has held it to anything")
	}
}

func TestATranslatedRuleSaysWhereItCameFrom(t *testing.T) {
	rule := translated(t, written)

	if rule.Source.Catalogue != sigma.Catalogue {
		t.Errorf("the rule came from %q", rule.Source.Catalogue)
	}
	if rule.Source.Identifier != "4b6a3a1e-6d61-4d0f-9f39-2b3f1b7c4a01" {
		t.Errorf("the rule was called %q where it came from", rule.Source.Identifier)
	}
}

func TestARuleWithoutAnIdentifierIsTracedByItsTitle(t *testing.T) {
	rule := translated(t, strings.ReplaceAll(written, "id: 4b6a3a1e-6d61-4d0f-9f39-2b3f1b7c4a01\n", ""))

	if rule.Source.Identifier != "A failed SSH password" {
		t.Errorf("the rule was called %q where it came from", rule.Source.Identifier)
	}
}

// A technique needs a tactic, an identifier and a name, and Sigma carries the
// first two: v1 answered the third from a table of thirteen technique names it
// maintained by hand, which is a catalogue that goes stale in silence. The tags
// survive, so a later build that carries ATT&CK can fill the technique from them.
func TestTheMetadataThatSurvivesTranslation(t *testing.T) {
	rule := translated(t, written)

	if rule.Description != "A password authentication over SSH failed for a session." {
		t.Errorf("the rule describes itself as %q", rule.Description)
	}
	if got, want := strings.Join(rule.Tags, " "), "attack.credential_access attack.t1110.001"; got != want {
		t.Errorf("the rule is tagged %q", got)
	}
	if len(rule.References) != 1 || rule.References[0] != "https://attack.mitre.org/techniques/T1110/001/" {
		t.Errorf("the rule cites %v", rule.References)
	}
	if got := rule.FalsePositives; got != "An administrator mistyping a password; A service account retrying a stale credential" {
		t.Errorf("the rule warns of %q", got)
	}
	if rule.Technique != (detection.Technique{}) {
		t.Errorf("the rule attributes itself to %+v, and Sigma carries no technique name", rule.Technique)
	}
}

func TestEveryLevelBecomesASeverity(t *testing.T) {
	for level, severity := range map[string]detection.Severity{
		"informational": detection.Low,
		"low":           detection.Low,
		"medium":        detection.Medium,
		"high":          detection.High,
		"critical":      detection.Critical,
	} {
		rule := translated(t, strings.ReplaceAll(written, "level: high", "level: "+level))
		if rule.Severity != severity {
			t.Errorf("a %s Sigma rule is %q here", level, rule.Severity)
		}
	}
}

const counting = `title: Repeated failed SSH passwords from one address
id: 7c2b91d4-1f0a-4c33-8a71-5e9d2a6b0f12
description: Twenty password authentications over SSH failed for one address inside a minute.
logsource:
    product: linux
    service: auth
detection:
    selection:
        Outcome: failure
    timeframe: 1m
    condition: selection | count() by SourceIp > 19
level: high
`

// Sigma writes a threshold as a comparison and this platform writes it as a
// floor, so `> 19` is twenty. v1 discarded the comparison and imported every
// rule with a threshold of one, which turns a rule that wanted twenty events
// into one that fires on the first.
func TestACountedSigmaRuleKeepsTheThresholdItAsksFor(t *testing.T) {
	rule := translated(t, counting)

	switch {
	case !rule.Count.Counts():
		t.Fatal("the rule counts nothing")
	case rule.Count.AtLeast != 20:
		t.Errorf("the rule counts to %d", rule.Count.AtLeast)
	case rule.Count.Within != time.Minute:
		t.Errorf("the rule counts inside %s", rule.Count.Within)
	case len(rule.Count.GroupBy) != 1 || rule.Count.GroupBy[0] != "authentication.network.source.ip":
		t.Errorf("the rule counts by %v", rule.Count.GroupBy)
	}

	inclusive := translated(t, strings.ReplaceAll(counting, "> 19", ">= 20"))
	if inclusive.Count.AtLeast != 20 {
		t.Errorf("a count written >= 20 counts to %d", inclusive.Count.AtLeast)
	}
}

package alert_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func keyed(parts ...alert.Part) alert.Fold {
	return alert.Fold{Keyed: parts, Window: 15 * time.Minute}
}

func tuned(t *testing.T, suppressions ...alert.Suppression) *alert.Tuning {
	t.Helper()
	tuning, err := alert.NewTuning(keyed(alert.PartRule, alert.PartAgent), nil, suppressions)
	if err != nil {
		t.Fatalf("compile the tuning: %v", err)
	}
	return tuning
}

func TestTheKeyFoldsWhatItNamesAndSplitsWhatItDoesNot(t *testing.T) {
	first := decided()
	second := decided()
	second.DetectionId = "a-different-detection"
	second.Evidence = []*detectionv1.Evidence{{Field: "authentication.source.ip", Held: "198.51.100.9"}}
	first.Evidence = []*detectionv1.Evidence{{Field: "authentication.source.ip", Held: "203.0.113.10"}}

	byAgent := []alert.Part{alert.PartRule, alert.PartAgent}
	if alert.CorrelationKey(first, byAgent) != alert.CorrelationKey(second, byAgent) {
		t.Error("two detections from one agent and one rule did not share a key")
	}

	bySource := []alert.Part{alert.PartRule, alert.PartAgent, alert.Part("evidence:authentication.source.ip")}
	if alert.CorrelationKey(first, bySource) == alert.CorrelationKey(second, bySource) {
		t.Error("two different sources shared a key that names the source")
	}
}

func TestAKeyNeverFoldsAcrossATenantOrARule(t *testing.T) {
	here := decided()
	elsewhere := decided()
	elsewhere.Origin = &eventv1.Origin{TenantId: "another-tenant", AgentId: "dev-agent-01"}

	byAgent := []alert.Part{alert.PartRule, alert.PartAgent}
	if alert.CorrelationKey(here, byAgent) == alert.CorrelationKey(elsewhere, byAgent) {
		t.Fatal("two tenants shared a correlation key")
	}

	other := decided()
	other.Rule = &detectionv1.Rule{Id: "some.other.rule", Revision: 1}
	if alert.CorrelationKey(here, byAgent) == alert.CorrelationKey(other, byAgent) {
		t.Fatal("two rules shared a correlation key")
	}
}

func TestAnAbsentEvidenceFieldIsNotTheSameAsAnEmptyOne(t *testing.T) {
	absent := decided()
	absent.Evidence = []*detectionv1.Evidence{{Field: "authentication.source.ip", Absent: true}}
	empty := decided()
	empty.Evidence = []*detectionv1.Evidence{{Field: "authentication.source.ip", Held: ""}}

	parts := []alert.Part{alert.PartRule, alert.Part("evidence:authentication.source.ip")}
	if alert.CorrelationKey(absent, parts) == alert.CorrelationKey(empty, parts) {
		t.Error("a field the event did not carry keyed the same as one it carried empty")
	}
}

func TestAKeyThatDoesNotNameTheRuleIsRefused(t *testing.T) {
	_, err := alert.NewTuning(keyed(alert.PartAgent), nil, nil)
	if !errors.Is(err, alert.ErrUnkeyed) {
		t.Fatalf("a key without the rule compiled with %v", err)
	}

	_, err = alert.NewTuning(keyed(alert.PartRule), map[string]alert.Fold{"r": keyed(alert.PartAgent)}, nil)
	if !errors.Is(err, alert.ErrUnkeyed) {
		t.Fatalf("a per-rule key without the rule compiled with %v", err)
	}
}

func TestASuppressionSaysWhyAndSelectsSomething(t *testing.T) {
	_, err := alert.NewTuning(keyed(alert.PartRule), nil, []alert.Suppression{{Rule: "r"}})
	if !errors.Is(err, alert.ErrNoReason) {
		t.Errorf("a suppression with no reason compiled with %v", err)
	}

	_, err = alert.NewTuning(keyed(alert.PartRule), nil, []alert.Suppression{{Reason: "because"}})
	if !errors.Is(err, alert.ErrNoSelection) {
		t.Errorf("a suppression selecting nothing compiled with %v", err)
	}
}

func TestASuppressionMatchesOnTheVocabularyTheKeyUses(t *testing.T) {
	made := decided()
	made.Evidence = []*detectionv1.Evidence{{Field: "authentication.source.ip", Held: "203.0.113.10"}}
	now := instant(raisedAt)

	tuning := tuned(t, alert.Suppression{
		Rule:   "ssh_password_failure_from_outside",
		When:   alert.Selector{alert.PartAgent: {"dev-agent-01"}},
		Reason: "our own credentialed scanner",
	})
	if _, hidden := tuning.Suppressed(made, now); !hidden {
		t.Fatal("a matching suppression did not hide the detection")
	}

	elsewhere := decided()
	elsewhere.Origin = &eventv1.Origin{TenantId: "acme", AgentId: "some-other-agent"}
	if _, hidden := tuning.Suppressed(elsewhere, now); hidden {
		t.Error("a suppression matched an agent it does not name")
	}

	bySource := tuned(t, alert.Suppression{
		When:   alert.Selector{alert.Part("evidence:authentication.source.ip"): {"203.0.113.10", "203.0.113.11"}},
		Reason: "our own scanner range",
	})
	if _, hidden := bySource.Suppressed(made, now); !hidden {
		t.Error("a suppression naming one of two values did not match")
	}
}

func TestASuppressionStopsHidingActivityWhenItExpires(t *testing.T) {
	made := decided()
	expiry := instant("2026-09-01T00:00:00Z")

	tuning := tuned(t, alert.Suppression{
		Rule:   "ssh_password_failure_from_outside",
		When:   alert.Selector{alert.PartAgent: {"dev-agent-01"}},
		Reason: "while the migration runs",
		Until:  expiry,
	})

	if _, hidden := tuning.Suppressed(made, expiry.Add(-time.Second)); !hidden {
		t.Error("a suppression did not apply a second before it expires")
	}
	if _, hidden := tuning.Suppressed(made, expiry); hidden {
		t.Error("a suppression still applied at the instant it expires")
	}
	if _, hidden := tuning.Suppressed(made, expiry.Add(time.Hour)); hidden {
		t.Error("an expired suppression is still hiding activity")
	}
}

func TestATuningIsNamedByWhatIsInIt(t *testing.T) {
	one := tuned(t, alert.Suppression{Rule: "r", Reason: "because"})
	same := tuned(t, alert.Suppression{Rule: "r", Reason: "because"})
	if one.ID() != same.ID() {
		t.Error("two identical documents compiled to different ids")
	}

	different := tuned(t, alert.Suppression{Rule: "r", Reason: "a different reason"})
	if one.ID() == different.ID() {
		t.Error("changing a reason did not change the id")
	}

	windowed, err := alert.NewTuning(
		alert.Fold{Keyed: []alert.Part{alert.PartRule, alert.PartAgent}, Window: time.Hour},
		nil, []alert.Suppression{{Rule: "r", Reason: "because"}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if one.ID() == windowed.ID() {
		t.Error("changing the window did not change the id")
	}
}

func TestAPerRuleFoldOverridesTheDefaultAndNothingElseDoes(t *testing.T) {
	tuning, err := alert.NewTuning(
		alert.Fold{Keyed: []alert.Part{alert.PartRule, alert.PartAgent}, Window: 15 * time.Minute},
		map[string]alert.Fold{"noisy.rule": {Keyed: []alert.Part{alert.PartRule}, Window: time.Hour, Cooldown: 30 * time.Minute}},
		nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if fold := tuning.Fold("noisy.rule"); fold.Window != time.Hour || fold.Cooldown != 30*time.Minute {
		t.Errorf("the declared rule folds on %s / %s", fold.Window, fold.Cooldown)
	}
	if fold := tuning.Fold("anything.else"); fold.Window != 15*time.Minute || fold.Cooldown != 0 {
		t.Errorf("an undeclared rule folds on %s / %s", fold.Window, fold.Cooldown)
	}
}

func TestEveryWindowIsMeasuredInEventTimeSoAReplayDecidesTheSame(t *testing.T) {
	made := decided()
	tuning := tuned(t)

	early, err := alert.Consider(made, tuning, instant(raisedAt))
	if err != nil {
		t.Fatalf("consider: %v", err)
	}
	late, err := alert.Consider(made, tuning, instant("2026-09-15T04:00:00Z"))
	if err != nil {
		t.Fatalf("consider a week later: %v", err)
	}

	if !early.At.Equal(late.At) {
		t.Errorf("the same detection was placed at %s and then at %s", early.At, late.At)
	}
	if !early.At.Equal(made.GetEventTime().AsTime()) {
		t.Errorf("the window is measured from %s and not from the event time", early.At)
	}
	if early.Key != late.Key {
		t.Error("the same detection produced two correlation keys")
	}
	if early.Alert.GetOccurrences() != 1 {
		t.Errorf("a fresh candidate carries %d occurrences", early.Alert.GetOccurrences())
	}
}

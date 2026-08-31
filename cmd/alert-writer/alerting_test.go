package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertfile"
)

func shipped(t *testing.T) *alert.Tuning {
	t.Helper()

	tuning, err := alertfile.Tuning(os.DirFS(filepath.Join("..", "..", "deploy")), "alerting.yml")
	if err != nil {
		t.Fatalf("read the shipped alerting document: %v", err)
	}
	return tuning
}

func TestTheShippedAlertingDocumentCompiles(t *testing.T) {
	tuning := shipped(t)

	if tuning.ID() == "" {
		t.Fatal("the shipped document compiled to nothing")
	}
	if fold := tuning.Fold("anything.undeclared"); fold.Window != 15*time.Minute || fold.Cooldown != 0 {
		t.Errorf("an undeclared rule folds on %s / %s", fold.Window, fold.Cooldown)
	}
}

// The rule the development stack ships is the one an operator sees fire, so the
// document has to key it by something the rule actually reads.
func TestTheShippedDocumentKeysTheShippedRuleBySource(t *testing.T) {
	fold := shipped(t).Fold("ssh.failed_password_from_outside")

	if fold.Window != time.Hour || fold.Cooldown != 30*time.Minute {
		t.Errorf("it folds on %s / %s", fold.Window, fold.Cooldown)
	}
	source := alert.Part(alert.EvidencePrefix + "authentication.source.ip")
	for _, part := range []alert.Part{alert.PartRule, alert.PartAgent, source} {
		if !contains(fold.Keyed, part) {
			t.Errorf("the key does not name %s", part)
		}
	}
}

func contains(keyed []alert.Part, part alert.Part) bool {
	for _, held := range keyed {
		if held == part {
			return true
		}
	}
	return false
}

func TestEverySuppressionTheShippedDocumentCarriesSaysWhy(t *testing.T) {
	if shipped(t).Suppressions() != 0 {
		t.Error("the development document ships a suppression; an estate adds its own")
	}
}

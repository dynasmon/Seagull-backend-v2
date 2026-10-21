package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	source := alert.Part(alert.EvidencePrefix + "authentication.network.source.ip")
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

func TestADocumentKeyingOnAFieldNobodyDeclaresStopsTheWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerting.yml")
	written := "schema_version: 1\nrules:\n  - id: ssh.failed_password_from_outside\n    key: [rule, agent, \"evidence:authentication.source.ip\"]\n"
	if err := os.WriteFile(path, []byte(written), 0o600); err != nil {
		t.Fatalf("write the document: %v", err)
	}

	tuning, err := alerting(path)
	if err == nil {
		t.Fatalf("the writer would start on tuning %s", tuning.ID())
	}
	if !errors.Is(err, alert.ErrUndeclaredField) {
		t.Errorf("the writer was stopped for another reason: %v", err)
	}
	for _, said := range []string{"alerting.yml:4:", "rules[0].key[2]", "evidence:authentication.source.ip"} {
		if !strings.Contains(err.Error(), said) {
			t.Errorf("the refusal does not say %s: %v", said, err)
		}
	}
}

func TestEverySuppressionTheShippedDocumentCarriesSaysWhy(t *testing.T) {
	if shipped(t).Suppressions() != 0 {
		t.Error("the development document ships a suppression; an estate adds its own")
	}
}

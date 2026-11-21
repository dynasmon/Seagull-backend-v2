package agentfinding_test

import (
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestAFindingIsNamedByItsTenantAgentKindAndEpisode(t *testing.T) {
	silence := agentv1.Finding_KIND_SILENCE
	named := agentfinding.ID("default", "web-01", silence, "boot", "41")
	if named != agentfinding.ID("default", "web-01", silence, "boot", "41") {
		t.Fatal("the same episode was named twice differently")
	}
	if len(named) != agentfinding.IDLength {
		t.Errorf("a finding is named in %d characters, want %d", len(named), agentfinding.IDLength)
	}
	for name, other := range map[string]string{
		"another tenant":  agentfinding.ID("globex", "web-01", silence, "boot", "41"),
		"another agent":   agentfinding.ID("default", "web-02", silence, "boot", "41"),
		"another kind":    agentfinding.ID("default", "web-01", agentv1.Finding_KIND_SHARED_IDENTITY, "boot", "41"),
		"another episode": agentfinding.ID("default", "web-01", silence, "boot", "42"),
		"a moved border":  agentfinding.ID("default", "web-01", silence, "boot4", "1"),
		"a joined part":   agentfinding.ID("default", "web-01", silence, "boot41"),
	} {
		if other == named {
			t.Errorf("%s names the same finding", name)
		}
	}
}

func TestTheNamesOfAFindingAreTheContractsAndNothingElse(t *testing.T) {
	if got := agentfinding.KindName(agentv1.Finding_KIND_COPIED_INSTALLATION); got != "copied_installation" {
		t.Errorf("a copied installation is named %q", got)
	}
	if got := agentfinding.StateName(agentv1.Finding_STATE_OPEN); got != "open" {
		t.Errorf("an open finding is named %q", got)
	}
	if got := agentfinding.ClosureName(agentv1.Finding_CLOSURE_NOT_ADMITTED); got != "not_admitted" {
		t.Errorf("a closure by the registry is named %q", got)
	}
	for name, got := range map[string]string{
		"kind":    agentfinding.KindName(agentv1.Finding_Kind(99)),
		"state":   agentfinding.StateName(agentv1.Finding_State(99)),
		"closure": agentfinding.ClosureName(agentv1.Finding_Closure(99)),
	} {
		if got != "unknown" {
			t.Errorf("an undeclared %s is named %q", name, got)
		}
	}
	want := []agentv1.Finding_Kind{
		agentv1.Finding_KIND_SILENCE, agentv1.Finding_KIND_COPIED_INSTALLATION,
		agentv1.Finding_KIND_SHARED_IDENTITY, agentv1.Finding_KIND_REPLACED_CERTIFICATE,
	}
	if got := agentfinding.Kinds(); !slices.Equal(got, want) {
		t.Errorf("the kinds are %v, want %v", got, want)
	}
}

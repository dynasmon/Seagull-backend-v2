package agent_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func admission(agentID string, state agent.State, revision uint64) *agentv1.Admission {
	return admissionIn(agentID, "acme", state, revision)
}

func admissionIn(agentID, tenant string, state agent.State, revision uint64) *agentv1.Admission {
	return &agentv1.Admission{AgentId: agentID, TenantId: tenant, State: state.Wire(), Revision: revision}
}

func admitted(roster *agent.Roster, agentID string) bool {
	_, admits := roster.Tenant(agentID)
	return admits
}

func TestAnAgentTheRegistryNeverNamedIsNotAdmitted(t *testing.T) {
	roster := agent.NewRoster()
	if tenant, admits := roster.Tenant("web-01"); admits || tenant != "" {
		t.Fatalf("an agent nobody registered is admitted into %q", tenant)
	}
	if roster.Knows("web-01") || roster.Refused() != 0 {
		t.Fatal("an empty roster claims to know an agent")
	}
}

func TestAnAgentIsAdmittedIntoTheTenantItWasRegisteredIn(t *testing.T) {
	roster := agent.NewRoster()
	for _, record := range []*agentv1.Admission{
		admissionIn("web-01", "acme", agent.Active, 2),
		admissionIn("db-07", "globex", agent.Pending, 1),
	} {
		if err := roster.Apply(record); err != nil {
			t.Fatalf("apply %s: %v", record.GetAgentId(), err)
		}
	}

	for agentID, want := range map[string]string{"web-01": "acme", "db-07": "globex"} {
		if tenant, admits := roster.Tenant(agentID); !admits || tenant != want {
			t.Errorf("%s is admitted %t into %q, and it was registered in %q", agentID, admits, tenant, want)
		}
	}
}

func TestOnlyTheStatesThatStopAnAgentAreKept(t *testing.T) {
	roster := agent.NewRoster()
	for _, state := range []agent.State{agent.Pending, agent.Active} {
		if err := roster.Apply(admission("web-01", state, 1)); err != nil {
			t.Fatalf("apply %s: %v", state, err)
		}
		if !admitted(roster, "web-01") || roster.Refused() != 0 {
			t.Fatalf("a %s agent was refused", state)
		}
	}
	for _, state := range []agent.State{agent.Disabled, agent.Revoked, agent.Decommissioned} {
		if err := roster.Apply(admission("web-01", state, 2)); err != nil {
			t.Fatalf("apply %s: %v", state, err)
		}
		if tenant, admits := roster.Tenant("web-01"); admits || tenant != "" {
			t.Fatalf("a %s agent is admitted into %q", state, tenant)
		}
		if !roster.Knows("web-01") || roster.Refused() != 1 {
			t.Fatalf("a %s agent is not counted as refused", state)
		}
	}
}

func TestAnAgentLetInAgainStopsBeingRefused(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Apply(admission("web-01", agent.Disabled, 2)); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := roster.Apply(admission("web-01", agent.Active, 3)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !admitted(roster, "web-01") || roster.Refused() != 0 {
		t.Fatal("a re-enabled agent is still refused")
	}
}

func TestAReplayedRecordDoesNotBringARefusalBack(t *testing.T) {
	roster := agent.NewRoster()
	for _, record := range []*agentv1.Admission{
		admission("web-01", agent.Disabled, 2),
		admission("web-01", agent.Active, 3),
		admission("web-01", agent.Disabled, 2),
	} {
		if err := roster.Apply(record); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	if !admitted(roster, "web-01") {
		t.Fatal("an older record was applied over a newer one")
	}
}

func TestARecordTheRosterCannotReadIsRefusedRatherThanApplied(t *testing.T) {
	roster := agent.NewRoster()
	for name, record := range map[string]*agentv1.Admission{
		"no agent":        {TenantId: "acme", State: agent.Revoked.Wire()},
		"no state":        {AgentId: "web-01", TenantId: "acme"},
		"no tenant":       admissionIn("web-01", "", agent.Active, 1),
		"spaced tenant":   admissionIn("web-01", "acme corp", agent.Active, 1),
		"pathed tenant":   admissionIn("web-01", "../acme", agent.Active, 1),
		"too long tenant": admissionIn("web-01", strings.Repeat("a", 65), agent.Active, 1),
	} {
		if err := roster.Apply(record); !errors.Is(err, agent.ErrMalformed) {
			t.Errorf("%s: the record was applied: %v", name, err)
		}
	}
	if roster.Knows("web-01") || roster.Refused() != 0 {
		t.Fatal("an unreadable record changed what the roster holds")
	}
}

func TestTheRosterIsReadWhileItIsWritten(t *testing.T) {
	roster := agent.NewRoster()
	var waiting sync.WaitGroup
	for worker := range 8 {
		waiting.Add(2)
		go func() {
			defer waiting.Done()
			for revision := range 100 {
				_ = roster.Apply(admission("web-01", agent.Disabled, uint64(revision)))
				_ = roster.Apply(admission("db-07", agent.Active, uint64(revision)))
			}
		}()
		go func() {
			defer waiting.Done()
			for range 100 {
				roster.Tenant("web-01")
				roster.Knows("db-0" + string(rune('0'+worker)))
			}
		}()
	}
	waiting.Wait()

	if admitted(roster, "web-01") {
		t.Fatal("a disabled agent is admitted after concurrent use")
	}
}

// The log is compacted and keyed by the agent, so the record a reader could not
// read is the whole of what the platform decided about it. Forgetting it would
// re-admit the certificate the record revoked.
func TestAnAgentWhoseRecordCouldNotBeReadIsNoLongerAdmitted(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Apply(admission("web-02", agent.Active, 1)); err != nil {
		t.Fatalf("apply an admission: %v", err)
	}

	roster.Refuse("web-01")
	if admitted(roster, "web-01") {
		t.Error("an agent whose record could not be read is still admitted")
	}
	if roster.Known() != 2 || roster.Refused() != 1 {
		t.Errorf("the roster holds %d agents and refuses %d", roster.Known(), roster.Refused())
	}
	if !admitted(roster, "web-02") {
		t.Error("refusing one agent refused another")
	}
}

// The revision is kept, so the control plane can still say something readable
// about the agent afterwards and be believed.
func TestAReadableRecordReplacesARefusalItFollows(t *testing.T) {
	roster := agent.NewRoster()

	if err := roster.Apply(admission("web-01", agent.Active, 3)); err != nil {
		t.Fatalf("apply an admission: %v", err)
	}
	roster.Refuse("web-01")
	if admitted(roster, "web-01") {
		t.Fatal("the refusal did not take effect")
	}

	if err := roster.Apply(admission("web-01", agent.Active, 4)); err != nil {
		t.Fatalf("apply a later admission: %v", err)
	}
	if tenant, admits := roster.Tenant("web-01"); !admits || tenant != "acme" {
		t.Errorf("a later readable record admits the agent %t into %q", admits, tenant)
	}
}

func TestOneRevisionRepublishedUnchangedIsApplied(t *testing.T) {
	roster := agent.NewRoster()
	record := admission("web-01", agent.Revoked, 7)

	for range 2 {
		if err := roster.Apply(record); err != nil {
			t.Fatalf("republish one revocation: %v", err)
		}
	}
	if admitted(roster, "web-01") {
		t.Error("republishing a revocation re-admitted the agent")
	}
}

// Two control planes deciding one revision differently leave the platform unable
// to say what it decided, and an agent it cannot decide about is one it stops
// admitting rather than one it guesses about.
func TestOneRevisionDecidedBothWaysStopsAdmittingTheAgent(t *testing.T) {
	roster := agent.NewRoster()

	if err := roster.Apply(admission("web-01", agent.Revoked, 7)); err != nil {
		t.Fatalf("apply a revocation: %v", err)
	}
	err := roster.Apply(admission("web-01", agent.Active, 7))
	if !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("the conflicting record was applied: %v", err)
	}
	if admitted(roster, "web-01") {
		t.Error("a conflicting revision re-admitted a revoked agent")
	}
}

func TestOneRevisionNamingTwoTenantsStopsAdmittingTheAgent(t *testing.T) {
	roster := agent.NewRoster()

	if err := roster.Apply(admissionIn("web-01", "acme", agent.Active, 7)); err != nil {
		t.Fatalf("apply an admission: %v", err)
	}
	err := roster.Apply(admissionIn("web-01", "globex", agent.Active, 7))
	if !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("a revision naming a second tenant was applied: %v", err)
	}
	if tenant, admits := roster.Tenant("web-01"); admits {
		t.Errorf("an agent one revision placed in two tenants is admitted into %q", tenant)
	}
}

func TestARosterThatReadTheWholeLogAgreesWithOneThatReadOnlyWhatCompactionKept(t *testing.T) {
	history := []*agentv1.Admission{
		admissionIn("web-01", "acme", agent.Pending, 1),
		admissionIn("web-01", "acme", agent.Active, 2),
		admissionIn("web-01", "globex", agent.Active, 3),
	}

	running := agent.NewRoster()
	for _, record := range history {
		if err := running.Apply(record); err != nil {
			t.Fatalf("apply revision %d: %v", record.GetRevision(), err)
		}
	}
	started := agent.NewRoster()
	if err := started.Apply(history[len(history)-1]); err != nil {
		t.Fatalf("apply the compacted record: %v", err)
	}

	for name, roster := range map[string]*agent.Roster{"running": running, "started later": started} {
		if tenant, admits := roster.Tenant("web-01"); !admits || tenant != "globex" {
			t.Errorf("the %s gateway admits the agent %t into %q", name, admits, tenant)
		}
	}
}

func bound(revision uint64, fingerprint, replaced string) *agentv1.Admission {
	record := admission("web-01", agent.Active, revision)
	record.FingerprintSha256, record.IssuedAt = fingerprint, timestamppb.New(boundAt.Add(-time.Minute))
	if replaced != "" {
		record.ReplacedFingerprintSha256, record.ReplacedAt = replaced, timestamppb.New(boundAt)
	}
	return record
}

var boundAt = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

func TestTheRosterHoldsTheCertificateTheRegistryBindsAnAgentTo(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Apply(bound(3, strings.Repeat("ab", 32), strings.Repeat("ef", 32))); err != nil {
		t.Fatalf("apply: %v", err)
	}

	held, known := roster.Binding("web-01")
	want := agentidentity.Held{
		Binding: agentidentity.Binding{
			Fingerprint: strings.Repeat("ab", 32), IssuedAt: boundAt.Add(-time.Minute),
			Replaced: strings.Repeat("ef", 32), ReplacedAt: boundAt,
		},
		Revision: 3,
	}
	if !known || held != want {
		t.Fatalf("the roster holds %+v (%t), and the registry bound %+v", held, known, want)
	}
	if _, known := roster.Binding("db-07"); known {
		t.Fatal("the roster holds a binding for an agent the log never named")
	}
}

func TestARosterFollowingTheLogLearnsAReplacementWhenItAppliesIt(t *testing.T) {
	roster := agent.NewRoster()
	first, second := boundAt.Add(time.Second), boundAt.Add(time.Hour)

	if err := roster.Learn(bound(3, strings.Repeat("ab", 32), strings.Repeat("ef", 32)), first); err != nil {
		t.Fatalf("learn the renewal: %v", err)
	}
	if held, _ := roster.Binding("web-01"); !held.Learned.Equal(first) {
		t.Fatalf("a renewal learned at %s is held as learned at %s", first, held.Learned)
	}

	disabled := bound(4, strings.Repeat("ab", 32), strings.Repeat("ef", 32))
	disabled.State = agent.Disabled.Wire()
	if err := roster.Learn(disabled, second); err != nil {
		t.Fatalf("learn a move that binds nothing new: %v", err)
	}
	if held, _ := roster.Binding("web-01"); !held.Learned.Equal(first) {
		t.Fatalf("a move that bound nothing new restarted the tolerance at %s", held.Learned)
	}

	if err := roster.Learn(bound(5, strings.Repeat("cd", 32), strings.Repeat("ab", 32)), second); err != nil {
		t.Fatalf("learn the next renewal: %v", err)
	}
	if held, _ := roster.Binding("web-01"); !held.Learned.Equal(second) {
		t.Fatalf("the next renewal, learned at %s, is held as learned at %s", second, held.Learned)
	}
}

func TestARosterReadingTheLogBackLearnsNoReplacement(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Learn(bound(3, strings.Repeat("ab", 32), strings.Repeat("ef", 32)), boundAt.Add(time.Hour)); err != nil {
		t.Fatalf("learn: %v", err)
	}
	if err := roster.Apply(bound(4, strings.Repeat("cd", 32), strings.Repeat("ab", 32))); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if held, _ := roster.Binding("web-01"); !held.Learned.IsZero() {
		t.Fatalf("a renewal read back is held as learned at %s", held.Learned)
	}
}

func TestARecordWithoutTheCertificateNeverErasesOneOfItsRevision(t *testing.T) {
	roster := agent.NewRoster()
	for _, record := range []*agentv1.Admission{
		admission("web-01", agent.Active, 3),
		bound(3, strings.Repeat("ab", 32), ""),
		admission("web-01", agent.Active, 3),
	} {
		if err := roster.Apply(record); err != nil {
			t.Fatalf("apply revision 3: %v", err)
		}
	}
	if held, _ := roster.Binding("web-01"); held.Binding.Fingerprint != strings.Repeat("ab", 32) || !admitted(roster, "web-01") {
		t.Fatalf("a record of the same revision without the certificate left the roster holding %+v", held)
	}
}

func TestOneRevisionBindingTwoCertificatesLeavesTheAgentRefused(t *testing.T) {
	roster := agent.NewRoster()
	if err := roster.Apply(bound(3, strings.Repeat("ab", 32), "")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := roster.Apply(bound(3, strings.Repeat("cd", 32), "")); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("one revision binding two certificates was applied: %v", err)
	}
	if admitted(roster, "web-01") {
		t.Fatal("an agent whose revision binds two certificates is still admitted")
	}
}

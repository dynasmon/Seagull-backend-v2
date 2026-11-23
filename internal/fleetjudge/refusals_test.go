package fleetjudge_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/fleetjudge"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var (
	firstCertificate  = strings.Repeat("ab", 32)
	secondCertificate = strings.Repeat("cd", 32)
)

func bound(t *testing.T, state agentv1.State, fingerprint string, revision uint64, changed time.Time) fleetjudge.Record {
	return encoded(t, "web-01", &agentv1.Admission{AgentId: "web-01", TenantId: "default", State: state, Revision: revision,
		ChangedAt: timestamppb.New(changed), FingerprintSha256: fingerprint, IssuedAt: timestamppb.New(changed.Add(-time.Minute))})
}

func refusal(fingerprint string, first, last time.Time, refusals uint64, route string) *agentv1.Refusal {
	refused := agentidentity.Refused("web-01", "default", agentidentity.Held{Binding: agentidentity.Binding{Fingerprint: fingerprint}, Revision: 2},
		route, "gateway-1", first)
	refused.LastRefusedAt, refused.Refusals = timestamppb.New(last), refusals
	return refused
}

func refused(t *testing.T, fingerprint string, first, last time.Time, refusals uint64, route string) fleetjudge.Record {
	return encoded(t, "web-01", refusal(fingerprint, first, last, refusals, route))
}

func refusedAgent(t *testing.T) *harness {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{bound(t, agentv1.State_STATE_ACTIVE, firstCertificate, 2, start.Add(-time.Hour))}
	return h
}

func gatewayFindings(all []*agentv1.Finding) []*agentv1.Finding {
	var found []*agentv1.Finding
	for _, one := range all {
		if one.GetKind() == agentv1.Finding_KIND_REPLACED_CERTIFICATE {
			found = append(found, one)
		}
	}
	return found
}

func TestTheRefusalsOfAReplacedCertificateAtAGatewayAreOneFindingWhileOneCertificateIsInForce(t *testing.T) {
	h := refusedAgent(t)
	h.run()

	h.send(h.refusals, refused(t, firstCertificate, start.Add(10*time.Second), start.Add(12*time.Second), 2, "POST /v1/events"))
	h.at(20 * time.Second)
	got := gatewayFindings(h.published.all())
	if len(got) != 1 {
		t.Fatalf("the refusals were decided %d times", len(got))
	}
	opened := got[0]
	want := agentfinding.Refusing("default", "web-01", refusal(firstCertificate, start.Add(10*time.Second), start.Add(12*time.Second), 2, "POST /v1/events"), start)
	if err := agentfinding.Validate(opened); err != nil || opened.GetFindingId() != want.GetFindingId() ||
		opened.GetState() != agentv1.Finding_STATE_OPEN || opened.GetObservations() != 2 ||
		!opened.GetOpenedAt().AsTime().Equal(start.Add(10*time.Second)) || opened.GetUse().GetListener() != agentv1.Finding_Use_LISTENER_GATEWAY {
		t.Fatalf("the refusals were found as %v (%v)", opened, err)
	}
	if open := counted(t, h.exported, `seagull_fleetjudge_open_findings{kind="replaced_certificate"}`); open != 1 {
		t.Errorf("%v findings of a replaced certificate are counted open", open)
	}

	h.send(h.refusals, refused(t, firstCertificate, start.Add(15*time.Second), start.Add(18*time.Second), 1, "POST /v1/status"))
	h.at(50 * time.Second)
	if got := gatewayFindings(h.published.all()); len(got) != 1 {
		t.Fatalf("refusals observed inside a minute of the last decision were decided again: %v", got)
	}
	h.at(61 * time.Second)
	got = gatewayFindings(h.published.all())
	if len(got) != 2 || got[1].GetFindingId() != opened.GetFindingId() || got[1].GetObservations() != 3 ||
		!got[1].GetLastObservedAt().AsTime().Equal(start.Add(18*time.Second)) || got[1].GetUse().GetRoute() != "POST /v1/status" {
		t.Fatalf("refusals observed again were decided as %v", got)
	}
	h.at(3 * time.Minute)
	if got := gatewayFindings(h.published.all()); len(got) != 2 {
		t.Fatalf("a finding nothing new was observed of was decided again within a day: %v", got[2:])
	}
}

func TestAFindingOfRefusalsClosesAsReboundWhenAnotherCertificateIsBound(t *testing.T) {
	h := refusedAgent(t)
	h.run()
	h.send(h.refusals, refused(t, firstCertificate, start.Add(10*time.Second), start.Add(10*time.Second), 1, "POST /v1/events"))
	h.at(time.Minute)

	h.send(h.admissions, bound(t, agentv1.State_STATE_ACTIVE, secondCertificate, 3, start.Add(2*time.Minute)))
	h.at(3 * time.Minute)
	got := gatewayFindings(h.published.all())
	if len(got) != 2 || got[1].GetState() != agentv1.Finding_STATE_CLOSED || got[1].GetClosure() != agentv1.Finding_CLOSURE_REBOUND ||
		!got[1].GetClosedAt().AsTime().Equal(start.Add(2*time.Minute)) {
		t.Fatalf("binding another certificate left the refusals found as %v", got)
	}
	if open := counted(t, h.exported, `seagull_fleetjudge_open_findings{kind="replaced_certificate"}`); open != 0 {
		t.Errorf("%v findings of a replaced certificate are counted open", open)
	}
}

func TestAFindingOfRefusalsClosesWhenTheAgentIsNoLongerAdmitted(t *testing.T) {
	h := refusedAgent(t)
	h.run()
	h.send(h.refusals, refused(t, firstCertificate, start.Add(10*time.Second), start.Add(10*time.Second), 1, "POST /v1/events"))
	h.at(time.Minute)

	h.send(h.admissions, bound(t, agentv1.State_STATE_REVOKED, firstCertificate, 3, start.Add(2*time.Minute)))
	h.at(3 * time.Minute)
	got := gatewayFindings(h.published.all())
	if len(got) != 2 || got[1].GetClosure() != agentv1.Finding_CLOSURE_NOT_ADMITTED || !got[1].GetClosedAt().AsTime().Equal(start.Add(2*time.Minute)) {
		t.Fatalf("revoking the agent left the refusals found as %v", got)
	}
}

func TestARefusalUnderACertificateOrAnAdmissionNoLongerInForceOpensNothing(t *testing.T) {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{bound(t, agentv1.State_STATE_ACTIVE, secondCertificate, 4, start.Add(-time.Minute))}
	h.run()

	h.send(h.refusals,
		refused(t, firstCertificate, start.Add(10*time.Second), start.Add(10*time.Second), 1, "POST /v1/events"),
		refused(t, secondCertificate, start.Add(-2*time.Minute), start.Add(-90*time.Second), 1, "POST /v1/events"))
	h.at(time.Minute)
	if got := gatewayFindings(h.published.all()); len(got) != 0 {
		t.Fatalf("refusals no longer in force were found: %v", got)
	}
	if outdated := counted(t, h.exported, `seagull_fleetjudge_refusals_total{outcome="outdated"}`); outdated != 2 {
		t.Errorf("%v refusals are counted outdated, and 2 were", outdated)
	}
}

func TestARefusalReadBackOpensTheFindingItIsEvidenceOf(t *testing.T) {
	h := refusedAgent(t)
	h.refusals.replay = []fleetjudge.Record{refused(t, firstCertificate, start.Add(-30*time.Second), start.Add(-20*time.Second), 4, "POST /v1/inventory")}
	h.run()

	h.at(time.Minute)
	got := gatewayFindings(h.published.all())
	if len(got) != 1 || got[0].GetObservations() != 4 || !got[0].GetOpenedAt().AsTime().Equal(start.Add(-30*time.Second)) {
		t.Fatalf("refusals made while no judge ran were found as %v", got)
	}
}

func TestAJudgeThatStartsAgainCountsOnlyTheRefusalsItHadNotCounted(t *testing.T) {
	h := refusedAgent(t)
	counted := refusal(firstCertificate, start.Add(-3*time.Minute), start.Add(-2*time.Minute), 2, "POST /v1/events")
	before := agentfinding.Refusing("default", "web-01", counted, start.Add(-2*time.Minute))
	h.findings.replay = []fleetjudge.Record{remembered(t, before)}
	h.refusals.replay = []fleetjudge.Record{
		encoded(t, "web-01", counted),
		refused(t, firstCertificate, start.Add(-time.Minute), start.Add(-time.Minute), 1, "POST /v1/status"),
	}
	h.run()

	h.at(time.Minute)
	got := gatewayFindings(h.published.all())
	if len(got) != 1 || got[0].GetFindingId() != before.GetFindingId() || got[0].GetObservations() != 3 ||
		got[0].GetState() != agentv1.Finding_STATE_OPEN || !got[0].GetOpenedAt().AsTime().Equal(start.Add(-3*time.Minute)) {
		t.Fatalf("a judge starting again decided the refusals as %v", got)
	}
}

func TestAJudgeThatStartsAgainClosesTheRefusalsOfACertificateReplacedMeanwhile(t *testing.T) {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{bound(t, agentv1.State_STATE_ACTIVE, secondCertificate, 3, start.Add(-time.Minute))}
	open := agentfinding.Refusing("default", "web-01", refusal(firstCertificate, start.Add(-time.Hour), start.Add(-time.Hour), 1, "POST /v1/events"), start.Add(-time.Hour))
	h.findings.replay = []fleetjudge.Record{remembered(t, open)}
	h.run()

	h.at(time.Minute)
	got := gatewayFindings(h.published.all())
	if len(got) != 1 || got[0].GetClosure() != agentv1.Finding_CLOSURE_REBOUND || !got[0].GetClosedAt().AsTime().Equal(start.Add(-time.Minute)) {
		t.Fatalf("a finding of a certificate replaced while no judge ran was decided as %v", got)
	}
}

func TestTheJudgeLeavesTheControlListenersFindingsToTheControlPlane(t *testing.T) {
	h := refusedAgent(t)
	control := agentfinding.Replaced{TenantID: "default", AgentID: "web-01", InForce: firstCertificate, OpenedAt: start.Add(-time.Hour),
		LastObservedAt: start.Add(-time.Hour), Observations: 1, DecidedAt: start.Add(-time.Hour), Revision: 1}.
		Finding(&agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_CONTROL, Route: "POST /v1/agents/certificate"})
	h.findings.replay = []fleetjudge.Record{remembered(t, control)}
	h.run()

	h.send(h.admissions, bound(t, agentv1.State_STATE_ACTIVE, secondCertificate, 3, start.Add(30*time.Second)))
	h.at(time.Minute)
	if got := gatewayFindings(h.published.all()); len(got) != 0 {
		t.Fatalf("the judge decided about the control listener's finding: %v", got)
	}
}

func TestARefusalTheJudgeCannotReadIsCountedAndSteppedOver(t *testing.T) {
	h := refusedAgent(t)
	h.run()

	spoiled := refusal(firstCertificate, start, start, 1, "POST /v1/events")
	spoiled.SchemaVersion = 9
	h.send(h.refusals, encoded(t, "web-01", spoiled), fleetjudge.Record{Key: []byte("web-01"), Value: []byte{0xff}},
		encoded(t, "db-07", refusal(firstCertificate, start, start, 1, "POST /v1/events")))
	h.at(time.Minute)
	if got := gatewayFindings(h.published.all()); len(got) != 0 {
		t.Fatalf("an unreadable refusal was found: %v", got)
	}
	if unread := counted(t, h.exported, `seagull_fleetjudge_refused_records_total{log="refusals"}`); unread != 3 {
		t.Errorf("%v unreadable refusals were counted, and 3 were sent", unread)
	}
}

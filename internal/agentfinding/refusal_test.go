package agentfinding_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var refusedAt = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func gatewayRefusal() *agentv1.Refusal {
	held := agentidentity.Held{Binding: agentidentity.Binding{Fingerprint: strings.Repeat("ab", 32)}, Revision: 7}
	return agentidentity.Refused("web-01", "acme", held, "POST /v1/events", "gateway-a", refusedAt)
}

func TestARefusalAGatewayMadeIsRead(t *testing.T) {
	if err := agentfinding.ValidateRefusal(gatewayRefusal()); err != nil {
		t.Fatalf("a refusal a gateway made was refused: %v", err)
	}
}

func TestARefusalTheJudgeCannotReadIsRefused(t *testing.T) {
	for name, spoil := range map[string]func(*agentv1.Refusal){
		"another schema":                func(r *agentv1.Refusal) { r.SchemaVersion = 2 },
		"no reason":                     func(r *agentv1.Refusal) { r.Reason = agentv1.Refusal_REASON_UNSPECIFIED },
		"a reason nobody declared":      func(r *agentv1.Refusal) { r.Reason = 9 },
		"no agent":                      func(r *agentv1.Refusal) { r.AgentId = "" },
		"an agent no certificate names": func(r *agentv1.Refusal) { r.AgentId = "../web-01" },
		"no tenant":                     func(r *agentv1.Refusal) { r.TenantId = "" },
		"a tenant too long":             func(r *agentv1.Refusal) { r.TenantId = strings.Repeat("t", 65) },
		"no certificate in force":       func(r *agentv1.Refusal) { r.FingerprintSha256 = "" },
		"a fingerprint in capitals":     func(r *agentv1.Refusal) { r.FingerprintSha256 = strings.Repeat("AB", 32) },
		"no revision":                   func(r *agentv1.Refusal) { r.Revision = 0 },
		"another listener":              func(r *agentv1.Refusal) { r.Use.Listener = agentv1.Finding_Use_LISTENER_CONTROL },
		"no route":                      func(r *agentv1.Refusal) { r.Use.Route = "" },
		"a route too long":              func(r *agentv1.Refusal) { r.Use.Route = strings.Repeat("r", agentfinding.MaxRouteLength+1) },
		"no refusal":                    func(r *agentv1.Refusal) { r.Refusals = 0 },
		"no first refusal":              func(r *agentv1.Refusal) { r.FirstRefusedAt = nil },
		"the last before the first":     func(r *agentv1.Refusal) { r.LastRefusedAt = timestamppb.New(refusedAt.Add(-time.Second)) },
		"no gateway":                    func(r *agentv1.Refusal) { r.Gateway = "" },
		"a gateway too long":            func(r *agentv1.Refusal) { r.Gateway = strings.Repeat("g", 65) },
	} {
		t.Run(name, func(t *testing.T) {
			record := gatewayRefusal()
			spoil(record)
			if err := agentfinding.ValidateRefusal(record); err == nil {
				t.Fatalf("a refusal with %s was read", name)
			}
		})
	}
}

func TestTheRefusalsOfACertificateAtAGatewayAreAFindingOfItsOwn(t *testing.T) {
	inForce := strings.Repeat("ab", 32)
	decided := refusedAt.Add(time.Second)
	opened := agentfinding.Refusing("acme", "web-01", gatewayRefusal(), decided)

	if err := agentfinding.Validate(opened); err != nil {
		t.Fatalf("the finding a gateway's refusals make cannot be stored: %v", err)
	}
	if opened.GetKind() != agentv1.Finding_KIND_REPLACED_CERTIFICATE || opened.GetState() != agentv1.Finding_STATE_OPEN ||
		!opened.GetOpenedAt().AsTime().Equal(refusedAt) || !opened.GetLastObservedAt().AsTime().Equal(refusedAt) ||
		opened.GetObservations() != 1 || !opened.GetDecidedAt().AsTime().Equal(decided) ||
		opened.GetUse().GetListener() != agentv1.Finding_Use_LISTENER_GATEWAY || opened.GetUse().GetRoute() != "POST /v1/events" {
		t.Fatalf("the refusals were found as %v", opened)
	}
	if strings.Contains(opened.String(), inForce) {
		t.Fatalf("the finding names the certificate in force: %v", opened)
	}

	control := agentfinding.Replaced{TenantID: "acme", AgentID: "web-01", InForce: inForce, OpenedAt: refusedAt,
		LastObservedAt: refusedAt, Observations: 1, DecidedAt: decided}.Finding(&agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_CONTROL, Route: "POST /v1/agents/certificate"})
	if opened.GetFindingId() == control.GetFindingId() {
		t.Fatal("the gateway's refusals and the control listener's name one finding")
	}

	later := gatewayRefusal()
	later.FirstRefusedAt, later.LastRefusedAt = timestamppb.New(refusedAt.Add(time.Hour)), timestamppb.New(refusedAt.Add(time.Hour))
	if again := agentfinding.Refusing("acme", "web-01", later, decided); again.GetFindingId() != opened.GetFindingId() {
		t.Fatal("two records of refusals under one certificate in force name two findings")
	}
	renewed := gatewayRefusal()
	renewed.FingerprintSha256 = strings.Repeat("cd", 32)
	if next := agentfinding.Refusing("acme", "web-01", renewed, decided); next.GetFindingId() == opened.GetFindingId() {
		t.Fatal("refusals under another certificate in force name the same finding")
	}
}

func TestAnotherRecordOfRefusalsIsCountedAndTheNewestSaysWhere(t *testing.T) {
	opened := agentfinding.Refusing("acme", "web-01", gatewayRefusal(), refusedAt)

	newer := gatewayRefusal()
	newer.FirstRefusedAt, newer.LastRefusedAt = timestamppb.New(refusedAt.Add(time.Minute)), timestamppb.New(refusedAt.Add(2*time.Minute))
	newer.Refusals, newer.Use.Route = 3, "GET /v1/descriptor"
	observed := agentfinding.RefusedAgain(opened, newer)
	if observed.GetObservations() != 4 || !observed.GetLastObservedAt().AsTime().Equal(refusedAt.Add(2*time.Minute)) ||
		observed.GetUse().GetRoute() != "GET /v1/descriptor" || !observed.GetOpenedAt().AsTime().Equal(refusedAt) {
		t.Fatalf("a newer record of refusals was observed as %v", observed)
	}
	if opened.GetObservations() != 1 {
		t.Fatal("observing refusals changed the decision it started from")
	}

	earlier := gatewayRefusal()
	earlier.FirstRefusedAt, earlier.LastRefusedAt = timestamppb.New(refusedAt.Add(-time.Minute)), timestamppb.New(refusedAt.Add(-time.Minute))
	earlier.Use.Route = "POST /v1/status"
	observed = agentfinding.RefusedAgain(observed, earlier)
	if observed.GetObservations() != 5 || !observed.GetOpenedAt().AsTime().Equal(refusedAt.Add(-time.Minute)) ||
		!observed.GetLastObservedAt().AsTime().Equal(refusedAt.Add(2*time.Minute)) || observed.GetUse().GetRoute() != "GET /v1/descriptor" {
		t.Fatalf("a record a gateway published late was observed as %v", observed)
	}
}

package agentfinding_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var opened = time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)

func heard(installation string, sequence uint64, at time.Time) *agentv1.Heard {
	return &agentv1.Heard{
		InstallationId: installation,
		BootId:         "8f2c9a8e-4c3d-4b8a-9a51-6c1f0d6e2b11",
		Sequence:       sequence,
		RunStartedAt:   timestamppb.New(at.Add(-time.Hour)),
		ReportedAt:     timestamppb.New(at),
		IngestTime:     timestamppb.New(at.Add(40 * time.Millisecond)),
		Gateway:        "gateway-1",
		Interval:       durationpb.New(time.Minute),
	}
}

func wellFormed(kind agentv1.Finding_Kind) *agentv1.Finding {
	decided := &agentv1.Finding{
		SchemaVersion:  agentfinding.SchemaVersion,
		FindingId:      agentfinding.ID("default", "web-01", kind, "episode"),
		TenantId:       "default",
		AgentId:        "web-01",
		Kind:           kind,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(opened),
		LastObservedAt: timestamppb.New(opened.Add(time.Minute)),
		Observations:   1,
		DecidedAt:      timestamppb.New(opened.Add(2 * time.Minute)),
	}
	switch kind {
	case agentv1.Finding_KIND_SILENCE:
		decided.Reports = []*agentv1.Heard{heard("installation-a", 41, opened.Add(-5*time.Minute))}
	case agentv1.Finding_KIND_COPIED_INSTALLATION, agentv1.Finding_KIND_SHARED_IDENTITY:
		decided.Reports = []*agentv1.Heard{heard("installation-a", 41, opened), heard("installation-b", 12, opened)}
	case agentv1.Finding_KIND_REPLACED_CERTIFICATE:
		decided.Use = &agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_CONTROL, Route: "POST /v1/agents/certificate"}
	}
	return decided
}

func closed(decided *agentv1.Finding, closure agentv1.Finding_Closure) *agentv1.Finding {
	decided.State = agentv1.Finding_STATE_CLOSED
	decided.Closure = closure
	decided.ClosedAt = timestamppb.New(opened.Add(10 * time.Minute))
	return decided
}

func TestEveryKindThisBuildJudgesIsAccepted(t *testing.T) {
	endings := map[agentv1.Finding_Kind]agentv1.Finding_Closure{
		agentv1.Finding_KIND_SILENCE:              agentv1.Finding_CLOSURE_HEARD,
		agentv1.Finding_KIND_COPIED_INSTALLATION:  agentv1.Finding_CLOSURE_ONE_SOURCE,
		agentv1.Finding_KIND_SHARED_IDENTITY:      agentv1.Finding_CLOSURE_ONE_SOURCE,
		agentv1.Finding_KIND_REPLACED_CERTIFICATE: agentv1.Finding_CLOSURE_REBOUND,
	}
	for _, kind := range agentfinding.Kinds() {
		if err := agentfinding.Validate(wellFormed(kind)); err != nil {
			t.Errorf("an open %s finding was refused: %v", kind, err)
		}
		if err := agentfinding.Validate(closed(wellFormed(kind), endings[kind])); err != nil {
			t.Errorf("a closed %s finding was refused: %v", kind, err)
		}
		if err := agentfinding.Validate(closed(wellFormed(kind), agentv1.Finding_CLOSURE_NOT_ADMITTED)); err != nil {
			t.Errorf("a %s finding closed because the agent is no longer admitted was refused: %v", kind, err)
		}
	}
	if len(endings) != len(agentfinding.Kinds()) {
		t.Errorf("the contract declares %d kinds and this test knows %d", len(agentfinding.Kinds()), len(endings))
	}
}

func TestAMalformedFindingIsRefusedByTheFieldThatIsWrong(t *testing.T) {
	silence := func(change func(*agentv1.Finding)) *agentv1.Finding {
		decided := wellFormed(agentv1.Finding_KIND_SILENCE)
		change(decided)
		return decided
	}
	for field, decided := range map[string]*agentv1.Finding{
		"schema_version":     silence(func(f *agentv1.Finding) { f.SchemaVersion = 2 }),
		"finding_id":         silence(func(f *agentv1.Finding) { f.FindingId = strings.ToUpper(f.FindingId) }),
		"tenant_id":          silence(func(f *agentv1.Finding) { f.TenantId = "" }),
		"agent_id":           silence(func(f *agentv1.Finding) { f.AgentId = "web 01" }),
		"kind":               silence(func(f *agentv1.Finding) { f.Kind = agentv1.Finding_Kind(99) }),
		"state":              silence(func(f *agentv1.Finding) { f.State = agentv1.Finding_STATE_UNSPECIFIED }),
		"closure":            silence(func(f *agentv1.Finding) { f.Closure = agentv1.Finding_CLOSURE_HEARD }),
		"closed_at":          silence(func(f *agentv1.Finding) { closed(f, agentv1.Finding_CLOSURE_HEARD).ClosedAt = nil }),
		"opened_at":          silence(func(f *agentv1.Finding) { f.OpenedAt = nil }),
		"last_observed_at":   silence(func(f *agentv1.Finding) { f.LastObservedAt = timestamppb.New(opened.Add(-time.Second)) }),
		"decided_at":         silence(func(f *agentv1.Finding) { f.DecidedAt = &timestamppb.Timestamp{Seconds: 1, Nanos: -1} }),
		"observations":       silence(func(f *agentv1.Finding) { f.Observations = 0 }),
		"reports":            silence(func(f *agentv1.Finding) { f.Reports = nil }),
		"reports[0].gateway": silence(func(f *agentv1.Finding) { f.Reports[0].Gateway = "" }),
		"reports[0].installation_id": silence(func(f *agentv1.Finding) {
			f.Reports[0].InstallationId = strings.Repeat("i", agentfinding.MaxTextLength+1)
		}),
		"reports[0].sequence":    silence(func(f *agentv1.Finding) { f.Reports[0].Sequence = 0 }),
		"reports[0].interval":    silence(func(f *agentv1.Finding) { f.Reports[0].Interval = durationpb.New(time.Second) }),
		"reports[0].report":      silence(func(f *agentv1.Finding) { f.Reports[0] = nil }),
		"reports[0].reported_at": silence(func(f *agentv1.Finding) { f.Reports[0].ReportedAt = nil }),
		"use": silence(func(f *agentv1.Finding) {
			f.Use = &agentv1.Finding_Use{Listener: agentv1.Finding_Use_LISTENER_GATEWAY, Route: "POST /v1/status"}
		}),
	} {
		var violation *event.Violation
		if err := agentfinding.Validate(decided); !errors.As(err, &violation) || violation.Field != field {
			t.Errorf("a finding wrong in %s was answered %v", field, err)
		}
	}

	for name, decided := range map[string]*agentv1.Finding{
		"a copy closed as heard": closed(wellFormed(agentv1.Finding_KIND_COPIED_INSTALLATION), agentv1.Finding_CLOSURE_HEARD),
		"a copy resting on one report": func() *agentv1.Finding {
			copied := wellFormed(agentv1.Finding_KIND_COPIED_INSTALLATION)
			copied.Reports = copied.Reports[:1]
			return copied
		}(),
		"a replaced certificate with no use": func() *agentv1.Finding {
			replaced := wellFormed(agentv1.Finding_KIND_REPLACED_CERTIFICATE)
			replaced.Use = nil
			return replaced
		}(),
		"a replaced certificate with a route too long": func() *agentv1.Finding {
			replaced := wellFormed(agentv1.Finding_KIND_REPLACED_CERTIFICATE)
			replaced.Use.Route = strings.Repeat("r", agentfinding.MaxRouteLength+1)
			return replaced
		}(),
		"more reports than a finding names": func() *agentv1.Finding {
			copied := wellFormed(agentv1.Finding_KIND_SHARED_IDENTITY)
			for len(copied.Reports) <= agentfinding.MaxReports {
				copied.Reports = append(copied.Reports, heard("installation-c", 3, opened))
			}
			return copied
		}(),
		"nothing": nil,
	} {
		if err := agentfinding.Validate(decided); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTheHeaviestFindingTheContractAllowsIsInsideItsCeiling(t *testing.T) {
	longest := func(length int) string { return strings.Repeat("x", length) }
	heaviest := wellFormed(agentv1.Finding_KIND_SHARED_IDENTITY)
	heaviest.TenantId = longest(event.MaxTenantIDLength)
	heaviest.AgentId = longest(event.MaxAgentIDLength)
	heaviest.Reports = nil
	for range agentfinding.MaxReports {
		one := heard(longest(agentfinding.MaxTextLength), ^uint64(0), opened)
		one.BootId, one.Gateway, one.Stopping = longest(agentfinding.MaxTextLength), longest(agentfinding.MaxTextLength), true
		heaviest.Reports = append(heaviest.Reports, one)
	}
	heaviest.Observations = ^uint64(0)
	closed(heaviest, agentv1.Finding_CLOSURE_NOT_ADMITTED)
	if err := agentfinding.Validate(heaviest); err != nil {
		t.Fatalf("the heaviest finding was refused: %v", err)
	}
	if size := proto.Size(heaviest); size > agentfinding.MaxFindingBytes/4 {
		t.Errorf("the heaviest finding encodes to %d bytes, which leaves less than three quarters of %d spare", size, agentfinding.MaxFindingBytes)
	}
}

package fixtures

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type Report struct {
	AgentID        string
	InstallationID string
	BootID         string
	Sequence       uint64
	At             time.Time
	Interval       time.Duration
	Condition      agentv1.Status_Condition
}

func (r Report) Status() *agentv1.Status {
	if r.AgentID == "" {
		r.AgentID = "dev-agent-01"
	}
	if r.InstallationID == "" {
		r.InstallationID = "0d6f2c3a-5b4e-4f1d-9c8b-7a6e5d4c3b2a"
	}
	if r.BootID == "" {
		r.BootID = "8e1f0a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
	}
	if r.Sequence == 0 {
		r.Sequence = 1
	}
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	if r.Interval == 0 {
		r.Interval = time.Minute
	}
	if r.Condition == agentv1.Status_CONDITION_UNSPECIFIED {
		r.Condition = agentv1.Status_CONDITION_RUNNING
	}

	return &agentv1.Status{
		SchemaVersion:  agentstatus.SchemaVersion,
		InstallationId: r.InstallationID,
		Sequence:       r.Sequence,
		ReportedAt:     timestamppb.New(r.At),
		Interval:       durationpb.New(r.Interval),
		Origin: &eventv1.Origin{
			AgentId:  r.AgentID,
			TenantId: "default",
			Host:     &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"},
		},
		Run: &agentv1.Status_Run{
			BootId:         r.BootID,
			StartedAt:      timestamppb.New(r.At.Add(-time.Hour)),
			PreviousEnding: agentv1.Status_ENDING_STOPPED,
			PreviousSeenAt: timestamppb.New(r.At.Add(-2 * time.Hour)),
			PreviousReason: "the agent was asked to stop",
		},
		Build:     &agentv1.Status_Build{Version: "v0.1.0", Toolchain: "go1.26.9", Os: "linux", Architecture: "amd64"},
		Condition: r.Condition,
		Components: []*agentv1.Status_Component{
			{Name: "delivery", Condition: agentv1.Status_CONDITION_RUNNING},
			{Name: "collection", Condition: agentv1.Status_CONDITION_RUNNING},
		},
		Modules: []*agentv1.Status_Module{
			{Name: "authentication", Condition: agentv1.Status_CONDITION_RUNNING, Since: timestamppb.New(r.At.Add(-time.Hour))},
			{Name: "files", Condition: agentv1.Status_CONDITION_DISABLED},
		},
		Spool: &agentv1.Status_Spool{
			MaxBytes: 512 << 20,
			Streams:  []*agentv1.Status_Stream{{Name: "events", Delivered: 12}, {Name: "inventory", Delivered: 7}},
		},
		Credential:    &agentv1.Status_Credential{Generation: 2, NotAfter: timestamppb.New(r.At.Add(24 * time.Hour))},
		Configuration: &agentv1.Status_Configuration{DigestSha256: strings.Repeat("0f", 32)},
		Privileges:    &agentv1.Status_Privileges{User: "997", Groups: []string{"997", "999"}, NoNewPrivileges: true, Seccomp: "filter"},
	}
}

func StatusBatch(batchID string, reports ...*agentv1.Status) *agentv1.StatusBatch {
	return &agentv1.StatusBatch{
		BatchId:         batchID,
		ProtocolVersion: protocol.Version,
		Reports:         reports,
	}
}

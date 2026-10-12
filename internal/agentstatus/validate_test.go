package agentstatus

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var reported = time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)

var window = event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 24 * time.Hour}

func report() *agentv1.Status {
	return &agentv1.Status{
		SchemaVersion:  SchemaVersion,
		InstallationId: "2f1d6c1e-6b0a-4f4e-9b8e-6d1c2a3b4c5d",
		Sequence:       42,
		ReportedAt:     timestamppb.New(reported),
		Interval:       durationpb.New(time.Minute),
		Origin: &eventv1.Origin{
			AgentId:  "web-01",
			TenantId: "acme",
			Host:     &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"},
		},
		Run: &agentv1.Status_Run{
			BootId:         "5f0c4a59-0c1a-4a8e-8f53-1b2c3d4e5f60",
			StartedAt:      timestamppb.New(reported.Add(-time.Hour)),
			PreviousEnding: agentv1.Status_ENDING_INTERRUPTED,
			PreviousSeenAt: timestamppb.New(reported.Add(-2 * time.Hour)),
		},
		Build:     &agentv1.Status_Build{Version: "v0.1.0", Revision: "ee7c1b4", Toolchain: "go1.26.9", Os: "linux", Architecture: "amd64"},
		Condition: agentv1.Status_CONDITION_DEGRADED,
		Components: []*agentv1.Status_Component{
			{Name: "delivery", Condition: agentv1.Status_CONDITION_DEGRADED, Since: timestamppb.New(reported.Add(-time.Minute)), Reason: "the platform does not answer"},
			{Name: "spool", Condition: agentv1.Status_CONDITION_RUNNING},
		},
		Modules: []*agentv1.Status_Module{
			{Name: "authentication", Condition: agentv1.Status_CONDITION_RUNNING, Since: timestamppb.New(reported.Add(-time.Hour))},
			{Name: "files", Condition: agentv1.Status_CONDITION_DISABLED},
		},
		Spool: &agentv1.Status_Spool{
			Bytes:    4096,
			MaxBytes: 512 << 20,
			Streams: []*agentv1.Status_Stream{
				{Name: "events", Outstanding: 3, Bytes: 4096, OldestAdmitted: timestamppb.New(reported.Add(-time.Minute)), FailingSince: timestamppb.New(reported.Add(-time.Minute))},
				{Name: "inventory"},
			},
		},
		Credential: &agentv1.Status_Credential{Generation: 3, NotAfter: timestamppb.New(reported.Add(24 * time.Hour))},
		Configuration: &agentv1.Status_Configuration{
			DigestSha256:    strings.Repeat("ab", 32),
			PolicyId:        "linux-web",
			PolicyRevision:  7,
			PolicyExpiresAt: timestamppb.New(reported.Add(30 * 24 * time.Hour)),
		},
		Privileges: &agentv1.Status_Privileges{User: "997", Groups: []string{"997", "999"}, NoNewPrivileges: true, Seccomp: "filter"},
	}
}

func mutate(change func(*agentv1.Status)) *agentv1.Status {
	changed := report()
	change(changed)
	return changed
}

func TestAWellFormedReportIsAdmitted(t *testing.T) {
	if err := Validate(report(), reported, window); err != nil {
		t.Fatalf("a well formed report was refused: %v", err)
	}
	unenrolled := mutate(func(r *agentv1.Status) {
		r.Credential, r.Configuration.PolicyId, r.Configuration.PolicyRevision = nil, "", 0
	})
	if err := Validate(unenrolled, reported, window); err != nil {
		t.Fatalf("a report without a credential or a policy was refused: %v", err)
	}
}

func TestAReportIsRefusedNamingTheFieldAtFault(t *testing.T) {
	long := strings.Repeat("x", MaxReasonLength+1)
	for name, one := range map[string]struct {
		report *agentv1.Status
		field  string
	}{
		"schema version":         {mutate(func(r *agentv1.Status) { r.SchemaVersion = MaxSchemaVersion + 1 }), "schema_version"},
		"no installation":        {mutate(func(r *agentv1.Status) { r.InstallationId = "" }), "installation_id"},
		"malformed installation": {mutate(func(r *agentv1.Status) { r.InstallationId = "not an identifier" }), "installation_id"},
		"no sequence":            {mutate(func(r *agentv1.Status) { r.Sequence = 0 }), "sequence"},
		"no reported at":         {mutate(func(r *agentv1.Status) { r.ReportedAt = nil }), "reported_at"},
		"no interval":            {mutate(func(r *agentv1.Status) { r.Interval = nil }), "interval"},
		"interval too short":     {mutate(func(r *agentv1.Status) { r.Interval = durationpb.New(MinInterval - time.Second) }), "interval"},
		"interval too long":      {mutate(func(r *agentv1.Status) { r.Interval = durationpb.New(MaxInterval + time.Second) }), "interval"},
		"no agent":               {mutate(func(r *agentv1.Status) { r.Origin.AgentId = "" }), "origin.agent_id"},
		"no tenant":              {mutate(func(r *agentv1.Status) { r.Origin.TenantId = "" }), "origin.tenant_id"},
		"no run":                 {mutate(func(r *agentv1.Status) { r.Run = nil }), "run"},
		"no start":               {mutate(func(r *agentv1.Status) { r.Run.StartedAt = nil }), "run.started_at"},
		"undeclared ending":      {mutate(func(r *agentv1.Status) { r.Run.PreviousEnding = agentv1.Status_Ending(42) }), "run.previous_ending"},
		"long previous reason":   {mutate(func(r *agentv1.Status) { r.Run.PreviousReason = long }), "run.previous_reason"},
		"no build":               {mutate(func(r *agentv1.Status) { r.Build = nil }), "build"},
		"no version":             {mutate(func(r *agentv1.Status) { r.Build.Version = "" }), "build.version"},
		"unspecified condition":  {mutate(func(r *agentv1.Status) { r.Condition = agentv1.Status_CONDITION_UNSPECIFIED }), "condition"},
		"undeclared condition":   {mutate(func(r *agentv1.Status) { r.Condition = agentv1.Status_Condition(42) }), "condition"},
		"unnamed component":      {mutate(func(r *agentv1.Status) { r.Components[1].Name = "" }), "components[1].name"},
		"long component reason":  {mutate(func(r *agentv1.Status) { r.Components[0].Reason = long }), "components[0].reason"},
		"unspecified module":     {mutate(func(r *agentv1.Status) { r.Modules[0].Condition = agentv1.Status_CONDITION_UNSPECIFIED }), "modules[0].condition"},
		"invalid module since":   {mutate(func(r *agentv1.Status) { r.Modules[0].Since = &timestamppb.Timestamp{Nanos: -1} }), "modules[0].since"},
		"no spool":               {mutate(func(r *agentv1.Status) { r.Spool = nil }), "spool"},
		"unnamed stream":         {mutate(func(r *agentv1.Status) { r.Spool.Streams[1].Name = "" }), "spool.streams[1].name"},
		"no expiry":              {mutate(func(r *agentv1.Status) { r.Credential.NotAfter = nil }), "credential.not_after"},
		"no configuration":       {mutate(func(r *agentv1.Status) { r.Configuration = nil }), "configuration"},
		"uppercase digest":       {mutate(func(r *agentv1.Status) { r.Configuration.DigestSha256 = strings.Repeat("AB", 32) }), "configuration.digest_sha256"},
		"short digest":           {mutate(func(r *agentv1.Status) { r.Configuration.DigestSha256 = "abcd" }), "configuration.digest_sha256"},
		"no privileges":          {mutate(func(r *agentv1.Status) { r.Privileges = nil }), "privileges"},
		"no user":                {mutate(func(r *agentv1.Status) { r.Privileges.User = "" }), "privileges.user"},
		"empty capability":       {mutate(func(r *agentv1.Status) { r.Privileges.Capabilities = []string{""} }), "privileges.capabilities[0]"},
		"long capability": {mutate(func(r *agentv1.Status) {
			r.Privileges.Capabilities = []string{strings.Repeat("C", MaxCapabilityLength+1)}
		}), "privileges.capabilities[0]"},
		"reported from the future": {mutate(func(r *agentv1.Status) { r.ReportedAt = timestamppb.New(reported.Add(time.Hour)) }), "reported_at"},
		"reported too long ago":    {mutate(func(r *agentv1.Status) { r.ReportedAt = timestamppb.New(reported.Add(-48 * time.Hour)) }), "reported_at"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Validate(one.report, reported, window)
			var violation *event.Violation
			if !errors.As(err, &violation) {
				t.Fatalf("the report was refused without naming a field, or admitted: %v", err)
			}
			if violation.Field != one.field {
				t.Errorf("the refusal names %s and the fault is in %s", violation.Field, one.field)
			}
		})
	}
}

func TestEveryCeilingRefusesOneMore(t *testing.T) {
	for name, one := range map[string]struct {
		report *agentv1.Status
		field  string
	}{
		"components": {mutate(func(r *agentv1.Status) {
			r.Components = make([]*agentv1.Status_Component, MaxComponents+1)
			for i := range r.Components {
				r.Components[i] = &agentv1.Status_Component{Name: "part", Condition: agentv1.Status_CONDITION_RUNNING}
			}
		}), "components"},
		"modules": {mutate(func(r *agentv1.Status) {
			r.Modules = make([]*agentv1.Status_Module, MaxModules+1)
			for i := range r.Modules {
				r.Modules[i] = &agentv1.Status_Module{Name: "module", Condition: agentv1.Status_CONDITION_RUNNING}
			}
		}), "modules"},
		"streams": {mutate(func(r *agentv1.Status) {
			r.Spool.Streams = make([]*agentv1.Status_Stream, MaxStreams+1)
			for i := range r.Spool.Streams {
				r.Spool.Streams[i] = &agentv1.Status_Stream{Name: "stream"}
			}
		}), "spool.streams"},
		"groups":       {mutate(func(r *agentv1.Status) { r.Privileges.Groups = make([]string, MaxGroups+1) }), "privileges.groups"},
		"capabilities": {mutate(func(r *agentv1.Status) { r.Privileges.Capabilities = make([]string, MaxCapabilities+1) }), "privileges.capabilities"},
	} {
		t.Run(name, func(t *testing.T) {
			var violation *event.Violation
			if err := ValidateContract(one.report); !errors.As(err, &violation) || violation.Field != one.field {
				t.Fatalf("one more than the ceiling was answered with %v", err)
			}
		})
	}
}

// What the projector reads back is what the gateway admitted earlier, so its
// own check never refuses a report for having aged on the way.
func TestTheContractAloneIsIndifferentToWhenAReportIsRead(t *testing.T) {
	old := mutate(func(r *agentv1.Status) { r.ReportedAt = timestamppb.New(reported.Add(-365 * 24 * time.Hour)) })
	if err := ValidateContract(old); err != nil {
		t.Fatalf("an old report broke the contract: %v", err)
	}
	if err := Validate(old, reported, window); err == nil {
		t.Fatal("an old report was admitted")
	}
	if !proto.Equal(old, mutate(func(r *agentv1.Status) { r.ReportedAt = timestamppb.New(reported.Add(-365 * 24 * time.Hour)) })) {
		t.Fatal("validating changed the report")
	}
}

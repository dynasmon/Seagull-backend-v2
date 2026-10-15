package agentpolicy_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

var now = written.Add(time.Hour)

func files(paths, exclude []string) *policyv1.ModuleSettings {
	held := &policyv1.ModuleSettings{Module: policyv1.Module_MODULE_FILES, Collection: policyv1.Collection_COLLECTION_ENABLED}
	if paths != nil {
		held.Paths = &policyv1.Paths{Paths: paths}
	}
	if exclude != nil {
		held.Exclude = &policyv1.Paths{Paths: exclude}
	}
	return held
}

func complete() *policyv1.Policy {
	policy := wellFormed()
	policy.Settings = &policyv1.Settings{
		LogLevel: policyv1.LogLevel_LOG_LEVEL_DEBUG,
		Modules: []*policyv1.ModuleSettings{
			{Module: policyv1.Module_MODULE_AUTHENTICATION, Collection: policyv1.Collection_COLLECTION_ENABLED},
			{Module: policyv1.Module_MODULE_INVENTORY, Interval: durationpb.New(6 * time.Hour)},
			{Module: policyv1.Module_MODULE_NETWORK, Collection: policyv1.Collection_COLLECTION_DISABLED, Interval: durationpb.New(30 * time.Second)},
			files([]string{"/etc", "/usr/bin"}, []string{"/etc/machine-id", "*.swp"}),
			{Module: policyv1.Module_MODULE_ASSESSMENT, Collection: policyv1.Collection_COLLECTION_ENABLED, Interval: durationpb.New(12 * time.Hour)},
		},
		Budgets: &policyv1.Budgets{
			SpoolMaxBytes:               256 << 20,
			SpoolMaxAge:                 durationpb.New(48 * time.Hour),
			MaxBatchBytes:               1 << 20,
			MaxEventsPerBatch:           500,
			MaxInventoryRecordsPerBatch: 16,
			MaxUploadBytesPerSecond:     512 << 10,
			MemoryLimitBytes:            128 << 20,
			MaxConcurrentScans:          1,
			MaxScanBytesPerSecond:       4 << 20,
			MaxConcurrentUploads:        1,
		},
		Assessment: &assessmentv1.Checklist{Checks: []*assessmentv1.Check{
			{CheckId: "ssh.root-login", Title: "Nobody logs in as root over ssh", Test: &assessmentv1.Check_Directive{Directive: &assessmentv1.DirectiveTest{
				Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: "PermitRootLogin", Allowed: []string{"no"},
			}}},
			{CheckId: "telnetd", Test: &assessmentv1.Check_Package{Package: &assessmentv1.PackageTest{
				Name: "telnetd", Presence: assessmentv1.Presence_PRESENCE_FORBIDDEN,
			}}},
		}},
	}
	return policy
}

func TestAPolicyWithinEveryBoundIsTaken(t *testing.T) {
	for name, policy := range map[string]*policyv1.Policy{
		"one setting":     wellFormed(),
		"every setting":   complete(),
		"nothing to set":  func() *policyv1.Policy { held := wellFormed(); held.Settings = nil; return held }(),
		"exclusions only": withModule(files(nil, []string{"/var/lib/anything"})),
		"no exclusions":   withModule(files([]string{"/etc"}, []string{})),
		"the longest life": func() *policyv1.Policy {
			held := wellFormed()
			held.ExpiresAt = timestamppb.New(written.Add(agentpolicy.MaxLifetime))
			return held
		}(),
		"ten thousand agents": withTargets(agentpolicy.MaxTargets),
	} {
		t.Run(name, func(t *testing.T) {
			if err := agentpolicy.Validate(policy, now); err != nil {
				t.Fatalf("a policy within every bound was refused: %v", err)
			}
		})
	}
}

func withModule(module *policyv1.ModuleSettings) *policyv1.Policy {
	policy := wellFormed()
	policy.Settings.Modules = []*policyv1.ModuleSettings{module}
	return policy
}

func withTargets(count int) *policyv1.Policy {
	policy := wellFormed()
	policy.Targets.AgentIds = nil
	for index := range count {
		policy.Targets.AgentIds = append(policy.Targets.AgentIds, fmt.Sprintf("agent-%05d", index))
	}
	return policy
}

func TestAPolicyOutsideTheContractIsRefusedNamingWhatIsWrong(t *testing.T) {
	for name, malformed := range map[string]struct {
		change func(*policyv1.Policy)
		names  string
	}{
		"a newer schema":       {func(p *policyv1.Policy) { p.SchemaVersion = 2 }, "schema_version"},
		"no policy id":         {func(p *policyv1.Policy) { p.PolicyId = "" }, "policy_id"},
		"a policy id with a /": {func(p *policyv1.Policy) { p.PolicyId = "linux/web" }, "policy_id"},
		"revision zero":        {func(p *policyv1.Policy) { p.Revision = 0 }, "revision"},
		"no target":            {func(p *policyv1.Policy) { p.Targets = nil }, "targets"},
		"too many targets":     {func(p *policyv1.Policy) { p.Targets = withTargets(agentpolicy.MaxTargets + 1).Targets }, "at most 10000"},
		"a target that is not": {func(p *policyv1.Policy) { p.Targets.AgentIds[1] = "web 02" }, "targets.agent_ids[1]"},
		"a target twice":       {func(p *policyv1.Policy) { p.Targets.AgentIds[1] = "web-01" }, "again"},
		"no issue time":        {func(p *policyv1.Policy) { p.IssuedAt = nil }, "issued_at"},
		"no expiry":            {func(p *policyv1.Policy) { p.ExpiresAt = nil }, "expires_at"},
		"issued ahead":         {func(p *policyv1.Policy) { p.IssuedAt = timestamppb.New(now.Add(10 * time.Minute)) }, "ahead"},
		"ending before issued": {func(p *policyv1.Policy) { p.ExpiresAt = timestamppb.New(written.Add(-time.Second)) }, "not later"},
		"vouched for too long": {func(p *policyv1.Policy) {
			p.ExpiresAt = timestamppb.New(written.Add(agentpolicy.MaxLifetime + time.Second))
		}, "366 days"},
		"an unknown level":      {func(p *policyv1.Policy) { p.Settings.LogLevel = 9 }, "log_level"},
		"no module named":       {func(p *policyv1.Policy) { p.Settings.Modules = []*policyv1.ModuleSettings{{}} }, "names no module"},
		"an unknown module":     {func(p *policyv1.Policy) { p.Settings.Modules = []*policyv1.ModuleSettings{{Module: 99}} }, "names no module"},
		"a module twice":        {func(p *policyv1.Policy) { p.Settings.Modules = append(p.Settings.Modules, p.Settings.Modules[0]) }, "again"},
		"an unknown collection": {func(p *policyv1.Policy) { p.Settings.Modules[0].Collection = 7 }, "collection"},
		"a source interval": {func(p *policyv1.Policy) {
			p.Settings.Modules[0].Interval = durationpb.New(time.Hour)
		}, "follows its source"},
		"a short inventory": {func(p *policyv1.Policy) {
			p.Settings.Modules[1].Interval = durationpb.New(30 * time.Second)
		}, "between 1m0s and 24h0m0s"},
		"a long network": {func(p *policyv1.Policy) {
			p.Settings.Modules[2].Interval = durationpb.New(2 * time.Hour)
		}, "between 10s and 1h0m0s"},
		"a long assessment": {func(p *policyv1.Policy) {
			p.Settings.Modules[4].Interval = durationpb.New(48 * time.Hour)
		}, "between 1m0s and 24h0m0s"},
		"paths for the assessment": {func(p *policyv1.Policy) {
			p.Settings.Modules[4].Paths = &policyv1.Paths{Paths: []string{"/etc"}}
		}, "only the files module"},
		"an empty checklist": {func(p *policyv1.Policy) {
			p.Settings.Assessment.Checks = nil
		}, "settings.assessment.checks name nothing"},
		"a check without a test": {func(p *policyv1.Policy) {
			p.Settings.Assessment.Checks[1].Test = nil
		}, "settings.assessment.checks[1].test"},
		"a check named twice": {func(p *policyv1.Policy) {
			p.Settings.Assessment.Checks[1].CheckId = "ssh.root-login"
		}, "settings.assessment.checks[1].check_id"},
		"an invalid interval": {func(p *policyv1.Policy) {
			p.Settings.Modules[1].Interval = &durationpb.Duration{Seconds: 1, Nanos: -1}
		}, "not a duration"},
		"paths elsewhere": {func(p *policyv1.Policy) {
			p.Settings.Modules[1].Paths = &policyv1.Paths{Paths: []string{"/etc"}}
		}, "only the files module"},
		"no path":           {func(p *policyv1.Policy) { p.Settings.Modules[3].Paths.Paths = nil }, "names nothing"},
		"a relative path":   {func(p *policyv1.Policy) { p.Settings.Modules[3].Paths.Paths[0] = "etc" }, "absolute path"},
		"a path to resolve": {func(p *policyv1.Policy) { p.Settings.Modules[3].Paths.Paths[0] = "/etc/../root" }, "nothing to resolve"},
		"the root":          {func(p *policyv1.Policy) { p.Settings.Modules[3].Paths.Paths[0] = "/" }, "root of the filesystem"},
		"a made-up path":    {func(p *policyv1.Policy) { p.Settings.Modules[3].Paths.Paths[0] = "/proc/self" }, "within /proc"},
		"a path twice":      {func(p *policyv1.Policy) { p.Settings.Modules[3].Paths.Paths[1] = "/etc" }, "again"},
		"too many paths": {func(p *policyv1.Policy) {
			p.Settings.Modules[3].Paths.Paths = numbered(agentpolicy.MaxWatchedPaths + 1)
		}, "at most 64"},
		"a pattern with a /": {func(p *policyv1.Policy) { p.Settings.Modules[3].Exclude.Paths[1] = "cache/*" }, "pattern a name matches"},
		"a broken pattern":   {func(p *policyv1.Policy) { p.Settings.Modules[3].Exclude.Paths[1] = "[" }, "pattern a name matches"},
		"an outside exclusion": {func(p *policyv1.Policy) {
			p.Settings.Modules[3].Exclude.Paths[0] = "/var/log"
		}, "within none"},
		"a whole path excluded": {func(p *policyv1.Policy) {
			p.Settings.Modules[3].Exclude.Paths[0] = "/usr"
		}, "whole path"},
		"too many exclusions": {func(p *policyv1.Policy) {
			p.Settings.Modules[3].Exclude.Paths = numbered(agentpolicy.MaxExcluded + 1)
		}, "at most 256"},
		"a tiny spool":     {func(p *policyv1.Policy) { p.Settings.Budgets.SpoolMaxBytes = 1 << 20 }, "spool_max_bytes"},
		"a huge memory":    {func(p *policyv1.Policy) { p.Settings.Budgets.MemoryLimitBytes = 9 << 30 }, "memory_limit_bytes"},
		"too many events":  {func(p *policyv1.Policy) { p.Settings.Budgets.MaxEventsPerBatch = 1001 }, "max_events_per_batch"},
		"too many uploads": {func(p *policyv1.Policy) { p.Settings.Budgets.MaxConcurrentUploads = 17 }, "max_concurrent_uploads"},
		"a short spool age": {func(p *policyv1.Policy) {
			p.Settings.Budgets.SpoolMaxAge = durationpb.New(30 * time.Minute)
		}, "spool_max_age"},
	} {
		t.Run(name, func(t *testing.T) {
			policy := complete()
			malformed.change(policy)
			err := agentpolicy.Validate(policy, now)
			if !errors.Is(err, agentpolicy.ErrMalformed) {
				t.Fatalf("the policy was answered %v", err)
			}
			if !strings.Contains(err.Error(), malformed.names) {
				t.Fatalf("the refusal does not say %q: %v", malformed.names, err)
			}
		})
	}
}

func numbered(count int) []string {
	held := make([]string, 0, count)
	for index := range count {
		held = append(held, fmt.Sprintf("/etc/entry-%03d", index))
	}
	return held
}

func TestAPolicyAlreadyExpiredIsRefusedAsExpired(t *testing.T) {
	policy := wellFormed()
	err := agentpolicy.Validate(policy, policy.GetExpiresAt().AsTime())
	if !errors.Is(err, agentpolicy.ErrExpired) || errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("a policy at its expiry was answered %v", err)
	}
}

func TestARefusalNamesABoundedNumberOfProblems(t *testing.T) {
	policy := withTargets(agentpolicy.MaxTargets)
	for index := range policy.Targets.AgentIds {
		policy.Targets.AgentIds[index] = "not an agent"
	}
	err := agentpolicy.Validate(policy, now)
	if !errors.Is(err, agentpolicy.ErrMalformed) {
		t.Fatalf("the policy was answered %v", err)
	}
	if strings.Count(err.Error(), "not an agent identifier") != agentpolicy.MaxProblems ||
		!strings.Contains(err.Error(), fmt.Sprintf("and %d more", agentpolicy.MaxTargets-agentpolicy.MaxProblems)) {
		t.Fatalf("the refusal is not bounded: %d bytes", len(err.Error()))
	}
}

func TestValidatingReadsThePolicyAndChangesNothing(t *testing.T) {
	policy := complete()
	before := proto.Clone(policy)
	if err := agentpolicy.Validate(policy, now); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !proto.Equal(policy, before) {
		t.Fatal("validating changed the policy")
	}
}

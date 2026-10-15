package agentpolicy

import (
	"errors"
	"fmt"
	"math"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/assessment"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	MaxTargets      = 10_000
	MaxLifetime     = 366 * 24 * time.Hour
	MaxClockSkew    = 5 * time.Minute
	MaxWatchedPaths = 64
	MaxExcluded     = 256
	MaxPathBytes    = 4 << 10
	MaxNameBytes    = 255
	MaxProblems     = 16
)

var ErrExpired = errors.New("the policy has expired")

type span struct {
	least, most time.Duration
}

type ceiling struct {
	name        string
	value       uint64
	least, most uint64
}

var (
	intervals = map[policyv1.Module]span{
		policyv1.Module_MODULE_INVENTORY:  {least: time.Minute, most: 24 * time.Hour},
		policyv1.Module_MODULE_PROCESSES:  {least: time.Minute, most: 24 * time.Hour},
		policyv1.Module_MODULE_FILES:      {least: time.Minute, most: 24 * time.Hour},
		policyv1.Module_MODULE_NETWORK:    {least: 10 * time.Second, most: time.Hour},
		policyv1.Module_MODULE_ASSESSMENT: {least: time.Minute, most: 24 * time.Hour},
	}
	unwatched = []string{"/proc", "/sys", "/dev", "/tmp", "/var/tmp"}
	spoolAge  = span{least: time.Hour, most: 720 * time.Hour}
)

// Everything the contract bounds, checked whole so a refusal names every
// setting that is wrong at once. What an agent's own configuration adds — a
// ceiling lower than the policy's, a path within its own state — is the agent's
// to check, and it refuses such a policy as well.
func Validate(policy *policyv1.Policy, now time.Time) error {
	found := &problems{}
	if policy.GetSchemaVersion() != SchemaVersion {
		found.add(fmt.Errorf("schema_version is %d, and the platform reads %d", policy.GetSchemaVersion(), SchemaVersion))
	}
	if !agentidentity.Valid(policy.GetPolicyId()) {
		found.add(fmt.Errorf("policy_id is %s, and it is an identifier of at most 64 letters, digits, dots, dashes and underscores",
			strconv.Quote(bounded(policy.GetPolicyId()))))
	}
	switch {
	case policy.GetRevision() == 0:
		found.add(errors.New("revision is 0, and revisions start at 1"))
	case policy.GetRevision() > math.MaxInt64:
		found.add(fmt.Errorf("revision is %d, and the platform records revisions up to %d", policy.GetRevision(), int64(math.MaxInt64)))
	}
	targets(found, policy.GetTargets().GetAgentIds())
	settings(found, policy.GetSettings())
	expired := times(found, policy, now)
	if err := found.err(); err != nil {
		return err
	}
	return expired
}

func targets(found *problems, ids []string) {
	switch {
	case len(ids) == 0:
		found.add(errors.New("targets name no agent, and a policy that names nobody applies to nobody"))
		return
	case len(ids) > MaxTargets:
		found.add(fmt.Errorf("targets name %d agents, and a policy names at most %d", len(ids), MaxTargets))
		return
	}
	seen := make(map[string]struct{}, len(ids))
	for index, id := range ids {
		if !agentidentity.Valid(id) {
			found.add(fmt.Errorf("targets.agent_ids[%d] is %s, which is not an agent identifier", index, strconv.Quote(bounded(id))))
			continue
		}
		if _, twice := seen[id]; twice {
			found.add(fmt.Errorf("targets.agent_ids[%d] names %s again", index, id))
		}
		seen[id] = struct{}{}
	}
}

func times(found *problems, policy *policyv1.Policy, now time.Time) error {
	issued, expires := policy.GetIssuedAt(), policy.GetExpiresAt()
	unwritten := issued == nil || issued.CheckValid() != nil
	unbounded := expires == nil || expires.CheckValid() != nil
	if unwritten {
		found.add(errors.New("issued_at is not set, and a policy says when its signer wrote it"))
	}
	if unbounded {
		found.add(errors.New("expires_at is not set, and a policy says until when its signer vouches for it"))
	}
	if unwritten || unbounded {
		return nil
	}
	written, ending := issued.AsTime(), expires.AsTime()
	switch {
	case written.After(now.Add(MaxClockSkew)):
		found.add(fmt.Errorf("issued_at is %s, more than %s ahead of the platform's clock", written.UTC().Format(time.RFC3339), MaxClockSkew))
	case !ending.After(written):
		found.add(errors.New("expires_at is not later than issued_at"))
	case ending.Sub(written) > MaxLifetime:
		found.add(fmt.Errorf("expires_at is %s after issued_at, and a signer vouches for a policy for at most 366 days", ending.Sub(written)))
	case !ending.After(now):
		return fmt.Errorf("%w: it expired at %s", ErrExpired, ending.UTC().Format(time.RFC3339))
	}
	return nil
}

func settings(found *problems, held *policyv1.Settings) {
	if _, known := policyv1.LogLevel_name[int32(held.GetLogLevel())]; !known {
		found.add(fmt.Errorf("settings.log_level is %d, which names no level", held.GetLogLevel()))
	}
	seen := map[policyv1.Module]bool{}
	for index, module := range held.GetModules() {
		name := fmt.Sprintf("settings.modules[%d]", index)
		named := module.GetModule()
		if _, known := policyv1.Module_name[int32(named)]; !known || named == policyv1.Module_MODULE_UNSPECIFIED {
			found.add(fmt.Errorf("%s names no module the contract has", name))
			continue
		}
		if seen[named] {
			found.add(fmt.Errorf("%s names %s again", name, named))
		}
		seen[named] = true
		if _, known := policyv1.Collection_name[int32(module.GetCollection())]; !known {
			found.add(fmt.Errorf("%s.collection is %d, which says neither enabled nor disabled", name, module.GetCollection()))
		}
		interval(found, name, named, module.GetInterval())
		scope(found, name, named, module)
	}
	budgets(found, held.GetBudgets())
	if checklist := held.GetAssessment(); checklist != nil {
		for _, problem := range assessment.ValidateChecklist(checklist) {
			found.add(fmt.Errorf("settings.assessment.%w", problem))
		}
	}
}

func interval(found *problems, name string, module policyv1.Module, every *durationpb.Duration) {
	if every == nil {
		return
	}
	if every.CheckValid() != nil {
		found.add(fmt.Errorf("%s.interval is not a duration", name))
		return
	}
	value := every.AsDuration()
	if value == 0 {
		return
	}
	bounds, takesStock := intervals[module]
	switch {
	case !takesStock:
		found.add(fmt.Errorf("%s.interval is set, and the %s module follows its source rather than take stock every interval", name, module))
	case value < bounds.least || value > bounds.most:
		found.add(fmt.Errorf("%s.interval is %s, and the %s module takes between %s and %s", name, value, module, bounds.least, bounds.most))
	}
}

func scope(found *problems, name string, module policyv1.Module, held *policyv1.ModuleSettings) {
	watched, excluded := held.GetPaths(), held.GetExclude()
	if module != policyv1.Module_MODULE_FILES {
		if watched != nil || excluded != nil {
			found.add(fmt.Errorf("%s names paths, and only the files module watches any", name))
		}
		return
	}
	if watched != nil {
		paths := watched.GetPaths()
		switch {
		case len(paths) == 0:
			found.add(fmt.Errorf("%s.paths names nothing, and the files module watches the paths it is given", name))
		case len(paths) > MaxWatchedPaths:
			found.add(fmt.Errorf("%s.paths names %d paths, and the files module watches at most %d", name, len(paths), MaxWatchedPaths))
		}
		for index, written := range paths {
			entry := fmt.Sprintf("%s.paths[%d]", name, index)
			switch made := slices.IndexFunc(unwatched, func(held string) bool { return within(written, held) }); {
			case !absolute(found, entry, written):
			case made >= 0:
				found.add(fmt.Errorf("%s is within %s, which holds what the kernel or a service makes up rather than files a host keeps", entry, unwatched[made]))
			case slices.Index(paths, written) < index:
				found.add(fmt.Errorf("%s names %s again", entry, strconv.Quote(written)))
			}
		}
	}
	if excluded == nil {
		return
	}
	entries := excluded.GetPaths()
	if len(entries) > MaxExcluded {
		found.add(fmt.Errorf("%s.exclude names %d entries, and the files module leaves out at most %d", name, len(entries), MaxExcluded))
	}
	for index, written := range entries {
		entry := fmt.Sprintf("%s.exclude[%d]", name, index)
		if slices.Index(entries, written) < index {
			found.add(fmt.Errorf("%s names %s again", entry, strconv.Quote(bounded(written))))
			continue
		}
		if !strings.HasPrefix(written, "/") {
			if _, err := path.Match(written, ""); err != nil || written == "" || len(written) > MaxNameBytes || strings.Contains(written, "/") {
				found.add(fmt.Errorf("%s is %s, and it is an absolute path or a pattern a name matches, such as %q",
					entry, strconv.Quote(bounded(written)), "*.swp"))
			}
			continue
		}
		if !absolute(found, entry, written) || watched == nil {
			continue
		}
		switch paths := watched.GetPaths(); {
		case slices.ContainsFunc(paths, func(held string) bool { return within(held, written) }):
			found.add(fmt.Errorf("%s leaves out a whole path %s.paths names", entry, name))
		case !slices.ContainsFunc(paths, func(held string) bool { return strings.HasPrefix(written, held+"/") }):
			found.add(fmt.Errorf("%s is within none of the paths %s.paths names", entry, name))
		}
	}
}

func absolute(found *problems, name, written string) bool {
	switch {
	case written == "":
		found.add(fmt.Errorf("%s is empty, and it names an absolute path", name))
	case len(written) > MaxPathBytes:
		found.add(fmt.Errorf("%s is longer than %d bytes", name, MaxPathBytes))
	case !strings.HasPrefix(written, "/") || path.Clean(written) != written:
		found.add(fmt.Errorf("%s is %s, and it is an absolute path with nothing to resolve", name, strconv.Quote(bounded(written))))
	case written == "/":
		found.add(fmt.Errorf("%s is the root of the filesystem", name))
	default:
		return true
	}
	return false
}

func within(written, held string) bool {
	return written == held || strings.HasPrefix(written, held+"/")
}

func budgets(found *problems, held *policyv1.Budgets) {
	for _, each := range []ceiling{
		{name: "spool_max_bytes", value: held.GetSpoolMaxBytes(), least: 16 << 20, most: 64 << 30},
		{name: "max_batch_bytes", value: held.GetMaxBatchBytes(), least: 64 << 10, most: 8 << 20},
		{name: "max_events_per_batch", value: uint64(held.GetMaxEventsPerBatch()), least: 1, most: 1000},
		{name: "max_inventory_records_per_batch", value: uint64(held.GetMaxInventoryRecordsPerBatch()), least: 1, most: 64},
		{name: "max_upload_bytes_per_second", value: held.GetMaxUploadBytesPerSecond(), least: 64 << 10, most: 1 << 30},
		{name: "memory_limit_bytes", value: held.GetMemoryLimitBytes(), least: 64 << 20, most: 8 << 30},
		{name: "max_concurrent_scans", value: uint64(held.GetMaxConcurrentScans()), least: 1, most: 64},
		{name: "max_scan_bytes_per_second", value: held.GetMaxScanBytesPerSecond(), least: 1 << 20, most: 1 << 30},
		{name: "max_concurrent_uploads", value: uint64(held.GetMaxConcurrentUploads()), least: 1, most: 16},
	} {
		if each.value != 0 && (each.value < each.least || each.value > each.most) {
			found.add(fmt.Errorf("settings.budgets.%s is %d, and an agent takes between %d and %d", each.name, each.value, each.least, each.most))
		}
	}
	age := held.GetSpoolMaxAge()
	switch {
	case age == nil:
	case age.CheckValid() != nil:
		found.add(errors.New("settings.budgets.spool_max_age is not a duration"))
	case age.AsDuration() != 0 && (age.AsDuration() < spoolAge.least || age.AsDuration() > spoolAge.most):
		found.add(fmt.Errorf("settings.budgets.spool_max_age is %s, and an agent takes between %s and %s", age.AsDuration(), spoolAge.least, spoolAge.most))
	}
}

type problems struct {
	held  []error
	count int
}

func (p *problems) add(err error) {
	p.count++
	if len(p.held) < MaxProblems {
		p.held = append(p.held, err)
	}
}

func (p *problems) err() error {
	if p.count == 0 {
		return nil
	}
	held := p.held
	if p.count > len(held) {
		held = append(slices.Clone(held), fmt.Errorf("and %d more", p.count-len(held)))
	}
	return fmt.Errorf("%w: %w", ErrMalformed, errors.Join(held...))
}

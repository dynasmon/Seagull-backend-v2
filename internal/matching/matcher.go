package matching

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

const settleWarning = 30 * time.Second

type Owner struct {
	Topic string
	Group string
}

type Owners struct {
	Inventory  Owner
	Advisories Owner
	Findings   Owner
}

type Options struct {
	Source        Source
	Positions     Positions
	Inventory     Inventory
	Intelligence  Intelligence
	Findings      Findings
	Publisher     Publisher
	Owners        Owners
	Policy        finding.Policy
	SettleDelay   time.Duration
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
	Metrics       *Metrics
	Logger        *slog.Logger
	Now           func() time.Time
}

type Matcher struct {
	source        Source
	positions     Positions
	inventory     Inventory
	intelligence  Intelligence
	findings      Findings
	publisher     Publisher
	owners        Owners
	policy        finding.Policy
	settleDelay   time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration
	metrics       *Metrics
	logger        *slog.Logger
	now           func() time.Time
}

func NewMatcher(options Options) (*Matcher, error) {
	switch {
	case options.Source == nil || options.Positions == nil || options.Publisher == nil:
		return nil, errors.New("the vulnerability matcher needs a backbone to read, positions to wait on and somewhere to publish")
	case options.Inventory == nil || options.Intelligence == nil || options.Findings == nil:
		return nil, errors.New("the vulnerability matcher needs the inventory, the intelligence and the findings it decides from")
	case options.Owners.Inventory.Topic == "" || options.Owners.Inventory.Group == "" ||
		options.Owners.Advisories.Topic == "" || options.Owners.Advisories.Group == "" ||
		options.Owners.Findings.Topic == "" || options.Owners.Findings.Group == "":
		return nil, errors.New("the vulnerability matcher needs the topic and group of every store's owner")
	case options.Policy.Freshness <= 0:
		return nil, errors.New("the vulnerability matcher needs a positive freshness bound")
	case options.SettleDelay <= 0 || options.RetryDelay <= 0 || options.MaxRetryDelay < options.RetryDelay:
		return nil, errors.New("the vulnerability matcher needs positive delays, the retry one below its ceiling")
	case options.Metrics == nil || options.Logger == nil || options.Now == nil:
		return nil, errors.New("the vulnerability matcher needs metrics, a logger and a clock")
	}
	return &Matcher{
		source:        options.Source,
		positions:     options.Positions,
		inventory:     options.Inventory,
		intelligence:  options.Intelligence,
		findings:      options.Findings,
		publisher:     options.Publisher,
		owners:        options.Owners,
		policy:        options.Policy,
		settleDelay:   options.SettleDelay,
		retryDelay:    options.RetryDelay,
		maxRetryDelay: options.MaxRetryDelay,
		metrics:       options.Metrics,
		logger:        options.Logger,
		now:           options.Now,
	}, nil
}

func (m *Matcher) Name() string { return "vulnerability-matcher" }

func (m *Matcher) Run(ctx context.Context) error { return m.source.Consume(ctx, m.handle) }

// Retried until published or stopping. An outage of a store or of its owner is
// lag the matcher waits out, and a decision it cannot publish is a batch it
// keeps, never one it steps over.
func (m *Matcher) handle(ctx context.Context, records []Record) error {
	m.metrics.observeBatch(len(records))
	delay := m.retryDelay
	for attempt := 1; ; attempt++ {
		err := m.decide(ctx, records)
		if err == nil {
			m.metrics.batch("published")
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.metrics.batch("retried")
		m.logger.Error("finding_batch_not_published",
			slog.Int("attempt", attempt),
			slog.Int("records", len(records)),
			slog.Duration("retry_in", delay),
			slog.String("error", err.Error()),
		)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay = min(delay*2, m.maxRetryDelay)
	}
}

func (m *Matcher) decide(ctx context.Context, records []Record) error {
	if err := m.settle(ctx, records); err != nil {
		return err
	}
	assets, changed, err := m.triggers(ctx, records)
	if err != nil {
		return err
	}
	for _, asset := range assets {
		if err := m.whole(ctx, asset); err != nil {
			return err
		}
	}
	if len(changed) == 0 {
		return nil
	}
	holders, err := m.inventory.Holders(ctx, packagesOf(changed))
	if err != nil {
		return fmt.Errorf("find the assets holding what %d advisories name: %w", len(changed), err)
	}
	slices.SortFunc(holders, compareAssets)
	for _, holder := range slices.Compact(holders) {
		if _, assessed := slices.BinarySearchFunc(assets, holder, compareAssets); assessed {
			continue
		}
		if err := m.partial(ctx, holder, changed); err != nil {
			return err
		}
	}
	return nil
}

// Each owner commits only once its batch is durable, so waiting for its
// committed offset to pass a record waits for the record to be in its store.
// The findings writer is waited on up to where the findings stream ends, so
// every decision published before, by this process or one that stopped, is
// read back as the past of the next one.
func (m *Matcher) settle(ctx context.Context, records []Record) error {
	wanted := map[Owner]map[int32]int64{}
	for _, record := range records {
		owner := m.owners.Advisories
		if record.Topic == m.owners.Inventory.Topic {
			owner = m.owners.Inventory
		}
		if wanted[owner] == nil {
			wanted[owner] = map[int32]int64{}
		}
		wanted[owner][record.Partition] = max(wanted[owner][record.Partition], record.Offset+1)
	}
	ends, err := m.positions.Ends(ctx, m.owners.Findings.Topic)
	if err != nil {
		return fmt.Errorf("read where the findings end: %w", err)
	}
	wanted[m.owners.Findings] = ends

	for _, owner := range []Owner{m.owners.Inventory, m.owners.Advisories, m.owners.Findings} {
		needed := wanted[owner]
		started, warned := m.now(), false
		for {
			committed, err := m.positions.Committed(ctx, owner.Group, owner.Topic)
			if err != nil {
				return fmt.Errorf("read where %s stands: %w", owner.Group, err)
			}
			if reached(committed, needed) {
				break
			}
			if waited := m.now().Sub(started); waited > settleWarning && !warned {
				warned = true
				m.logger.Warn("owner_not_settled", slog.String("group", owner.Group), slog.String("topic", owner.Topic), slog.Duration("waited", waited))
			}
			select {
			case <-time.After(m.settleDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		m.metrics.settled(owner.Group, m.now().Sub(started))
	}
	return nil
}

func reached(committed, needed map[int32]int64) bool {
	for partition, offset := range needed {
		if committed[partition] < offset {
			return false
		}
	}
	return true
}

func (m *Matcher) triggers(ctx context.Context, records []Record) ([]Asset, map[Key]bool, error) {
	assets := map[Asset]bool{}
	changed := map[Key]bool{}
	for _, record := range records {
		if record.Topic == m.owners.Inventory.Topic {
			var observed inventoryv1.Record
			if err := proto.Unmarshal(record.Value, &observed); err != nil {
				m.metrics.trigger("inventory", "unreadable")
				continue
			}
			if kind := observed.GetKind(); kind != inventoryv1.Kind_KIND_PACKAGE && kind != inventoryv1.Kind_KIND_OPERATING_SYSTEM {
				m.metrics.trigger("inventory", "ignored")
				continue
			}
			assets[Asset{TenantID: observed.GetOrigin().GetTenantId(), AgentID: observed.GetOrigin().GetAgentId()}] = true
			m.metrics.trigger("inventory", "assessed")
			continue
		}

		var read vulnerabilityv1.Record
		if err := proto.Unmarshal(record.Value, &read); err != nil {
			m.metrics.trigger("advisory", "unreadable")
			continue
		}
		advisory := read.GetAdvisory()
		if advisory == nil {
			m.metrics.trigger("advisory", "ignored")
			continue
		}
		for _, entry := range advisory.GetAffected() {
			changed[Key{Ecosystem: entry.GetEcosystem(), Package: entry.GetName()}] = true
		}
		before, err := m.intelligence.Before(ctx, advisory.GetSource(), advisory.GetId(), advisory.GetModified().AsTime(), advisory.GetProvenance().GetNormalization())
		if err != nil {
			return nil, nil, fmt.Errorf("read what advisory %s named before: %w", advisory.GetId(), err)
		}
		for _, key := range before {
			changed[key] = true
		}
		m.metrics.trigger("advisory", "assessed")
	}

	sorted := make([]Asset, 0, len(assets))
	for asset := range assets {
		sorted = append(sorted, asset)
	}
	slices.SortFunc(sorted, compareAssets)
	return sorted, changed, nil
}

func (m *Matcher) whole(ctx context.Context, asset Asset) error {
	decidedAt := m.now()
	held, found, err := m.inventory.Asset(ctx, asset)
	if err != nil {
		return fmt.Errorf("read the inventory of agent %s: %w", asset.AgentID, err)
	}
	if !found {
		m.metrics.assessed(vulnerabilityv1.Assessment_SCOPE_ASSET, "nothing_stored")
		return nil
	}
	var intelligence finding.Intelligence
	if ecosystem, advised := advisedOf(held); ecosystem != "" {
		if intelligence, err = m.intelligence.Read(ctx, ecosystem, advised); err != nil {
			return fmt.Errorf("read the intelligence of %s: %w", ecosystem, err)
		}
	}
	previous, err := m.findings.Decisions(ctx, asset)
	if err != nil {
		return fmt.Errorf("read the findings of agent %s: %w", asset.AgentID, err)
	}
	return m.publish(ctx, finding.Assess(held, intelligence, previous, decidedAt, m.policy))
}

// An asset holding a package an advisory names under the name of another
// ecosystem, or one the platform cannot place, has nothing an advisory change
// decides; one that decided nothing publishes nothing.
func (m *Matcher) partial(ctx context.Context, asset Asset, changed map[Key]bool) error {
	decidedAt := m.now()
	held, found, err := m.inventory.Asset(ctx, asset)
	if err != nil {
		return fmt.Errorf("read the inventory of agent %s: %w", asset.AgentID, err)
	}
	if !found {
		return nil
	}
	ecosystem, advised := advisedOf(held)
	var concerned []string
	for _, name := range advised {
		if changed[Key{Ecosystem: ecosystem, Package: name}] {
			concerned = append(concerned, name)
		}
	}
	if len(concerned) == 0 {
		return nil
	}
	intelligence, err := m.intelligence.Read(ctx, ecosystem, concerned)
	if err != nil {
		return fmt.Errorf("read the intelligence of %s: %w", ecosystem, err)
	}
	previous, err := m.findings.Decisions(ctx, asset)
	if err != nil {
		return fmt.Errorf("read the findings of agent %s: %w", asset.AgentID, err)
	}
	evaluation := finding.AssessPackages(held, intelligence, previous, concerned, decidedAt, m.policy)
	if len(evaluation.Findings) == 0 {
		m.metrics.assessed(vulnerabilityv1.Assessment_SCOPE_PACKAGES, "nothing_decided")
		return nil
	}
	return m.publish(ctx, evaluation)
}

func (m *Matcher) publish(ctx context.Context, evaluation finding.Evaluation) error {
	records := make([]*vulnerabilityv1.FindingRecord, 0, len(evaluation.Findings)+1)
	for _, decided := range evaluation.Findings {
		records = append(records, &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Finding{Finding: decided}})
	}
	records = append(records, &vulnerabilityv1.FindingRecord{Record: &vulnerabilityv1.FindingRecord_Assessment{Assessment: evaluation.Assessment}})
	for _, record := range records {
		if err := finding.ValidateRecord(record); err != nil {
			return fmt.Errorf("a decision about agent %s breaks the contract the writer holds it to: %w", evaluation.Assessment.GetAgentId(), err)
		}
	}
	if err := m.publisher.Publish(ctx, records); err != nil {
		return fmt.Errorf("publish %d records about agent %s: %w", len(records), evaluation.Assessment.GetAgentId(), err)
	}
	outcome := "assessed"
	if evaluation.Assessment.GetUnassessable() != vulnerabilityv1.Unassessable_UNASSESSABLE_UNSPECIFIED {
		outcome = "unassessable"
	}
	m.metrics.assessed(evaluation.Assessment.GetScope(), outcome)
	m.metrics.decided(evaluation.Findings)
	return nil
}

func advisedOf(held finding.Asset) (string, []string) {
	ecosystem, err := vulnerability.EcosystemOf(held.System)
	if err != nil {
		return "", nil
	}
	var advised []string
	for _, item := range held.Packages {
		if placed, err := vulnerability.PackageOf(held.System, item.Package); err == nil {
			advised = append(advised, placed.Key.Package)
		}
	}
	slices.Sort(advised)
	return ecosystem, slices.Compact(advised)
}

func packagesOf(changed map[Key]bool) []string {
	var named []string
	for key := range changed {
		named = append(named, key.Package)
	}
	slices.Sort(named)
	return slices.Compact(named)
}

func compareAssets(a, b Asset) int {
	return cmp.Or(cmp.Compare(a.TenantID, b.TenantID), cmp.Compare(a.AgentID, b.AgentID))
}

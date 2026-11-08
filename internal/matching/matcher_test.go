package matching

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/finding"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var (
	scanned = time.Date(2026, time.November, 8, 6, 0, 0, 0, time.UTC)
	owners  = Owners{
		Inventory:  Owner{Topic: "security.inventory.raw", Group: "inventory-projector"},
		Advisories: Owner{Topic: "security.advisories", Group: "advisory-writer"},
		Findings:   Owner{Topic: "security.findings", Group: "finding-writer"},
	}
	debian  = Asset{TenantID: "acme", AgentID: "web-01"}
	another = Asset{TenantID: "acme", AgentID: "web-02"}
	alpine  = Asset{TenantID: "acme", AgentID: "edge-01"}
)

type positions struct {
	mu        sync.Mutex
	committed map[string]map[int32]int64
	ends      map[int32]int64
	asked     int
	catchUp   int
}

func (p *positions) Committed(_ context.Context, group, _ string) (map[int32]int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked++
	if p.asked == p.catchUp {
		p.committed["inventory-projector"] = map[int32]int64{0: 100}
		p.committed["advisory-writer"] = map[int32]int64{0: 100}
		p.committed["finding-writer"] = maps.Clone(p.ends)
	}
	return maps.Clone(p.committed[group]), nil
}

func (p *positions) Ends(context.Context, string) (map[int32]int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.ends), nil
}

func settledPositions() *positions {
	return &positions{
		committed: map[string]map[int32]int64{
			"inventory-projector": {0: 100}, "advisory-writer": {0: 100}, "finding-writer": {0: 7},
		},
		ends: map[int32]int64{0: 7},
	}
}

type inventory struct {
	assets   map[Asset]finding.Asset
	holders  map[string][]Asset
	failures int
}

func (i *inventory) Asset(_ context.Context, asset Asset) (finding.Asset, bool, error) {
	if i.failures > 0 {
		i.failures--
		return finding.Asset{}, false, errors.New("the inventory store is away")
	}
	held, found := i.assets[asset]
	return held, found, nil
}

func (i *inventory) Holders(_ context.Context, packages []string) ([]Asset, error) {
	var holders []Asset
	for _, name := range packages {
		holders = append(holders, i.holders[name]...)
	}
	return holders, nil
}

type intelligence struct {
	advisories []finding.Advisory
	before     []Key
}

func (i *intelligence) Read(_ context.Context, ecosystem string, packages []string) (finding.Intelligence, error) {
	var advisories []finding.Advisory
	for _, advisory := range i.advisories {
		for _, entry := range advisory.Affected {
			if entry.GetEcosystem() == ecosystem && slices.Contains(packages, entry.GetName()) {
				advisories = append(advisories, advisory)
				break
			}
		}
	}
	feed := finding.Feed{Source: "osv", Name: "Debian", SyncedAt: scanned.Add(-time.Hour)}
	return finding.Intelligence{Advisories: advisories, Feed: feed, AsOf: scanned.Add(-time.Hour)}, nil
}

func (i *intelligence) Before(context.Context, string, string, time.Time, uint32) ([]Key, error) {
	return i.before, nil
}

type decisions struct {
	decided map[Asset]map[finding.Name]*vulnerabilityv1.Finding
}

func (d *decisions) Decisions(_ context.Context, asset Asset) (map[finding.Name]*vulnerabilityv1.Finding, error) {
	return d.decided[asset], nil
}

type publisher struct {
	mu      sync.Mutex
	records []*vulnerabilityv1.FindingRecord
}

func (p *publisher) Publish(_ context.Context, records []*vulnerabilityv1.FindingRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, records...)
	return nil
}

func (p *publisher) assessments() map[string]vulnerabilityv1.Assessment_Scope {
	scopes := map[string]vulnerabilityv1.Assessment_Scope{}
	for _, record := range p.records {
		if assessed := record.GetAssessment(); assessed != nil {
			scopes[assessed.GetAgentId()] = assessed.GetScope()
		}
	}
	return scopes
}

type source struct {
	records   []Record
	committed bool
}

func (s *source) Consume(ctx context.Context, deliver Deliver) error {
	if err := deliver(ctx, s.records); err != nil {
		return err
	}
	s.committed = true
	return nil
}

func itemOf(name string) string {
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:])
}

func host(asset Asset, platform, version string, packages ...*inventoryv1.Package) finding.Asset {
	held := finding.Asset{
		TenantID: asset.TenantID, AgentID: asset.AgentID,
		System: &inventoryv1.OperatingSystem{Platform: platform, Version: version},
		Scan:   finding.Scan{RecordID: "inv-0000000001", ScannedAt: scanned},
		AsOf:   scanned,
	}
	for _, installed := range packages {
		held.Packages = append(held.Packages, finding.Item{ID: itemOf(asset.AgentID + installed.GetName()), Package: installed, RecordID: "inv-0000000001", LastSeen: scanned})
	}
	return held
}

func libssl(version string) *inventoryv1.Package {
	return &inventoryv1.Package{Name: "libssl3", Version: version, Architecture: "amd64", Manager: "dpkg", Source: "openssl"}
}

func dsa() finding.Advisory {
	return finding.Advisory{
		Source: "osv", ID: "DSA-5764-1", Modified: scanned.Add(-2 * time.Hour), Normalization: 1, Upstream: []string{"CVE-2024-6119"},
		Affected: []*vulnerabilityv1.Affected{{
			Ecosystem: "Debian:12", Name: "openssl",
			Ranges: []*vulnerabilityv1.Range{{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
				{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "0"}},
				{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: "3.0.14-1~deb12u2"}},
			}}},
		}},
	}
}

func inventoryRecord(t *testing.T, asset Asset, kind inventoryv1.Kind, offset int64) Record {
	t.Helper()
	value, err := proto.Marshal(&inventoryv1.Record{Kind: kind, Origin: &eventv1.Origin{TenantId: asset.TenantID, AgentId: asset.AgentID}})
	if err != nil {
		t.Fatalf("encode an inventory record: %v", err)
	}
	return Record{Topic: owners.Inventory.Topic, Partition: 0, Offset: offset, Value: value}
}

func advisoryRecord(t *testing.T, offset int64) Record {
	t.Helper()
	value, err := proto.Marshal(&vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Advisory{Advisory: &vulnerabilityv1.Advisory{
		Source: "osv", Id: "DSA-5764-1", Modified: timestamppb.New(scanned.Add(-2 * time.Hour)),
		Affected:   []*vulnerabilityv1.Affected{{Ecosystem: "Debian:12", Name: "openssl"}},
		Provenance: &vulnerabilityv1.Provenance{Normalization: 1},
	}}})
	if err != nil {
		t.Fatalf("encode an advisory record: %v", err)
	}
	return Record{Topic: owners.Advisories.Topic, Partition: 0, Offset: offset, Value: value}
}

type world struct {
	source       *source
	positions    *positions
	inventory    *inventory
	intelligence *intelligence
	findings     *decisions
	published    *publisher
}

func matcherOver(t *testing.T, w world) *Matcher {
	t.Helper()
	clock := scanned.Add(time.Hour)
	if w.intelligence == nil {
		w.intelligence = &intelligence{advisories: []finding.Advisory{dsa()}}
	}
	if w.findings == nil {
		w.findings = &decisions{}
	}
	built, err := NewMatcher(Options{
		Source:        w.source,
		Positions:     w.positions,
		Inventory:     w.inventory,
		Intelligence:  w.intelligence,
		Findings:      w.findings,
		Publisher:     w.published,
		Owners:        owners,
		Policy:        finding.Policy{Freshness: 48 * time.Hour},
		SettleDelay:   time.Millisecond,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:           func() time.Time { clock = clock.Add(time.Second); return clock },
	})
	if err != nil {
		t.Fatalf("build the matcher: %v", err)
	}
	return built
}

func TestABatchIsDecidedOnlyOnceTheOwnerOfItsRecordsStoredThem(t *testing.T) {
	waiting := settledPositions()
	waiting.committed["inventory-projector"] = map[int32]int64{0: 3}
	waiting.catchUp = 4
	w := world{
		source:    &source{records: []Record{inventoryRecord(t, debian, inventoryv1.Kind_KIND_PACKAGE, 5)}},
		positions: waiting,
		inventory: &inventory{assets: map[Asset]finding.Asset{debian: host(debian, "debian", "12", libssl("3.0.11-1~deb12u2"))}},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	if waiting.asked < waiting.catchUp {
		t.Fatalf("the matcher asked the owners %d times and decided before they caught up", waiting.asked)
	}
	records := w.published.records
	if len(records) != 2 || records[0].GetFinding().GetState() != vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED || records[1].GetAssessment() == nil {
		t.Fatalf("the batch published %v, want the finding and then the assessment it was decided in", records)
	}
	if !w.source.committed {
		t.Fatal("the source did not advance past a published batch")
	}
}

func TestTheMatcherWaitsForTheFindingsWriterToHaveStoredWhatWasPublishedBefore(t *testing.T) {
	lagging := settledPositions()
	lagging.committed["finding-writer"] = map[int32]int64{0: 2}
	lagging.catchUp = 5
	w := world{
		source:    &source{records: []Record{inventoryRecord(t, debian, inventoryv1.Kind_KIND_PACKAGE, 5)}},
		positions: lagging,
		inventory: &inventory{assets: map[Asset]finding.Asset{debian: host(debian, "debian", "12", libssl("3.0.11-1~deb12u2"))}},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	if lagging.asked < lagging.catchUp || len(w.published.records) == 0 {
		t.Fatalf("the matcher asked %d times and published %d records, deciding before the writer stored what it decided last",
			lagging.asked, len(w.published.records))
	}
}

func TestAnAdvisoryThatStopsNamingAPackageClosesTheFindingsOfItsHolders(t *testing.T) {
	stopped := advisoryRecord(t, 9)
	var read vulnerabilityv1.Record
	if err := proto.Unmarshal(stopped.Value, &read); err != nil {
		t.Fatalf("decode the advisory record: %v", err)
	}
	read.GetAdvisory().Affected = []*vulnerabilityv1.Affected{{Ecosystem: "Debian:12", Name: "curl"}}
	stopped.Value, _ = proto.Marshal(&read)

	held := host(another, "debian", "12", libssl("3.0.11-1~deb12u2"))
	open := &vulnerabilityv1.Finding{
		SchemaVersion: finding.SchemaVersion, TenantId: another.TenantID, AgentId: another.AgentID,
		ItemId: held.Packages[0].ID, VulnerabilityId: "CVE-2024-6119", State: vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED,
		Package: held.Packages[0].Package, Advised: &vulnerabilityv1.AdvisedPackage{Ecosystem: "Debian:12", Name: "openssl"},
		ComparedVersion: "3.0.11-1~deb12u2", OpenedAt: timestamppb.New(scanned.Add(-72 * time.Hour)),
		Inventory:    &vulnerabilityv1.InventoryBasis{RecordId: "inv-0000000000", LastSeen: timestamppb.New(scanned), AsOf: timestamppb.New(scanned)},
		Intelligence: &vulnerabilityv1.IntelligenceBasis{Source: "osv", Feed: "Debian", AsOf: timestamppb.New(scanned)},
		DecidedAt:    timestamppb.New(scanned),
	}
	w := world{
		source:       &source{records: []Record{stopped}},
		positions:    settledPositions(),
		inventory:    &inventory{assets: map[Asset]finding.Asset{another: held}, holders: map[string][]Asset{"openssl": {another}}},
		intelligence: &intelligence{before: []Key{{Ecosystem: "Debian:12", Package: "openssl"}}},
		findings: &decisions{decided: map[Asset]map[finding.Name]*vulnerabilityv1.Finding{
			another: {{ItemID: open.ItemId, VulnerabilityID: open.VulnerabilityId}: open},
		}},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	if len(w.published.records) != 2 || w.published.records[0].GetFinding().GetState() != vulnerabilityv1.FindingState_FINDING_STATE_NOT_AFFECTED {
		t.Fatalf("a version that stopped naming openssl published %v, want the finding it held closed", w.published.records)
	}
}

func TestAnAdvisoryChangeJudgesItsHoldersInItsEcosystemAndAnAssetAssessedWholeOnlyOnce(t *testing.T) {
	w := world{
		source:    &source{records: []Record{inventoryRecord(t, debian, inventoryv1.Kind_KIND_PACKAGE, 5), advisoryRecord(t, 9)}},
		positions: settledPositions(),
		inventory: &inventory{
			assets: map[Asset]finding.Asset{
				debian:  host(debian, "debian", "12", libssl("3.0.11-1~deb12u2")),
				another: host(another, "debian", "12.5", libssl("3.0.11-1~deb12u2")),
				alpine:  host(alpine, "alpine", "3.19.1", &inventoryv1.Package{Name: "libcrypto3", Version: "3.1.4-r5", Manager: "apk", Source: "openssl"}),
			},
			holders: map[string][]Asset{"openssl": {debian, another, alpine, another}},
		},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	scopes := w.published.assessments()
	want := map[string]vulnerabilityv1.Assessment_Scope{
		debian.AgentID:  vulnerabilityv1.Assessment_SCOPE_ASSET,
		another.AgentID: vulnerabilityv1.Assessment_SCOPE_PACKAGES,
	}
	if !maps.Equal(scopes, want) {
		t.Fatalf("the batch assessed %v, want the asset its inventory named whole and the other debian holder by its packages", scopes)
	}
}

func TestAPartialAssessmentThatDecidesNothingPublishesNothing(t *testing.T) {
	w := world{
		source:    &source{records: []Record{advisoryRecord(t, 9)}},
		positions: settledPositions(),
		inventory: &inventory{
			assets:  map[Asset]finding.Asset{another: host(another, "debian", "12", libssl("3.0.14-1~deb12u2"))},
			holders: map[string][]Asset{"openssl": {another}},
		},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	if len(w.published.records) != 0 {
		t.Fatalf("an advisory that changes nothing for a holder published %v", w.published.records)
	}
}

func TestARecordTheMatcherCannotReadIsSkippedAndAKindNoAdvisoryDescribesIsIgnored(t *testing.T) {
	w := world{
		source: &source{records: []Record{
			{Topic: owners.Inventory.Topic, Partition: 0, Offset: 1, Value: []byte{0xff, 0xff}},
			inventoryRecord(t, debian, inventoryv1.Kind_KIND_SERVICE, 2),
			{Topic: owners.Advisories.Topic, Partition: 0, Offset: 3, Value: []byte{0xff, 0xff}},
		}},
		positions: settledPositions(),
		inventory: &inventory{assets: map[Asset]finding.Asset{debian: host(debian, "debian", "12", libssl("3.0.11-1~deb12u2"))}},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	if len(w.published.records) != 0 || !w.source.committed {
		t.Fatalf("a batch of nothing assessable published %d records and advanced: %t", len(w.published.records), w.source.committed)
	}
}

func TestAStoreThatFailsIsWaitedOutAndTheBatchDecidedAgain(t *testing.T) {
	w := world{
		source:    &source{records: []Record{inventoryRecord(t, debian, inventoryv1.Kind_KIND_OPERATING_SYSTEM, 5)}},
		positions: settledPositions(),
		inventory: &inventory{failures: 2, assets: map[Asset]finding.Asset{debian: host(debian, "debian", "12", libssl("3.0.11-1~deb12u2"))}},
		published: &publisher{},
	}
	if err := matcherOver(t, w).Run(context.Background()); err != nil {
		t.Fatalf("decide the batch: %v", err)
	}
	if len(w.published.records) != 2 || !w.source.committed {
		t.Fatalf("after two failures the batch published %d records and advanced: %t", len(w.published.records), w.source.committed)
	}
}

func TestADecisionTheWriterWouldRefuseIsNeverPublished(t *testing.T) {
	broken := host(debian, "debian", "12", libssl("3.0.11-1~deb12u2"))
	broken.Packages[0].ID = "libssl3"
	w := world{
		source:    &source{records: []Record{inventoryRecord(t, debian, inventoryv1.Kind_KIND_PACKAGE, 5)}},
		positions: settledPositions(),
		inventory: &inventory{assets: map[Asset]finding.Asset{debian: broken}},
		published: &publisher{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := matcherOver(t, w).Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a batch whose decision breaks the contract ended with %v", err)
	}
	if len(w.published.records) != 0 || w.source.committed {
		t.Fatalf("a decision the writer would refuse was published (%d records) or stepped over (%t)", len(w.published.records), w.source.committed)
	}
}

func TestTheMatcherRefusesAnIncompleteComposition(t *testing.T) {
	complete := Options{
		Source: &source{}, Positions: settledPositions(), Inventory: &inventory{}, Intelligence: &intelligence{},
		Findings: &decisions{}, Publisher: &publisher{}, Owners: owners, Policy: finding.Policy{Freshness: time.Hour},
		SettleDelay: time.Millisecond, RetryDelay: time.Millisecond, MaxRetryDelay: time.Second,
		Metrics: NewMetrics(metrics.New("test")), Logger: slog.New(slog.DiscardHandler), Now: time.Now,
	}
	if _, err := NewMatcher(complete); err != nil {
		t.Fatalf("a complete matcher was refused: %v", err)
	}
	for name, breaking := range map[string]func(*Options){
		"no source":          func(o *Options) { o.Source = nil },
		"no inventory":       func(o *Options) { o.Inventory = nil },
		"no findings":        func(o *Options) { o.Findings = nil },
		"no owner group":     func(o *Options) { o.Owners.Findings.Group = "" },
		"no freshness bound": func(o *Options) { o.Policy.Freshness = 0 },
		"upside down":        func(o *Options) { o.MaxRetryDelay = 0 },
		"no clock":           func(o *Options) { o.Now = nil },
	} {
		options := complete
		breaking(&options)
		if _, err := NewMatcher(options); err == nil {
			t.Errorf("%s: the matcher was built", name)
		}
	}
}

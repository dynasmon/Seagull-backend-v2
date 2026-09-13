//go:build integration

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisoryfeed"
	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/osv"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// A mirror laid out the way OSV's export is: per feed an index of every record
// and when it changed, and each record on its own.
type published struct {
	modified time.Time
	body     string
}

type mirror struct {
	server *httptest.Server

	mu      sync.Mutex
	records map[string]published
	failing bool
	asked   map[string]int
}

func mirrored(t *testing.T, records map[string]published) *mirror {
	t.Helper()
	served := &mirror{records: records, asked: map[string]int{}}
	served.server = httptest.NewTLSServer(http.HandlerFunc(served.serve))
	t.Cleanup(served.server.Close)
	return served
}

func (m *mirror) serve(writer http.ResponseWriter, request *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked[request.URL.Path]++
	if m.failing {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if request.URL.Path == "/Debian/modified_id.csv" {
		var index strings.Builder
		for _, id := range slices.Sorted(maps.Keys(m.records)) {
			fmt.Fprintf(&index, "%s,%s\n", m.records[id].modified.Format(time.RFC3339Nano), id)
		}
		_, _ = writer.Write([]byte(index.String()))
		return
	}
	id, found := strings.CutPrefix(request.URL.Path, "/Debian/")
	record, held := m.records[strings.TrimSuffix(id, ".json")]
	if !found || !held {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = writer.Write([]byte(record.body))
}

func (m *mirror) fail(failing bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failing = failing
}

func (m *mirror) recordsAsked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for path, count := range m.asked {
		if strings.HasSuffix(path, ".json") {
			total += count
		}
	}
	return total
}

func compactedAdvisoryTopic(t *testing.T, addresses []string) string {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(addresses...))
	if err != nil {
		t.Fatalf("connect to the backbone: %v", err)
	}
	t.Cleanup(client.Close)

	admin := kadm.NewClient(client)
	topic := fmt.Sprintf("security.advisories.test.%d", time.Now().UnixNano())
	compact, forever := "compact", "-1"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admin.CreateTopic(ctx, 1, 1, map[string]*string{"cleanup.policy": &compact, "retention.ms": &forever}, topic); err != nil {
		t.Fatalf("create topic: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.DeleteTopics(cleanup, topic)
	})
	return topic
}

type advisoryHistory struct{ log *broker.StateLog }

func (r advisoryHistory) Replay(ctx context.Context, learn func(*vulnerabilityv1.Record)) error {
	return r.log.Replay(ctx, func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var decoded vulnerabilityv1.Record
			if err := proto.Unmarshal(record.Value, &decoded); err != nil {
				return err
			}
			learn(&decoded)
		}
		return nil
	})
}

func importerOf(t *testing.T, addresses []string, topic string, served *mirror, now func() time.Time) *advisoryfeed.Importer {
	t.Helper()

	publisher, err := broker.NewAdvisories(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the advisory publisher: %v", err)
	}
	t.Cleanup(publisher.Close)

	log, err := broker.NewStateLog(broker.Config{Brokers: addresses, Topic: topic, ClientID: "integration-test"}, 64)
	if err != nil {
		t.Fatalf("build the advisory log reader: %v", err)
	}
	t.Cleanup(log.Close)

	export, err := osv.NewExport(osv.ExportOptions{
		Base: served.server.URL, Client: served.server.Client(), MaxIndexBytes: 1 << 20, MaxRecordBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("build the export: %v", err)
	}

	importer, err := advisoryfeed.NewImporter(advisoryfeed.Options{
		Source:        osv.Source,
		Feeds:         []string{"Debian"},
		Origin:        export,
		Translate:     osv.Translate,
		Normalization: osv.Normalization,
		Log:           publisher,
		History:       advisoryHistory{log: log},
		Metrics:       advisoryfeed.NewMetrics(metrics.New(t.Name())),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Interval:      time.Hour,
		RetryDelay:    time.Second,
		Backoff:       10 * time.Millisecond,
		Attempts:      2,
		Concurrency:   4,
		Batch:         16,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("build the importer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := importer.Recall(ctx); err != nil {
		t.Fatalf("recall what the backbone holds: %v", err)
	}
	return importer
}

func writing(t *testing.T, addresses []string, topic string, store *clickhouse.AdvisoryStore) func() {
	t.Helper()
	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      addresses,
		Topic:        topic,
		Group:        fmt.Sprintf("advisory-writer-%d", time.Now().UnixNano()),
		ClientID:     "integration-test",
		MaxRecords:   64,
		FetchMaxWait: 200 * time.Millisecond,
		Metrics:      broker.NewConsumerMetrics(metrics.New("integration")),
	})
	if err != nil {
		t.Fatalf("build the consumer: %v", err)
	}
	t.Cleanup(consumer.Close)

	refused, err := broker.NewQuarantine(broker.Config{Brokers: addresses, Topic: temporaryTopic(t, addresses), ClientID: "integration-test"})
	if err != nil {
		t.Fatalf("build the quarantine publisher: %v", err)
	}
	t.Cleanup(refused.Close)

	component, err := advisorystore.NewWriter(advisorystore.WriterOptions{
		Source:        advisorySource{consumer: consumer},
		Sink:          store,
		Quarantine:    advisoryQuarantine{topic: refused},
		Metrics:       advisorystore.NewMetrics(metrics.New("integration")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  30 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetryDelay: time.Second,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}

	ctx, stop := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- component.Run(ctx) }()
	return func() {
		stop()
		if err := <-stopped; err != nil && !isCancellation(err) {
			t.Errorf("the writer stopped with %v", err)
		}
	}
}

type advisorySource struct{ consumer *broker.Consumer }

func (a advisorySource) Consume(ctx context.Context, deliver advisorystore.Deliver) error {
	return a.consumer.Consume(ctx, func(ctx context.Context, records []broker.Record) error {
		converted := make([]advisorystore.Record, 0, len(records))
		for _, record := range records {
			converted = append(converted, advisorystore.Record{Partition: record.Partition, Offset: record.Offset, Key: record.Key, Value: record.Value})
		}
		return deliver(ctx, converted)
	})
}

type advisoryQuarantine struct{ topic *broker.Quarantine }

func (a advisoryQuarantine) Publish(ctx context.Context, refused []advisorystore.Refused) error {
	converted := make([]broker.Refused, 0, len(refused))
	for _, entry := range refused {
		converted = append(converted, broker.Refused{Key: entry.Key, Value: entry.Value, Reason: entry.Reason, Detail: entry.Detail, Partition: entry.Partition, Offset: entry.Offset})
	}
	return a.topic.Publish(ctx, converted)
}

func osvRecord(id, pkg string, modified time.Time, fixedIn string) string {
	return fmt.Sprintf(`{"schema_version": "1.9.0", "id": %q, "modified": %q, "upstream": ["CVE-2026-0001"],
		"affected": [{"package": {"ecosystem": "Debian:12", "name": %q},
		"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": %q}]}]}]}`,
		id, modified.Format(time.RFC3339Nano), pkg, fixedIn)
}

func waitForSync(t *testing.T, address string, checked time.Time) string {
	t.Helper()
	inspect := inspector(t, address)
	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var outcome string
		err := inspect.QueryRow(ctx,
			"SELECT outcome FROM vulnerability_feed_syncs FINAL WHERE source = 'osv' AND feed = 'Debian' AND toUnixTimestamp64Milli(checked_at) = ?",
			checked.UnixMilli()).Scan(&outcome)
		cancel()
		if err == nil {
			return outcome
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sync checked at %v reached the store: %v", checked, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// The whole intelligence plane with nothing stubbed between its ends: a mirror
// served over TLS, the importer, the backbone, the writer and the store. A feed
// that fails afterwards leaves the intelligence and the inventory as they were
// and says so, and a restarted importer asks the feed only for what changed.
func TestAnAdvisoryReadFromItsFeedReachesTheStoreSayingWhereAndWhenItWasRead(t *testing.T) {
	addresses := brokers(t)
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	suffix := owned(t)
	pkg := "openssl-" + suffix
	id := "DSA-" + suffix + "-1"
	modified := time.Now().UTC().Add(-time.Hour)
	body := osvRecord(id, pkg, modified, "3.0.13-1~deb12u1")

	owner := tenant(t)
	inventory := migratedInventoryStore(t, address)
	fold(t, inventory, owner, fixtures.PackageScan{AgentID: "web-01", Packages: []fixtures.Installed{{Name: pkg, Version: "3.0.11-1", Architecture: "amd64", Manager: "dpkg"}}})
	before := current(t, inspector(t, address), owner)

	served := mirrored(t, map[string]published{id: {modified: modified, body: body}})
	topic := compactedAdvisoryTopic(t, addresses)
	stopWriting := writing(t, addresses, topic, store)
	defer stopWriting()

	first := time.Now().UTC().Truncate(time.Millisecond)
	importer := importerOf(t, addresses, topic, served, func() time.Time { return first })
	if sync := importer.Sync(context.Background(), "Debian"); sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE {
		t.Fatalf("the first attempt says %v", sync)
	}
	if outcome := waitForSync(t, address, first); outcome != "complete" {
		t.Fatalf("the first attempt was stored as %s", outcome)
	}

	if got, want := affecting(t, address, pkg), []believed{{advisory: id, fixedIn: "3.0.13-1~deb12u1"}}; !slices.Equal(got, want) {
		t.Fatalf("%s is affected by %v, want %v", pkg, got, want)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var location, digest string
	if err := inspector(t, address).QueryRow(ctx,
		"SELECT location, digest FROM vulnerability_advisories FINAL WHERE advisory_id = ?", id).Scan(&location, &digest); err != nil {
		t.Fatalf("read the provenance back: %v", err)
	}
	sum := sha256.Sum256([]byte(body))
	if location != served.server.URL+"/Debian/"+id+".json" || digest != hex.EncodeToString(sum[:]) {
		t.Errorf("the advisory says it was read from %s as %s", location, digest)
	}

	served.fail(true)
	second := first.Add(time.Hour)
	failing := importerOf(t, addresses, topic, served, func() time.Time { return second })
	if sync := failing.Sync(context.Background(), "Debian"); sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_FAILED ||
		!sync.GetSyncedAt().AsTime().Equal(first) || sync.GetHeld() != 1 {
		t.Fatalf("an attempt against a failing feed says %v", sync)
	}
	if outcome := waitForSync(t, address, second); outcome != "failed" {
		t.Fatalf("the failed attempt was stored as %s", outcome)
	}
	if got := affecting(t, address, pkg); len(got) != 1 {
		t.Errorf("after a failed attempt %s is affected by %v: a feed that failed changed what the platform believes", pkg, got)
	}
	if after := current(t, inspector(t, address), owner); !maps.Equal(before, after) {
		t.Errorf("the inventory held %v before the feed failed and %v after", before, after)
	}

	served.fail(false)
	asked := served.recordsAsked()
	third := second.Add(time.Hour)
	restarted := importerOf(t, addresses, topic, served, func() time.Time { return third })
	if sync := restarted.Sync(context.Background(), "Debian"); sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE || sync.GetPublished() != 0 {
		t.Errorf("a restarted importer says %v", sync)
	}
	if served.recordsAsked() != asked {
		t.Errorf("a restarted importer asked for %d records it already held", served.recordsAsked()-asked)
	}
}

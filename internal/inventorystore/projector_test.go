package inventorystore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// Advances only when deliver returns nil, which is the whole of what this
// capability asks of a backbone.
type reader struct {
	records   []Record
	committed bool
}

func (r *reader) Consume(ctx context.Context, deliver Deliver) error {
	if err := deliver(ctx, r.records); err != nil {
		return err
	}
	r.committed = true
	return nil
}

type folded struct {
	order    []string
	failures int
	rows     [][]Row
	scans    [][]Scan
}

func (f *folded) Store(_ context.Context, rows []Row, scans []Scan) error {
	f.order = append(f.order, "store")
	if f.failures != 0 {
		if f.failures > 0 {
			f.failures--
		}
		return errors.New("the store is unavailable")
	}
	f.rows = append(f.rows, slices.Clone(rows))
	f.scans = append(f.scans, slices.Clone(scans))
	return nil
}

type refuser struct {
	order   []string
	refused [][]Refused
}

func (r *refuser) Publish(_ context.Context, refused []Refused) error {
	r.order = append(r.order, "quarantine")
	r.refused = append(r.refused, slices.Clone(refused))
	return nil
}

func projector(t *testing.T, source Source, sink Sink, quarantine Quarantine) *Projector {
	t.Helper()

	built, err := NewProjector(ProjectorOptions{
		Source:        source,
		Sink:          sink,
		Quarantine:    quarantine,
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the projector: %v", err)
	}
	return built
}

func fetched(t *testing.T, made proto.Message) Record {
	t.Helper()

	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a record: %v", err)
	}
	return Record{Partition: 1, Offset: 42, Value: payload}
}

func TestASnapshotIsFoldedIntoItemsAndAScan(t *testing.T) {
	source := &reader{records: []Record{fetched(t, record(inventoryv1.Kind_KIND_PACKAGE,
		packageItem("curl", "8.5.0"), packageItem("openssl", "3.0.13")))}}
	sink := &folded{}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if !source.committed {
		t.Fatal("the source advanced past a batch it was not told was durable")
	}
	if len(sink.rows[0]) != 2 || len(sink.scans[0]) != 1 {
		t.Fatalf("the batch folded into %d items and %d scans", len(sink.rows[0]), len(sink.scans[0]))
	}
}

func TestADeltaFoldsIntoItemsAndNoScan(t *testing.T) {
	delta := record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.6.0"))
	delta.Mode = inventoryv1.Mode_MODE_DELTA

	sink := &folded{}
	if err := projector(t, &reader{records: []Record{fetched(t, delta)}}, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if len(sink.rows[0]) != 1 || len(sink.scans[0]) != 0 {
		t.Fatalf("a delta folded into %d items and %d scans", len(sink.rows[0]), len(sink.scans[0]))
	}
}

func TestARecordThisBuildCannotReadIsQuarantinedAndTheRestIsFolded(t *testing.T) {
	nameless := record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"))
	nameless.RecordId = ""

	source := &reader{records: []Record{
		{Partition: 1, Offset: 1, Value: []byte{0xff, 0xff, 0xff}},
		fetched(t, nameless),
		fetched(t, record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"))),
	}}
	sink := &folded{}
	quarantine := &refuser{}

	if err := projector(t, source, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}

	if len(sink.rows[0]) != 1 {
		t.Fatalf("one good record folded into %d items", len(sink.rows[0]))
	}
	reasons := []string{}
	for _, entry := range quarantine.refused[0] {
		reasons = append(reasons, entry.Reason)
	}
	if !slices.Equal(reasons, []string{ReasonUndecodable, ReasonContractViolation}) {
		t.Fatalf("the refused records were put aside as %v", reasons)
	}
}

// A scan whose items never landed would retire everything the record was going
// to confirm, so the record is refused whole.
func TestAnItemTheStoreCannotHoldTakesItsScanWithIt(t *testing.T) {
	unstorable := record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0"))
	unstorable.Items[0].GetPackage().InstalledAt = timestamppb.New(time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC))

	sink := &folded{}
	quarantine := &refuser{}
	if err := projector(t, &reader{records: []Record{fetched(t, unstorable)}}, sink, quarantine).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}

	if len(sink.rows) != 0 {
		t.Fatalf("an unstorable record reached the store as %d batches", len(sink.rows))
	}
	if quarantine.refused[0][0].Reason != ReasonUnstorable {
		t.Fatalf("the record was put aside as %q", quarantine.refused[0][0].Reason)
	}
}

func TestABatchIsRetriedUntilItIsDurableAndTheSourceWaits(t *testing.T) {
	source := &reader{records: []Record{fetched(t, record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0")))}}
	sink := &folded{failures: 2}

	if err := projector(t, source, sink, &refuser{}).Run(context.Background()); err != nil {
		t.Fatalf("fold the batch: %v", err)
	}
	if len(sink.order) != 3 {
		t.Fatalf("the batch was written %d times, want three attempts", len(sink.order))
	}
	if !source.committed {
		t.Fatal("the source advanced before the batch was durable")
	}
}

func TestAStoppedProjectorDoesNotAdvancePastABatchItCouldNotStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &reader{records: []Record{fetched(t, record(inventoryv1.Kind_KIND_PACKAGE, packageItem("curl", "8.5.0")))}}
	sink := &folded{failures: -1}

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	if err := projector(t, source, sink, &refuser{}).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a stopped projector returned %v", err)
	}
	if source.committed {
		t.Fatal("the source advanced past a batch that never became durable")
	}
}

func TestTheProjectorRefusesAnIncompleteComposition(t *testing.T) {
	complete := ProjectorOptions{
		Source:        &reader{},
		Sink:          &folded{},
		Quarantine:    &refuser{},
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Second,
		MaxRetryDelay: time.Minute,
	}
	for name, breaking := range map[string]func(*ProjectorOptions){
		"no source":     func(o *ProjectorOptions) { o.Source = nil },
		"no sink":       func(o *ProjectorOptions) { o.Sink = nil },
		"no quarantine": func(o *ProjectorOptions) { o.Quarantine = nil },
		"no metrics":    func(o *ProjectorOptions) { o.Metrics = nil },
		"no logger":     func(o *ProjectorOptions) { o.Logger = nil },
		"no budget":     func(o *ProjectorOptions) { o.WriteTimeout = 0 },
		"upside down":   func(o *ProjectorOptions) { o.MaxRetryDelay = time.Millisecond },
	} {
		t.Run(name, func(t *testing.T) {
			options := complete
			breaking(&options)
			if _, err := NewProjector(options); err == nil {
				t.Fatal("the projector was built")
			}
		})
	}
}

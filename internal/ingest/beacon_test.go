package ingest_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

type rosterIs bool

func (r rosterIs) Stale() bool { return bool(r) }

func counted(t *testing.T, registry *metrics.Registry, series string) float64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if value, found := strings.CutPrefix(line, series+" "); found {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return parsed
		}
	}
	t.Fatalf("%s is not exported", series)
	return 0
}

type announced struct {
	mu      sync.Mutex
	beacons []*platformv1.GatewayBeacon
	first   chan struct{}
	refuse  error
}

func (a *announced) Announce(ctx context.Context, beacon *platformv1.GatewayBeacon) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.beacons = append(a.beacons, beacon)
	if len(a.beacons) == 1 {
		close(a.first)
	}
	return a.refuse
}

func beaconed(t *testing.T, roster ingest.Current, sent *announced) (*ingest.Beacon, *metrics.Registry) {
	t.Helper()
	exported := metrics.New("ingest-beacon")
	beacon, err := ingest.NewBeacon(ingest.BeaconOptions{
		Gateway: "gateway-1", Every: time.Second, Current: roster, Beacons: sent,
		Registry: exported, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return beacon, exported
}

func runUntilFirst(t *testing.T, beacon *ingest.Beacon, sent *announced) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- beacon.Run(ctx) }()
	select {
	case <-sent.first:
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway never said it serves")
	}
	stop()
	if err := <-done; err != nil {
		t.Fatalf("the beacon stopped with %v", err)
	}
}

func TestAGatewaySaysItAdmitsWhileItsRosterIsCurrentAndThatItStoppedAsItStops(t *testing.T) {
	sent := &announced{first: make(chan struct{})}
	beacon, exported := beaconed(t, rosterIs(false), sent)
	runUntilFirst(t, beacon, sent)

	if len(sent.beacons) < 2 {
		t.Fatalf("the gateway sent %d beacons through a start and a stop", len(sent.beacons))
	}
	first, last := sent.beacons[0], sent.beacons[len(sent.beacons)-1]
	if err := listening.Validate(first); err != nil || !first.GetAdmitting() || first.GetGateway() != "gateway-1" || first.GetEvery().AsDuration() != time.Second {
		t.Errorf("the first beacon was %v (%v)", first, err)
	}
	if last.GetAdmitting() {
		t.Error("the last beacon of a stopping gateway said it still admits")
	}
	if got := counted(t, exported, `seagull_ingest_beacons_total{outcome="not_admitting"}`); got != 1 {
		t.Errorf("%v beacons are counted as not admitting", got)
	}
}

func TestAGatewayWhoseRosterIsStaleSaysItDoesNotAdmit(t *testing.T) {
	sent := &announced{first: make(chan struct{})}
	beacon, _ := beaconed(t, rosterIs(true), sent)
	runUntilFirst(t, beacon, sent)
	for _, one := range sent.beacons {
		if one.GetAdmitting() {
			t.Fatal("a gateway with a stale roster said it admits")
		}
	}
}

func TestABeaconTheBackboneDoesNotTakeIsCountedAndTheGatewayGoesOn(t *testing.T) {
	sent := &announced{first: make(chan struct{}), refuse: errors.New("the backbone is unreachable")}
	beacon, exported := beaconed(t, rosterIs(false), sent)
	runUntilFirst(t, beacon, sent)
	if got := counted(t, exported, `seagull_ingest_beacons_total{outcome="unsent"}`); got < 1 {
		t.Errorf("%v unsent beacons are counted", got)
	}
}

func TestABeaconNeedsItsGatewayAnIntervalTheContractAllowsAndARoster(t *testing.T) {
	for name, options := range map[string]ingest.BeaconOptions{
		"no gateway":   {Every: time.Second, Current: rosterIs(false), Beacons: &announced{}},
		"too rarely":   {Gateway: "gateway-1", Every: 2 * time.Minute, Current: rosterIs(false), Beacons: &announced{}},
		"no roster":    {Gateway: "gateway-1", Every: time.Second, Beacons: &announced{}},
		"nowhere sent": {Gateway: "gateway-1", Every: time.Second, Current: rosterIs(false)},
	} {
		options.Registry, options.Logger = metrics.New("ingest-beacon-"+name), slog.New(slog.DiscardHandler)
		if _, err := ingest.NewBeacon(options); err == nil {
			t.Errorf("a beacon with %s was built", name)
		}
	}
}

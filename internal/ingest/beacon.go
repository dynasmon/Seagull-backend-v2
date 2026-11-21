package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

// Where a gateway says that it serves agents, for a reader of what they report
// to tell an agent that went quiet from a platform that stopped listening.
type Beacons interface {
	Announce(ctx context.Context, beacon *platformv1.GatewayBeacon) error
}

type BeaconOptions struct {
	Gateway  string
	Every    time.Duration
	Current  Current
	Beacons  Beacons
	Registry *metrics.Registry
	Logger   *slog.Logger
	Now      func() time.Time
}

type Beacon struct {
	gateway string
	every   time.Duration
	current Current
	beacons Beacons
	logger  *slog.Logger
	now     func() time.Time
	sent    *prometheus.CounterVec
}

func NewBeacon(options BeaconOptions) (*Beacon, error) {
	switch {
	case options.Gateway == "" || len(options.Gateway) > listening.MaxGatewayLength:
		return nil, fmt.Errorf("a gateway beacon names its gateway in 1 to %d bytes", listening.MaxGatewayLength)
	case options.Every < listening.MinEvery || options.Every > listening.MaxEvery:
		return nil, fmt.Errorf("a gateway says it serves every %s to %s", listening.MinEvery, listening.MaxEvery)
	case options.Current == nil:
		return nil, errors.New("a gateway says it admits only while its roster is current, and was given no way to tell")
	case options.Beacons == nil:
		return nil, errors.New("a gateway beacon needs somewhere to be sent")
	case options.Registry == nil || options.Logger == nil:
		return nil, errors.New("a gateway beacon reports what it sent, and was given nowhere to")
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	sent := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "ingest",
		Name:      "beacons_total",
		Help:      "Beacons the gateway sent, by whether they said it admits, and the ones the backbone did not take.",
	}, []string{"outcome"})
	for _, outcome := range []string{"admitting", "not_admitting", "unsent"} {
		sent.WithLabelValues(outcome)
	}
	options.Registry.MustRegister(sent)

	return &Beacon{
		gateway: options.Gateway,
		every:   options.Every,
		current: options.Current,
		beacons: options.Beacons,
		logger:  options.Logger,
		now:     options.Now,
		sent:    sent,
	}, nil
}

func (b *Beacon) Name() string { return "gateway-beacon" }

// A gateway says it admits only while its roster is current, which is when it
// does, and the last beacon it sends as it stops says it no longer admits, so a
// reader need not wait for it to fall silent to know.
func (b *Beacon) Run(ctx context.Context) error {
	ticker := time.NewTicker(b.every)
	defer ticker.Stop()

	for {
		b.announce(ctx, !b.current.Stale())
		select {
		case <-ctx.Done():
			b.announce(context.WithoutCancel(ctx), false)
			return nil
		case <-ticker.C:
		}
	}
}

func (b *Beacon) announce(ctx context.Context, admitting bool) {
	within, cancel := context.WithTimeout(ctx, b.every)
	defer cancel()
	if err := b.beacons.Announce(within, listening.Beacon(b.gateway, b.now(), b.every, admitting)); err != nil {
		b.sent.WithLabelValues("unsent").Inc()
		b.logger.Warn("gateway_beacon_unsent", slog.Bool("admitting", admitting), slog.String("error", err.Error()))
		return
	}
	if admitting {
		b.sent.WithLabelValues("admitting").Inc()
		return
	}
	b.sent.WithLabelValues("not_admitting").Inc()
}

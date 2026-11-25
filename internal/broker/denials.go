package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

var (
	ErrNotAuthenticated = errors.New("the backbone refused the credentials of this process")
	ErrNotAuthorized    = errors.New("the backbone refused this process an operation its grant does not hold")
)

const (
	refusedWho  = "authentication"
	refusedWhat = "authorization"
)

func refusal(err error) (string, bool) {
	switch {
	case err == nil:
		return "", false
	case errors.Is(err, kerr.SaslAuthenticationFailed), errors.Is(err, kerr.UnsupportedSaslMechanism), errors.Is(err, kerr.IllegalSaslState):
		return refusedWho, true
	case errors.Is(err, kerr.TopicAuthorizationFailed), errors.Is(err, kerr.GroupAuthorizationFailed),
		errors.Is(err, kerr.ClusterAuthorizationFailed), errors.Is(err, kerr.TransactionalIDAuthorizationFailed):
		return refusedWhat, true
	}
	return "", false
}

func named(err error) error {
	reason, refused := refusal(err)
	switch {
	case !refused:
		return err
	case reason == refusedWho:
		return fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
	default:
		return fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
}

// What the backbone refused a process, from every client the process builds:
// a connection whose credentials it refused, a group it may not join, a record
// it may not write and a read it may not make. Readiness fails while refusals
// keep arriving, naming the newest, and holds again once a look finds no new one.
type Denials struct {
	counted *prometheus.CounterVec

	mu      sync.Mutex
	seen    uint64
	checked uint64
	newest  error
}

func NewDenials(registry *metrics.Registry) *Denials {
	denials := &Denials{counted: prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "backbone",
		Name:      "denials_total",
		Help:      "Connections, requests and records the backbone refused this process, by whether it refused who the process is or what it asked for.",
	}, []string{"reason"})}
	for _, reason := range []string{refusedWho, refusedWhat} {
		denials.counted.WithLabelValues(reason)
	}
	registry.MustRegister(denials.counted)
	return denials
}

func (d *Denials) observe(err error) {
	if d == nil {
		return
	}
	reason, refused := refusal(err)
	if !refused {
		return
	}
	d.counted.WithLabelValues(reason).Inc()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen++
	d.newest = named(err)
}

func (d *Denials) OnBrokerConnect(_ kgo.BrokerMetadata, _ time.Duration, _ net.Conn, err error) {
	d.observe(err)
}

func (d *Denials) OnGroupManageError(err error) { d.observe(err) }

func (d *Denials) OnProduceRecordUnbuffered(_ *kgo.Record, err error) { d.observe(err) }

func (d *Denials) Check(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == d.checked {
		return nil
	}
	d.checked = d.seen
	return d.newest
}

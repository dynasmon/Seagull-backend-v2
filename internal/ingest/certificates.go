package ingest

import (
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

const (
	CodeCertificateReplaced = "agent_certificate_replaced"
	CodeRosterBehind        = "roster_behind"
)

// How a gateway judges the certificate an agent presents against the one the
// registry binds it to, as its roster was told. Everything is decided from the
// roster in memory: a certificate is never looked up anywhere per request.
type Certificates struct {
	tolerance time.Duration
	refusals  *Refusals
	standings *prometheus.CounterVec
	now       func() time.Time
}

type CertificatesOptions struct {
	Tolerance time.Duration
	Refusals  *Refusals
	Registry  *metrics.Registry
	Now       func() time.Time
}

func NewCertificates(options CertificatesOptions) (*Certificates, error) {
	switch {
	case options.Tolerance <= 0:
		return nil, errors.New("a gateway tolerates the certificate a renewal replaced for a positive while")
	case options.Refusals == nil:
		return nil, errors.New("a gateway says what it refused, and was given nowhere to")
	case options.Registry == nil:
		return nil, errors.New("a gateway counts the certificates it did not admit as in force, and was given nowhere to")
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	standings := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "ingest",
		Name:      "certificates_total",
		Help:      "Requests presented with a certificate other than the one in force: admitted inside the tolerance, newer than the roster, or replaced.",
	}, []string{"standing"})
	for _, standing := range []agentidentity.Standing{agentidentity.Tolerated, agentidentity.Unheard, agentidentity.Replaced} {
		standings.WithLabelValues(standing.String())
	}
	options.Registry.MustRegister(standings)

	return &Certificates{tolerance: options.Tolerance, refusals: options.Refusals, standings: standings, now: options.Now}, nil
}

func (c *Certificates) standing(roster Roster, identity agentidentity.Identity) (agentidentity.Standing, agentidentity.Held) {
	held, known := roster.Binding(identity.AgentID)
	if !known {
		return agentidentity.Unbound, held
	}
	return held.Judge(identity.Certificate, c.now(), c.tolerance), held
}

// A connection that presented a certificate other than the one in force is
// closed once it is answered, so an agent that renewed meanwhile opens its next
// one with the certificate it renewed into: a busy connection finishes its
// request and is never used again. A certificate newer than the roster is one
// the agent renewed into while this gateway was behind, and is answered as a
// stale roster is, so the agent keeps what it sent and sends it again.
func (c *Certificates) admits(w http.ResponseWriter, roster Roster, identity agentidentity.Identity, tenant, route string) (string, bool) {
	standing, held := c.standing(roster, identity)
	switch standing {
	case agentidentity.Unbound, agentidentity.InForce:
		return "", true
	case agentidentity.Tolerated:
		c.standings.WithLabelValues(standing.String()).Inc()
		w.Header().Set("Connection", "close")
		return "", true
	case agentidentity.Unheard:
		c.standings.WithLabelValues(standing.String()).Inc()
		w.Header().Set("Connection", "close")
		w.Header().Set("Retry-After", "5")
		refuse(w, http.StatusServiceUnavailable, CodeRosterBehind,
			"this gateway has not yet heard of the certificate this agent presents, which is newer than the one it holds", "", -1)
		return CodeRosterBehind, false
	}
	c.standings.WithLabelValues(agentidentity.Replaced.String()).Inc()
	c.refusals.refused(identity.AgentID, tenant, held, route, c.now())
	w.Header().Set("Connection", "close")
	refuse(w, http.StatusForbidden, CodeCertificateReplaced,
		"the certificate this connection presents was replaced, and the platform admits this agent only on the certificate in force", "", -1)
	return CodeCertificateReplaced, false
}

// Judged again as the answer is written, since the roster may have learned of
// a renewal while the request was in flight: the request completes, and its
// connection is not used again.
func (c *Certificates) answering(w http.ResponseWriter, roster Roster, identity agentidentity.Identity) {
	if standing, _ := c.standing(roster, identity); standing != agentidentity.InForce && standing != agentidentity.Unbound {
		w.Header().Set("Connection", "close")
	}
}

package agentidentity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
)

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var (
	ErrNoClientCertificate = errors.New("the connection carries no verified client certificate")
	ErrMalformedIdentity   = errors.New("the client certificate does not carry a usable agent identity")
)

type Identity struct {
	AgentID string
}

// The agent identity is taken from the verified certificate and never from a
// request header or body: a header is chosen by the caller, a certificate is
// chosen by the certificate authority.
func FromConnection(state *tls.ConnectionState) (Identity, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Identity{}, ErrNoClientCertificate
	}
	return FromCertificate(state.VerifiedChains[0][0])
}

func FromCertificate(certificate *x509.Certificate) (Identity, error) {
	if certificate == nil {
		return Identity{}, ErrNoClientCertificate
	}
	name := certificate.Subject.CommonName
	if !agentIDPattern.MatchString(name) {
		return Identity{}, fmt.Errorf("%w: common name %q", ErrMalformedIdentity, name)
	}
	return Identity{AgentID: name}, nil
}

func Valid(agentID string) bool { return agentIDPattern.MatchString(agentID) }

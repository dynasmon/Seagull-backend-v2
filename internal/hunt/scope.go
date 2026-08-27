package hunt

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
)

var (
	ErrNoClientCertificate = errors.New("the connection carries no verified client certificate")
	ErrNoScope             = errors.New("the client certificate names no tenant this caller may read")
)

// The tenants a caller may read. It is not a filter the caller supplies and not
// a predicate a query may relax: a query cannot be compiled without one, and the
// tenant a record belongs to is the first thing the store is asked about. An
// empty scope reads nothing rather than everything, so a caller who lost their
// authorisation loses their answers with it.
type Scope struct {
	tenants []string
}

func NewScope(tenants []string) (Scope, error) {
	kept := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		if !event.ValidIdentifier(tenant) {
			return Scope{}, fmt.Errorf("%q is not a tenant identifier", tenant)
		}
		if !slices.Contains(kept, tenant) {
			kept = append(kept, tenant)
		}
	}
	if len(kept) == 0 {
		return Scope{}, ErrNoScope
	}
	slices.Sort(kept)
	return Scope{tenants: kept}, nil
}

func (s Scope) Tenants() []string { return slices.Clone(s.tenants) }

func (s Scope) Empty() bool { return len(s.tenants) == 0 }

// The caller is named by the certificate's common name and the tenants it may
// read are named by its organisation, so authorisation arrives from the
// certificate authority rather than from the request: a header is chosen by
// whoever sends it. When there is an identity service to ask, the scope comes
// from there instead and nothing below this line changes.
func ScopeFromConnection(state *tls.ConnectionState) (Scope, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Scope{}, ErrNoClientCertificate
	}
	return ScopeFromCertificate(state.VerifiedChains[0][0])
}

func ScopeFromCertificate(certificate *x509.Certificate) (Scope, error) {
	if certificate == nil {
		return Scope{}, ErrNoClientCertificate
	}
	scope, err := NewScope(certificate.Subject.Organization)
	if err != nil {
		return Scope{}, fmt.Errorf("%w: %s", ErrNoScope, err)
	}
	return scope, nil
}

// Who asked, for the log and for nothing else: a caller is not a tenant and
// never narrows what the scope already decided.
func CallerFromConnection(state *tls.ConnectionState) string {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ""
	}
	return state.VerifiedChains[0][0].Subject.CommonName
}

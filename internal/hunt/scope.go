package hunt

import (
	"crypto/tls"
	"errors"
	"fmt"
	"slices"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
)

var (
	ErrNoClientCertificate = errors.New("the connection carries no verified client certificate")
	ErrNotGranted          = errors.New("the policy grants this caller nothing")
	ErrNotPermitted        = errors.New("the policy does not let this caller read this dataset")
	ErrNoScope             = errors.New("the policy names no tenant this caller may read")
)

// Who may ask the query plane what: the policy the control plane decides by,
// which a pinned *authz.Policy answers.
type Grants interface {
	Grant(subject string) (authz.Grant, error)
}

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

// The caller is the common name of its verified certificate, and everything
// else is the policy's: whether it may read the dataset, and in which tenants.
// What a certificate's organisation names authorises nothing, so removing a
// subject from the policy removes its answers whatever certificate it holds.
func Authorize(state *tls.ConnectionState, grants Grants, dataset Dataset) (Scope, error) {
	caller := CallerFromConnection(state)
	if caller == "" {
		return Scope{}, ErrNoClientCertificate
	}
	grant, err := grants.Grant(caller)
	if err != nil {
		return Scope{}, fmt.Errorf("%w: %q", ErrNotGranted, caller)
	}
	permission := authz.Permission{Resource: authz.Events, Action: authz.Read}
	if dataset == Detections {
		permission.Resource = authz.Detections
	}
	if !grant.Allows(permission) {
		return Scope{}, fmt.Errorf("%w: it needs %s", ErrNotPermitted, permission)
	}
	return NewScope(grant.Tenants())
}

func CallerFromConnection(state *tls.ConnectionState) string {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ""
	}
	return state.VerifiedChains[0][0].Subject.CommonName
}

package agentidentity_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
)

const (
	inForce  = "1111111111111111111111111111111111111111111111111111111111111111"
	replaced = "2222222222222222222222222222222222222222222222222222222222222222"
	another  = "3333333333333333333333333333333333333333333333333333333333333333"
)

var (
	issuedAt   = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	replacedAt = time.Date(2026, 11, 23, 10, 1, 0, 0, time.UTC)
	tolerance  = time.Minute
)

func bound() agentidentity.Binding {
	return agentidentity.Binding{Fingerprint: inForce, IssuedAt: issuedAt, Replaced: replaced, ReplacedAt: replacedAt}
}

func presented(fingerprint string, notBefore time.Time) agentidentity.Certificate {
	return agentidentity.Certificate{Fingerprint: fingerprint, NotBefore: notBefore}
}

func TestACertificateStandsByWhatTheRegistryBindsTheAgentTo(t *testing.T) {
	for name, test := range map[string]struct {
		binding   agentidentity.Binding
		presented agentidentity.Certificate
		learned   time.Time
		now       time.Time
		want      agentidentity.Standing
	}{
		"the certificate in force": {
			binding: bound(), presented: presented(inForce, issuedAt), now: replacedAt.Add(time.Hour),
			want: agentidentity.InForce,
		},
		"any certificate, when the record binds none": {
			binding: agentidentity.Binding{}, presented: presented(another, issuedAt), now: replacedAt,
			want: agentidentity.Unbound,
		},
		"the replaced certificate, inside the tolerance of a record read back": {
			binding: bound(), presented: presented(replaced, issuedAt.Add(-time.Hour)), now: replacedAt.Add(tolerance - time.Nanosecond),
			want: agentidentity.Tolerated,
		},
		"the replaced certificate, once the tolerance of a record read back has passed": {
			binding: bound(), presented: presented(replaced, issuedAt.Add(-time.Hour)), now: replacedAt.Add(tolerance),
			want: agentidentity.Replaced,
		},
		"the replaced certificate, inside the tolerance counted from when the listener learned it": {
			binding: bound(), presented: presented(replaced, issuedAt.Add(-time.Hour)),
			learned: replacedAt.Add(time.Hour), now: replacedAt.Add(time.Hour + tolerance - time.Nanosecond),
			want: agentidentity.Tolerated,
		},
		"the replaced certificate, once the tolerance counted from when the listener learned it has passed": {
			binding: bound(), presented: presented(replaced, issuedAt.Add(-time.Hour)),
			learned: replacedAt.Add(time.Hour), now: replacedAt.Add(time.Hour + tolerance),
			want: agentidentity.Replaced,
		},
		"the replaced certificate, learned by a clock behind the registry's": {
			binding: bound(), presented: presented(replaced, issuedAt.Add(-time.Hour)),
			learned: replacedAt.Add(-time.Hour), now: replacedAt.Add(tolerance),
			want: agentidentity.Replaced,
		},
		"a certificate issued after the one in force": {
			binding: bound(), presented: presented(another, issuedAt.Add(time.Second)), now: replacedAt,
			want: agentidentity.Unheard,
		},
		"a certificate issued the same second as the one in force": {
			binding: bound(), presented: presented(another, issuedAt), now: replacedAt,
			want: agentidentity.Unheard,
		},
		"a certificate issued before the one in force and not the one it replaced": {
			binding: bound(), presented: presented(another, issuedAt.Add(-time.Second)), now: replacedAt,
			want: agentidentity.Replaced,
		},
		"a certificate the record cannot order, when it says not when the one in force was issued": {
			binding:   agentidentity.Binding{Fingerprint: inForce, Replaced: replaced, ReplacedAt: replacedAt},
			presented: presented(another, issuedAt.Add(-time.Hour)), now: replacedAt,
			want: agentidentity.Unheard,
		},
		"another certificate, when the one in force replaced none": {
			binding:   agentidentity.Binding{Fingerprint: inForce, IssuedAt: issuedAt},
			presented: presented(another, issuedAt.Add(-time.Hour)), now: issuedAt,
			want: agentidentity.Replaced,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := test.binding.Judge(test.presented, test.learned, test.now, tolerance); got != test.want {
				t.Fatalf("the certificate stands %s, and it should stand %s", got, test.want)
			}
		})
	}
}

func TestOnlyACertificateInForceOrToleratedIsAdmitted(t *testing.T) {
	for standing, admits := range map[agentidentity.Standing]bool{
		agentidentity.Unbound:   true,
		agentidentity.InForce:   true,
		agentidentity.Tolerated: true,
		agentidentity.Unheard:   false,
		agentidentity.Replaced:  false,
	} {
		if standing.Admits() != admits {
			t.Errorf("a certificate that stands %s is admitted %t", standing, standing.Admits())
		}
	}
}

func TestTheCertificateAConnectionPresentedIsKeptByItsFingerprint(t *testing.T) {
	notBefore := time.Date(2026, 11, 23, 9, 59, 0, 0, time.UTC)
	leaf := &x509.Certificate{Raw: []byte("abc"), Subject: pkix.Name{CommonName: "web-01"}, NotBefore: notBefore}

	identity, err := agentidentity.FromCertificate(leaf)
	if err != nil {
		t.Fatalf("read the identity: %v", err)
	}
	want := agentidentity.Certificate{
		Fingerprint: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		NotBefore:   notBefore,
	}
	if identity.Certificate != want {
		t.Fatalf("the connection presented %+v, kept as %+v", want, identity.Certificate)
	}
}

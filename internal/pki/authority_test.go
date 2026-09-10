package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
)

const subject = "agent-01"

func authority(t *testing.T, validity time.Duration) *pki.Authority {
	t.Helper()
	development, err := devpki.NewAuthority("Seagull Test Agent CA", validity)
	if err != nil {
		t.Fatalf("build a development authority: %v", err)
	}
	material := development.Material()
	signing, err := pki.NewAuthority(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("read the authority: %v", err)
	}
	return signing
}

func request(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("create a certificate request: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignedCertificateBindsToTheAgentItNames(t *testing.T) {
	now := time.Now().UTC()
	issued, err := authority(t, 30*24*time.Hour).Sign(subject, request(t, subject), 24*time.Hour, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := agent.Bindable(subject, issued.Identity, now); err != nil {
		t.Fatalf("the registry refused what the authority signed: %v", err)
	}

	block, _ := pem.Decode(issued.CertificatePEM)
	if block == nil {
		t.Fatal("the signed certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the signed certificate: %v", err)
	}
	digest := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(digest[:]); got != issued.Identity.GetFingerprintSha256() {
		t.Fatalf("the recorded fingerprint is %q and the certificate is %q",
			issued.Identity.GetFingerprintSha256(), got)
	}
	recorded, hexadecimal := new(big.Int).SetString(issued.Identity.GetSerial(), 16)
	if !hexadecimal || recorded.Cmp(certificate.SerialNumber) != 0 {
		t.Fatalf("the recorded serial %q does not name the certificate's %s",
			issued.Identity.GetSerial(), certificate.SerialNumber)
	}
	if len(issued.Identity.GetSerial())%2 != 0 {
		t.Fatalf("the recorded serial %q is not written in whole bytes", issued.Identity.GetSerial())
	}
	if !certificate.NotAfter.Equal(issued.Identity.GetExpiresAt().AsTime()) ||
		!certificate.NotBefore.Equal(issued.Identity.GetIssuedAt().AsTime()) {
		t.Fatal("the recorded validity is not the certificate's")
	}
	if certificate.Subject.CommonName != subject {
		t.Fatalf("the certificate names %q", certificate.Subject.CommonName)
	}
	if certificate.IsCA || certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatal("the certificate may do more than authenticate an agent")
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("the certificate is for %v and not only for a client", certificate.ExtKeyUsage)
	}
}

func TestSignedCertificateVerifiesAgainstTheAuthority(t *testing.T) {
	signing := authority(t, 30*24*time.Hour)
	issued, err := signing.Sign(subject, request(t, subject), 24*time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(signing.Chain()) {
		t.Fatal("the authority chain holds no certificate")
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the signed certificate: %v", err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("a listener would refuse what the authority signed: %v", err)
	}
}

func TestSignRefusesARequestNamingAnotherAgent(t *testing.T) {
	_, err := authority(t, 30*24*time.Hour).Sign(subject, request(t, "agent-02"), 24*time.Hour, time.Now())
	if !errors.Is(err, pki.ErrMalformedRequest) {
		t.Fatalf("a request naming another agent was answered with %v", err)
	}
}

func TestSignRefusesAValidityOutsideWhatIsIssued(t *testing.T) {
	signing := authority(t, 30*24*time.Hour)
	for name, validity := range map[string]time.Duration{
		"below the floor":   pki.MinValidity - time.Second,
		"above the ceiling": pki.MaxValidity + time.Second,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := signing.Sign(subject, request(t, subject), validity, time.Now())
			if !errors.Is(err, pki.ErrUnusableValidity) {
				t.Fatalf("%s was answered with %v", name, err)
			}
		})
	}
}

// A certificate outliving the authority that signed it is trusted by nobody the
// day the authority expires, so it is cut short rather than issued as asked.
func TestSignedCertificateNeverOutlivesTheAuthority(t *testing.T) {
	signing := authority(t, 2*time.Hour)
	issued, err := signing.Sign(subject, request(t, subject), 24*time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if expires := issued.Identity.GetExpiresAt().AsTime(); expires.After(signing.NotAfter()) {
		t.Fatalf("the certificate expires at %s and the authority at %s", expires, signing.NotAfter())
	}
}

func TestSignRefusesWhenTheAuthorityIsNotValidYet(t *testing.T) {
	signing := authority(t, time.Hour)
	_, err := signing.Sign(subject, request(t, subject), time.Hour, time.Now().Add(2*time.Hour))
	if !errors.Is(err, pki.ErrAuthorityExpired) {
		t.Fatalf("an expired authority signed anyway, or refused with %v", err)
	}
}

func TestNewAuthorityRefusesMaterialThatCannotSign(t *testing.T) {
	development, err := devpki.NewAuthority("Seagull Test Agent CA", time.Hour)
	if err != nil {
		t.Fatalf("build a development authority: %v", err)
	}
	leaf, err := development.IssueClient(subject, time.Hour)
	if err != nil {
		t.Fatalf("issue a leaf: %v", err)
	}
	other, err := devpki.NewAuthority("Seagull Other Agent CA", time.Hour)
	if err != nil {
		t.Fatalf("build a second development authority: %v", err)
	}

	for name, material := range map[string]devpki.Material{
		"a leaf certificate": leaf,
		"another authority's key": {
			CertificatePEM: development.Material().CertificatePEM,
			PrivateKeyPEM:  other.Material().PrivateKeyPEM,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pki.NewAuthority(material.CertificatePEM, material.PrivateKeyPEM); !errors.Is(err, pki.ErrMalformedAuthority) {
				t.Fatalf("%s was accepted, or refused with %v", name, err)
			}
		})
	}
}

func TestSignedIdentityIsWhatTheRegistryRecords(t *testing.T) {
	now := time.Now().UTC()
	issued, err := authority(t, 30*24*time.Hour).Sign(subject, request(t, subject), time.Hour, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	registered := &agentv1.Agent{
		AgentId:  subject,
		State:    agentv1.State_STATE_PENDING,
		Revision: 1,
	}
	moved, _, err := agent.Apply(registered, agent.Move{Identity: issued.Identity, Actor: "operator", At: now})
	if err != nil {
		t.Fatalf("bind what was signed: %v", err)
	}
	if moved.GetState() != agentv1.State_STATE_ACTIVE {
		t.Fatalf("binding an issued certificate left the agent %s", moved.GetState())
	}
}

// The serial of a certificate whose first byte is below 0x10. Rendering it
// without the leading zero would name a different number of bytes than the
// certificate carries, and the registry would hold a serial that matches none.
func TestASerialIsWrittenInWholeBytes(t *testing.T) {
	for name, serial := range map[string]int64{
		"a leading zero nibble": 0x0a1b2c,
		"a whole first byte":    0xa1b2c3,
	} {
		t.Run(name, func(t *testing.T) {
			written := pki.Serial(&x509.Certificate{SerialNumber: big.NewInt(serial)})
			if len(written)%2 != 0 {
				t.Fatalf("%#x was written as %q", serial, written)
			}
			back, ok := new(big.Int).SetString(written, 16)
			if !ok || back.Int64() != serial {
				t.Fatalf("%#x was written as %q and reads back as %v", serial, written, back)
			}
		})
	}
}

func TestASignedSerialIsNeverZero(t *testing.T) {
	signing := authority(t, 30*24*time.Hour)
	for range 64 {
		issued, err := signing.Sign(subject, request(t, subject), time.Hour, time.Now().UTC())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := agent.Bindable(subject, issued.Identity, time.Now().UTC()); err != nil {
			t.Fatalf("the registry refused a signed identity: %v", err)
		}
	}
}

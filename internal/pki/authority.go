// Package pki signs the certificates an agent authenticates with. It states what
// a signing request may ask for, what the platform will put its name to and what
// was recorded about the result. It reads no file and serves no transport: the
// material is handed to it already parsed, so the process that holds the private
// key is a composition root and never this package.
package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	MinValidity = time.Hour
	MaxValidity = 90 * 24 * time.Hour
	backdate    = time.Minute
	serialBits  = 128
)

var (
	ErrMalformedAuthority = errors.New("the certificate authority cannot sign")
	ErrUnusableValidity   = errors.New("the certificate validity is not one this platform issues")
	ErrAuthorityExpired   = errors.New("the certificate authority is not valid at this moment")
)

type Authority struct {
	certificate *x509.Certificate
	key         crypto.Signer
	chain       []byte
}

type Issued struct {
	CertificatePEM []byte
	Identity       *agentv1.Identity
}

func NewAuthority(certificatePEM, keyPEM []byte) (*Authority, error) {
	certificate, chain, err := leadingCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return nil, fmt.Errorf("%w: %s is not a certificate authority", ErrMalformedAuthority, certificate.Subject)
	}
	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: %s may not sign certificates", ErrMalformedAuthority, certificate.Subject)
	}
	key, err := privateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	held, comparable := certificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !comparable || !held.Equal(key.Public()) {
		return nil, fmt.Errorf("%w: the key does not belong to %s", ErrMalformedAuthority, certificate.Subject)
	}
	return &Authority{certificate: certificate, key: key, chain: chain}, nil
}

func (a *Authority) Subject() string { return a.certificate.Subject.CommonName }

func (a *Authority) Chain() []byte { return append([]byte(nil), a.chain...) }

func (a *Authority) NotAfter() time.Time { return a.certificate.NotAfter }

// The identity this returns is the one the registry validates and records, so
// what was signed and what was bound cannot disagree.
func (a *Authority) Sign(subject string, requestPEM []byte, validity time.Duration, at time.Time) (Issued, error) {
	if validity < MinValidity || validity > MaxValidity {
		return Issued{}, fmt.Errorf("%w: %s is outside %s to %s",
			ErrUnusableValidity, validity, MinValidity, MaxValidity)
	}
	notBefore, notAfter := at.UTC().Add(-backdate), at.UTC().Add(validity)
	if at.Before(a.certificate.NotBefore) || !a.certificate.NotAfter.After(at) {
		return Issued{}, fmt.Errorf("%w: %s is valid from %s to %s", ErrAuthorityExpired,
			a.certificate.Subject.CommonName, a.certificate.NotBefore.Format(time.RFC3339),
			a.certificate.NotAfter.Format(time.RFC3339))
	}
	if notAfter.After(a.certificate.NotAfter) {
		notAfter = a.certificate.NotAfter
	}

	asked, err := parseRequest(requestPEM, subject)
	if err != nil {
		return Issued{}, err
	}
	serial, err := serialNumber()
	if err != nil {
		return Issued{}, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, asked.PublicKey, a.key)
	if err != nil {
		return Issued{}, fmt.Errorf("sign agent certificate: %w", err)
	}
	signed, err := x509.ParseCertificate(der)
	if err != nil {
		return Issued{}, fmt.Errorf("parse the signed agent certificate: %w", err)
	}

	digest := sha256.Sum256(der)
	return Issued{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Identity: &agentv1.Identity{
			Subject:           signed.Subject.CommonName,
			Serial:            Serial(signed),
			FingerprintSha256: hex.EncodeToString(digest[:]),
			IssuedAt:          timestamppb.New(signed.NotBefore),
			ExpiresAt:         timestamppb.New(signed.NotAfter),
		},
	}, nil
}

// Whole bytes, lower case, the way a certificate tool prints one. big.Int.Text
// drops a leading zero nibble instead, which renders the same certificate two
// ways depending on its first byte and makes a recorded serial unmatchable.
func Serial(certificate *x509.Certificate) string {
	return hex.EncodeToString(certificate.SerialNumber.Bytes())
}

// Never zero: a serial is what names a certificate, and one an identity cannot
// carry is one the registry would refuse after the platform had already signed.
func serialNumber() (*big.Int, error) {
	drawn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits-1))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return drawn.Add(drawn, big.NewInt(1)), nil
}

func leadingCertificate(bundlePEM []byte) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(bundlePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("%w: it is not a PEM certificate", ErrMalformedAuthority)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformedAuthority, err)
	}
	return certificate, append([]byte(nil), bundlePEM...), nil
}

func privateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: the key is not PEM", ErrMalformedAuthority)
	}
	parsed, err := parseKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the key is not an unencrypted PKCS#8, PKCS#1 or SEC 1 key: %v",
			ErrMalformedAuthority, err)
	}
	signer, signs := parsed.(crypto.Signer)
	if !signs {
		return nil, fmt.Errorf("%w: the key cannot sign", ErrMalformedAuthority)
	}
	return signer, nil
}

func parseKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return x509.ParsePKCS1PrivateKey(der)
}

package devpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

// What a certificate written before must still be issued for, so a run that
// finds it can keep it rather than mint one nobody enrolled trusts yet.
type Leaf struct {
	CommonName   string
	Organisation []string
	Hosts        []string
	Usage        x509.ExtKeyUsage
}

// An authority an earlier run wrote, taken back with its key so what it signs
// next is trusted by everything already enrolled under it.
func LoadAuthority(material Material, at time.Time, margin time.Duration) (*Authority, error) {
	certificate, err := lasting(material.CertificatePEM, at, margin)
	if err != nil {
		return nil, err
	}
	if !certificate.IsCA {
		return nil, errors.New("the certificate is not an authority")
	}
	key, err := keyOf(material.PrivateKeyPEM, certificate)
	if err != nil {
		return nil, err
	}
	return &Authority{certificate: certificate, key: key, material: material}, nil
}

func Lasts(authority Material, at time.Time, margin time.Duration) error {
	certificate, err := lasting(authority.CertificatePEM, at, margin)
	if err != nil {
		return err
	}
	if !certificate.IsCA {
		return errors.New("the certificate is not an authority")
	}
	return nil
}

// Keeps says why a certificate written before cannot stay, or nothing when it
// can: the authority signed it for the asked name, organisation, hosts and use,
// it still holds the key written beside it, and it outlasts the margin.
func Keeps(authority, leaf Material, wanted Leaf, at time.Time, margin time.Duration) error {
	root, err := parse(authority.CertificatePEM)
	if err != nil {
		return fmt.Errorf("the authority: %w", err)
	}
	certificate, err := lasting(leaf.CertificatePEM, at, margin)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{wanted.Usage}}); err != nil {
		return fmt.Errorf("not issued by the authority for this use: %w", err)
	}
	if certificate.Subject.CommonName != wanted.CommonName {
		return fmt.Errorf("issued to %q, and %q is asked for", certificate.Subject.CommonName, wanted.CommonName)
	}
	if !slices.Equal(slices.Sorted(slices.Values(certificate.Subject.Organization)), slices.Sorted(slices.Values(wanted.Organisation))) {
		return fmt.Errorf("issued for %v, and %v is asked for", certificate.Subject.Organization, wanted.Organisation)
	}
	for _, host := range wanted.Hosts {
		if err := certificate.VerifyHostname(host); err != nil {
			return fmt.Errorf("does not cover %s", host)
		}
	}
	if _, err := keyOf(leaf.PrivateKeyPEM, certificate); err != nil {
		return err
	}
	return nil
}

// Carries says whether a trust bundle holds the authority, whatever else an
// operator widened it with.
func Carries(bundle []byte, authority Material) bool {
	wanted, err := parse(authority.CertificatePEM)
	if err != nil {
		return false
	}
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, wanted.Raw) {
			return true
		}
	}
}

func lasting(encoded []byte, at time.Time, margin time.Duration) (*x509.Certificate, error) {
	certificate, err := parse(encoded)
	if err != nil {
		return nil, err
	}
	if at.Before(certificate.NotBefore) || certificate.NotAfter.Sub(at) < margin {
		return nil, fmt.Errorf("valid from %s to %s, which does not outlast %s from now", certificate.NotBefore.Format(time.RFC3339), certificate.NotAfter.Format(time.RFC3339), margin)
	}
	return certificate, nil
}

func parse(encoded []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate is written")
	}
	return x509.ParseCertificate(block.Bytes)
}

func keyOf(encoded []byte, certificate *x509.Certificate) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no private key is written beside the certificate")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(certificate.PublicKey) {
		return nil, errors.New("the private key written beside the certificate is not its key")
	}
	return key, nil
}

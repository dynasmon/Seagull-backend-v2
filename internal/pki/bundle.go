package pki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const MaxBundleBytes = 65536

var ErrMalformedBundle = errors.New("the trust bundle cannot be published to an agent")

// What an agent verifies a Seagull listener against, so a bundle carrying
// anything but certificate authorities is refused here rather than shipped and
// silently ignored by whoever reads it.
func Authorities(bundlePEM []byte) ([]*x509.Certificate, error) {
	if len(bundlePEM) == 0 {
		return nil, fmt.Errorf("%w: it is empty", ErrMalformedBundle)
	}
	if len(bundlePEM) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: it is longer than %d bytes", ErrMalformedBundle, MaxBundleBytes)
	}

	var authorities []*x509.Certificate
	remaining := bundlePEM
	for len(trimmed(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: it holds a block that is not a PEM certificate", ErrMalformedBundle)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedBundle, err)
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return nil, fmt.Errorf("%w: %s is not a certificate authority",
				ErrMalformedBundle, certificate.Subject.CommonName)
		}
		authorities = append(authorities, certificate)
		remaining = rest
	}
	if len(authorities) == 0 {
		return nil, fmt.Errorf("%w: it holds no certificate", ErrMalformedBundle)
	}
	return authorities, nil
}

// A rotation is over when the authority that signs is the only one still
// trusted, and is impossible to finish if it was never trusted at all.
func Trusts(bundlePEM []byte, authority *Authority) error {
	authorities, err := Authorities(bundlePEM)
	if err != nil {
		return err
	}
	for _, held := range authorities {
		if held.Equal(authority.certificate) {
			return nil
		}
	}
	return fmt.Errorf("%w: it does not carry %s, which is the authority that signs",
		ErrMalformedBundle, authority.Subject())
}

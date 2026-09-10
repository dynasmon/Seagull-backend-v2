package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	MaxRequestBytes = 16384
	MinRSABits      = 2048
)

var ErrMalformedRequest = errors.New("the certificate signing request cannot be signed")

func parseRequest(requestPEM []byte, subject string) (*x509.CertificateRequest, error) {
	if len(requestPEM) == 0 {
		return nil, fmt.Errorf("%w: it is empty", ErrMalformedRequest)
	}
	if len(requestPEM) > MaxRequestBytes {
		return nil, fmt.Errorf("%w: it is longer than %d bytes", ErrMalformedRequest, MaxRequestBytes)
	}
	block, rest := pem.Decode(requestPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: it is not a PEM certificate request", ErrMalformedRequest)
	}
	if len(trimmed(rest)) != 0 {
		return nil, fmt.Errorf("%w: it carries more than one PEM block", ErrMalformedRequest)
	}
	asked, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedRequest, err)
	}
	if err := asked.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: it is not signed by the key it carries: %v", ErrMalformedRequest, err)
	}
	if asked.Subject.CommonName != subject {
		return nil, fmt.Errorf("%w: it names %q and the certificate is for %q",
			ErrMalformedRequest, asked.Subject.CommonName, subject)
	}
	return asked, usable(asked.PublicKey)
}

// A weak key signed once is trusted for the whole life of the certificate, so
// the request is refused rather than upgraded.
func usable(key any) error {
	switch held := key.(type) {
	case *ecdsa.PublicKey:
		switch held.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return fmt.Errorf("%w: the curve %s is not offered", ErrMalformedRequest, held.Curve.Params().Name)
	case *rsa.PublicKey:
		if held.N.BitLen() < MinRSABits {
			return fmt.Errorf("%w: an RSA key of %d bits is below %d",
				ErrMalformedRequest, held.N.BitLen(), MinRSABits)
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("%w: the key is of no type this platform signs", ErrMalformedRequest)
	}
}

func trimmed(value []byte) []byte {
	for len(value) > 0 {
		switch value[0] {
		case ' ', '\t', '\r', '\n':
			value = value[1:]
		default:
			return value
		}
	}
	return value
}

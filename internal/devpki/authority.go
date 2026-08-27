package devpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Material struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

type Authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	material    Material
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func NewAuthority(commonName string, validity time.Duration) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate authority key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate authority serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign authority certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse authority certificate: %w", err)
	}

	encodedKey, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	return &Authority{
		certificate: certificate,
		key:         key,
		material: Material{
			CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			PrivateKeyPEM:  encodedKey,
		},
	}, nil
}

func (a *Authority) Material() Material { return a.material }

func (a *Authority) IssueServer(commonName string, hosts []string, validity time.Duration) (Material, error) {
	return a.issue(commonName, nil, hosts, validity, x509.ExtKeyUsageServerAuth)
}

func (a *Authority) IssueClient(commonName string, validity time.Duration) (Material, error) {
	return a.issue(commonName, nil, nil, validity, x509.ExtKeyUsageClientAuth)
}

// A caller of the read plane is named by its common name and authorised by its
// organisation: the tenants it may read travel in the certificate, so the
// authority decides the scope and the request never does.
func (a *Authority) IssueCaller(commonName string, tenants []string, validity time.Duration) (Material, error) {
	return a.issue(commonName, tenants, nil, validity, x509.ExtKeyUsageClientAuth)
}

func (a *Authority) issue(commonName string, organisation, hosts []string, validity time.Duration, usage x509.ExtKeyUsage) (Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return Material{}, fmt.Errorf("generate leaf serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: organisation},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if address := net.ParseIP(host); address != nil {
			template.IPAddresses = append(template.IPAddresses, address)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.key)
	if err != nil {
		return Material{}, fmt.Errorf("sign leaf certificate: %w", err)
	}
	encodedKey, err := encodeKey(key)
	if err != nil {
		return Material{}, err
	}
	return Material{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  encodedKey,
	}, nil
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

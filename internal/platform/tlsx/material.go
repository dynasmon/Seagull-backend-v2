package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type stamp struct {
	size    int64
	modTime time.Time
}

func stampOf(path string) (stamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	return stamp{size: info.Size(), modTime: info.ModTime()}, nil
}

// Certificates are reloaded from disk on change so that a renewal does not
// require a restart of a listener that agents depend on.
type Material struct {
	certFile     string
	keyFile      string
	clientCAFile string

	mu            sync.RWMutex
	certificate   *tls.Certificate
	certStamp     stamp
	keyStamp      stamp
	clientCAs     *x509.CertPool
	clientCAStamp stamp
}

func NewMaterial(certFile, keyFile, clientCAFile string) (*Material, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("a server certificate and key are required")
	}
	material := &Material{certFile: certFile, keyFile: keyFile, clientCAFile: clientCAFile}
	if _, err := material.Certificate(); err != nil {
		return nil, err
	}
	if clientCAFile != "" {
		if _, err := material.ClientCAs(); err != nil {
			return nil, err
		}
	}
	return material, nil
}

func (m *Material) Certificate() (*tls.Certificate, error) {
	certStamp, err := stampOf(m.certFile)
	if err != nil {
		return nil, fmt.Errorf("read server certificate: %w", err)
	}
	keyStamp, err := stampOf(m.keyFile)
	if err != nil {
		return nil, fmt.Errorf("read server key: %w", err)
	}

	m.mu.RLock()
	cached := m.certificate
	fresh := cached != nil && m.certStamp == certStamp && m.keyStamp == keyStamp
	m.mu.RUnlock()
	if fresh {
		return cached, nil
	}

	loaded, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.certificate = &loaded
	m.certStamp = certStamp
	m.keyStamp = keyStamp
	return m.certificate, nil
}

func (m *Material) ClientCAs() (*x509.CertPool, error) {
	if m.clientCAFile == "" {
		return nil, errors.New("no client certificate authority is configured")
	}
	caStamp, err := stampOf(m.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client certificate authority: %w", err)
	}

	m.mu.RLock()
	cached := m.clientCAs
	fresh := cached != nil && m.clientCAStamp == caStamp
	m.mu.RUnlock()
	if fresh {
		return cached, nil
	}

	pem, err := os.ReadFile(m.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client certificate authority: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("client certificate authority %q holds no certificate", m.clientCAFile)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientCAs = pool
	m.clientCAStamp = caStamp
	return pool, nil
}

func (m *Material) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.Certificate()
		},
	}
}

func (m *Material) MutualServerConfig() (*tls.Config, error) {
	if m.clientCAFile == "" {
		return nil, errors.New("mutual TLS requires a client certificate authority")
	}
	base := m.ServerConfig()
	base.ClientAuth = tls.RequireAndVerifyClientCert
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		pool, err := m.ClientCAs()
		if err != nil {
			return nil, err
		}
		clone := base.Clone()
		clone.ClientCAs = pool
		clone.GetConfigForClient = nil
		return clone, nil
	}
	return base, nil
}

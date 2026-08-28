package devpki

import (
	"fmt"
	"os"
	"path/filepath"
)

type Bundle struct {
	AuthorityCertificate string
	ServerCertificate    string
	ServerKey            string
	ClientCertificate    string
	ClientKey            string
	CallerCertificate    string
	CallerKey            string
}

// Private keys are written owner-readable only: development material still
// lands on a real filesystem, and a permissive default here becomes the habit
// that reaches production.
func Write(directory string, authority Material, server Material, client Material, caller Material) (Bundle, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Bundle{}, fmt.Errorf("create pki directory: %w", err)
	}

	bundle := Bundle{
		AuthorityCertificate: filepath.Join(directory, "agent-ca.pem"),
		ServerCertificate:    filepath.Join(directory, "gateway.pem"),
		ServerKey:            filepath.Join(directory, "gateway-key.pem"),
		ClientCertificate:    filepath.Join(directory, "agent.pem"),
		ClientKey:            filepath.Join(directory, "agent-key.pem"),
		CallerCertificate:    filepath.Join(directory, "caller.pem"),
		CallerKey:            filepath.Join(directory, "caller-key.pem"),
	}

	files := []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{bundle.AuthorityCertificate, authority.CertificatePEM, 0o644},
		{bundle.ServerCertificate, server.CertificatePEM, 0o644},
		{bundle.ServerKey, server.PrivateKeyPEM, 0o600},
		{bundle.ClientCertificate, client.CertificatePEM, 0o644},
		{bundle.ClientKey, client.PrivateKeyPEM, 0o600},
		{bundle.CallerCertificate, caller.CertificatePEM, 0o644},
		{bundle.CallerKey, caller.PrivateKeyPEM, 0o600},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, file.content, file.mode); err != nil {
			return Bundle{}, fmt.Errorf("write %s: %w", file.path, err)
		}
		if err := os.Chmod(file.path, file.mode); err != nil {
			return Bundle{}, fmt.Errorf("secure %s: %w", file.path, err)
		}
	}
	return bundle, nil
}

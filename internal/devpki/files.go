package devpki

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Two trust domains, not one. An agent's certificate authenticates it to the
// gateway and to nothing else; an operator's authenticates a person or an
// automation to the control and query planes. A single authority over both
// would mean a captured agent key could speak as an administrator, and no
// application check would be involved in stopping it.
type Bundle struct {
	AgentAuthority     string
	AgentAuthorityKey  string
	AgentTrustBundle   string
	GatewayCertificate string
	GatewayKey         string
	RenewalCertificate string
	RenewalKey         string
	AgentCertificate   string
	AgentKey           string

	OperatorAuthority  string
	ControlCertificate string
	ControlKey         string
	QueryCertificate   string
	QueryKey           string
	CallerCertificate  string
	CallerKey          string
	AdminCertificate   string
	AdminKey           string

	TenantAdminCertificate string
	TenantAdminKey         string
}

type Domain struct {
	Authority Material
	Servers   map[string]Material
	Clients   map[string]Material
	Trusted   []byte
}

// Private keys are written owner-readable only: development material still
// lands on a real filesystem, and a permissive default here becomes the habit
// that reaches production.
func Write(directory string, agents, operators Domain) (Bundle, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Bundle{}, fmt.Errorf("create pki directory: %w", err)
	}
	bundle := Layout(directory)
	trusted := agents.Trusted
	if len(trusted) == 0 {
		trusted = agents.Authority.CertificatePEM
	}

	files := []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{bundle.AgentAuthority, agents.Authority.CertificatePEM, 0o644},
		{bundle.AgentAuthorityKey, agents.Authority.PrivateKeyPEM, 0o600},
		{bundle.AgentTrustBundle, trusted, 0o644},
		{bundle.GatewayCertificate, agents.Servers["gateway"].CertificatePEM, 0o644},
		{bundle.GatewayKey, agents.Servers["gateway"].PrivateKeyPEM, 0o600},
		{bundle.RenewalCertificate, agents.Servers["renewal"].CertificatePEM, 0o644},
		{bundle.RenewalKey, agents.Servers["renewal"].PrivateKeyPEM, 0o600},
		{bundle.AgentCertificate, agents.Clients["agent"].CertificatePEM, 0o644},
		{bundle.AgentKey, agents.Clients["agent"].PrivateKeyPEM, 0o600},

		{bundle.OperatorAuthority, operators.Authority.CertificatePEM, 0o644},
		{bundle.ControlCertificate, operators.Servers["control-api"].CertificatePEM, 0o644},
		{bundle.ControlKey, operators.Servers["control-api"].PrivateKeyPEM, 0o600},
		{bundle.QueryCertificate, operators.Servers["query-api"].CertificatePEM, 0o644},
		{bundle.QueryKey, operators.Servers["query-api"].PrivateKeyPEM, 0o600},
		{bundle.CallerCertificate, operators.Clients["caller"].CertificatePEM, 0o644},
		{bundle.CallerKey, operators.Clients["caller"].PrivateKeyPEM, 0o600},
		{bundle.AdminCertificate, operators.Clients["admin"].CertificatePEM, 0o644},
		{bundle.AdminKey, operators.Clients["admin"].PrivateKeyPEM, 0o600},
		{bundle.TenantAdminCertificate, operators.Clients["tenant-admin"].CertificatePEM, 0o644},
		{bundle.TenantAdminKey, operators.Clients["tenant-admin"].PrivateKeyPEM, 0o600},
	}
	for _, file := range files {
		if len(file.content) == 0 {
			return Bundle{}, fmt.Errorf("%s has no material to write", file.path)
		}
		if held, err := os.ReadFile(file.path); err != nil || !bytes.Equal(held, file.content) {
			if err := os.WriteFile(file.path, file.content, file.mode); err != nil {
				return Bundle{}, fmt.Errorf("write %s: %w", file.path, err)
			}
		}
		if err := os.Chmod(file.path, file.mode); err != nil {
			return Bundle{}, fmt.Errorf("secure %s: %w", file.path, err)
		}
	}
	return bundle, nil
}

func Layout(directory string) Bundle {
	at := func(name string) string { return filepath.Join(directory, name) }
	return Bundle{
		AgentAuthority:     at("agent-ca.pem"),
		AgentAuthorityKey:  at("agent-ca-key.pem"),
		AgentTrustBundle:   at("agent-trust.pem"),
		GatewayCertificate: at("gateway.pem"),
		GatewayKey:         at("gateway-key.pem"),
		RenewalCertificate: at("control-api-renewal.pem"),
		RenewalKey:         at("control-api-renewal-key.pem"),
		AgentCertificate:   at("agent.pem"),
		AgentKey:           at("agent-key.pem"),

		OperatorAuthority:  at("operator-ca.pem"),
		ControlCertificate: at("control-api.pem"),
		ControlKey:         at("control-api-key.pem"),
		QueryCertificate:   at("query-api.pem"),
		QueryKey:           at("query-api-key.pem"),
		CallerCertificate:  at("caller.pem"),
		CallerKey:          at("caller-key.pem"),
		AdminCertificate:   at("admin.pem"),
		AdminKey:           at("admin-key.pem"),

		TenantAdminCertificate: at("tenant-admin.pem"),
		TenantAdminKey:         at("tenant-admin-key.pem"),
	}
}

// Write's inverse, holding nothing where a file is missing, so a run can keep
// what an earlier one minted; a file that is there and cannot be read stops it
// rather than being minted over. It reads through a root opened on the
// directory, so no name it is given reaches outside it.
func Read(directory string) (agents, operators Domain, err error) {
	root, err := os.OpenRoot(directory)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Domain{}, Domain{}, nil
	case err != nil:
		return Domain{}, Domain{}, fmt.Errorf("open %s: %w", directory, err)
	}
	defer func() { _ = root.Close() }()

	bundle := Layout(directory)
	read := func(path string) []byte {
		content, failed := root.ReadFile(filepath.Base(path))
		if failed != nil && !errors.Is(failed, fs.ErrNotExist) && err == nil {
			err = fmt.Errorf("read %s: %w", path, failed)
		}
		return content
	}
	material := func(certificate, key string) Material {
		return Material{CertificatePEM: read(certificate), PrivateKeyPEM: read(key)}
	}
	agents = Domain{
		Authority: material(bundle.AgentAuthority, bundle.AgentAuthorityKey),
		Servers: map[string]Material{
			"gateway": material(bundle.GatewayCertificate, bundle.GatewayKey),
			"renewal": material(bundle.RenewalCertificate, bundle.RenewalKey),
		},
		Clients: map[string]Material{"agent": material(bundle.AgentCertificate, bundle.AgentKey)},
		Trusted: read(bundle.AgentTrustBundle),
	}
	operators = Domain{
		Authority: Material{CertificatePEM: read(bundle.OperatorAuthority)},
		Servers: map[string]Material{
			"control-api": material(bundle.ControlCertificate, bundle.ControlKey),
			"query-api":   material(bundle.QueryCertificate, bundle.QueryKey),
		},
		Clients: map[string]Material{
			"caller":       material(bundle.CallerCertificate, bundle.CallerKey),
			"tenant-admin": material(bundle.TenantAdminCertificate, bundle.TenantAdminKey),
			"admin":        material(bundle.AdminCertificate, bundle.AdminKey),
		},
	}
	return agents, operators, err
}

package devpki

import (
	"fmt"
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
	GatewayCertificate string
	GatewayKey         string
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
}

type Domain struct {
	Authority Material
	Servers   map[string]Material
	Clients   map[string]Material
}

// Private keys are written owner-readable only: development material still
// lands on a real filesystem, and a permissive default here becomes the habit
// that reaches production.
func Write(directory string, agents, operators Domain) (Bundle, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Bundle{}, fmt.Errorf("create pki directory: %w", err)
	}

	at := func(name string) string { return filepath.Join(directory, name) }
	bundle := Bundle{
		AgentAuthority:     at("agent-ca.pem"),
		GatewayCertificate: at("gateway.pem"),
		GatewayKey:         at("gateway-key.pem"),
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
	}

	files := []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{bundle.AgentAuthority, agents.Authority.CertificatePEM, 0o644},
		{bundle.GatewayCertificate, agents.Servers["gateway"].CertificatePEM, 0o644},
		{bundle.GatewayKey, agents.Servers["gateway"].PrivateKeyPEM, 0o600},
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
	}
	for _, file := range files {
		if len(file.content) == 0 {
			return Bundle{}, fmt.Errorf("%s has no material to write", file.path)
		}
		if err := os.WriteFile(file.path, file.content, file.mode); err != nil {
			return Bundle{}, fmt.Errorf("write %s: %w", file.path, err)
		}
		if err := os.Chmod(file.path, file.mode); err != nil {
			return Bundle{}, fmt.Errorf("secure %s: %w", file.path, err)
		}
	}
	return bundle, nil
}

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func minted(t *testing.T) string {
	t.Helper()

	directory := t.TempDir()
	if err := generate(directory, "dev-agent-01", "dev-analyst", "dev-admin",
		[]string{"default"}, []string{"localhost", "127.0.0.1"}, time.Hour); err != nil {
		t.Fatalf("mint the development material: %v", err)
	}
	return directory
}

func read(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatalf("%s carries no certificate", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return certificate
}

func pool(t *testing.T, path string) *x509.CertPool {
	t.Helper()

	held := x509.NewCertPool()
	held.AddCert(read(t, path))
	return held
}

// The property the split exists for: a captured agent key cannot be presented
// to the control or query plane, and an administrator's cannot be presented to
// the gateway. Neither refusal involves an application check.
func TestAnIdentityFromOneTrustDomainIsRefusedByTheOther(t *testing.T) {
	directory := minted(t)
	agents := pool(t, filepath.Join(directory, "agent-ca.pem"))
	operators := pool(t, filepath.Join(directory, "operator-ca.pem"))

	client := x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}

	client.Roots = agents
	if _, err := read(t, filepath.Join(directory, "agent.pem")).Verify(client); err != nil {
		t.Fatalf("the agent was refused by the authority that issued it: %v", err)
	}
	if _, err := read(t, filepath.Join(directory, "admin.pem")).Verify(client); err == nil {
		t.Error("an administrator certificate authenticates as an agent")
	}

	client.Roots = operators
	if _, err := read(t, filepath.Join(directory, "admin.pem")).Verify(client); err != nil {
		t.Fatalf("the administrator was refused by the authority that issued it: %v", err)
	}
	if _, err := read(t, filepath.Join(directory, "agent.pem")).Verify(client); err == nil {
		t.Error("an agent certificate authenticates to the control plane")
	}
}

// Each plane carries a key of its own, so compromising the agent-facing gateway
// does not hand over the identity the control plane answers as.
func TestEveryPlaneAnswersWithAKeyOfItsOwn(t *testing.T) {
	directory := minted(t)

	serial := map[string]string{}
	for file, name := range map[string]string{
		"gateway":     "ingest-gateway",
		"control-api": "control-api",
		"query-api":   "query-api",
	} {
		certificate := read(t, filepath.Join(directory, file+".pem"))
		if held, shared := serial[certificate.SerialNumber.String()]; shared {
			t.Errorf("%s answers with the same certificate as %s", name, held)
		}
		serial[certificate.SerialNumber.String()] = name
		if err := certificate.VerifyHostname(name); err != nil {
			t.Errorf("%s does not answer for its own name: %v", name, err)
		}
	}
}

func TestTheGatewayIsVerifiableByAgentsAndThePlanesByOperators(t *testing.T) {
	directory := minted(t)
	server := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "localhost",
	}

	server.Roots = pool(t, filepath.Join(directory, "agent-ca.pem"))
	if _, err := read(t, filepath.Join(directory, "gateway.pem")).Verify(server); err != nil {
		t.Errorf("an agent cannot verify the gateway: %v", err)
	}
	if _, err := read(t, filepath.Join(directory, "control-api.pem")).Verify(server); err == nil {
		t.Error("the control plane is verifiable by whoever trusts agents")
	}

	server.Roots = pool(t, filepath.Join(directory, "operator-ca.pem"))
	for _, name := range []string{"control-api", "query-api"} {
		if _, err := read(t, filepath.Join(directory, name+".pem")).Verify(server); err != nil {
			t.Errorf("an operator cannot verify %s: %v", name, err)
		}
	}
}

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
	run(t, directory, []string{"localhost", "127.0.0.1"}, false, time.Now())
	return directory
}

func run(t *testing.T, directory string, hosts []string, rotate bool, at time.Time) {
	t.Helper()

	if err := generate(directory, "dev-agent-01", "dev-analyst", "dev-tenant-admin", "dev-admin",
		[]string{"default"}, hosts, time.Hour, rotate, at); err != nil {
		t.Fatalf("mint the development material: %v", err)
	}
}

func contents(t *testing.T, directory string, names ...string) map[string]string {
	t.Helper()

	held := map[string]string{}
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		held[name] = string(content)
	}
	return held
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

// The shipped policy binds three operators, and each needs a certificate of its
// own to be anybody: the one who reads, the administrator of a tenant and the
// administrator of the platform.
func TestEveryOperatorTheDevelopmentPolicyBindsIsIssuedAnIdentity(t *testing.T) {
	directory := minted(t)
	client := x509.VerifyOptions{
		Roots:     pool(t, filepath.Join(directory, "operator-ca.pem")),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for file, subject := range map[string]string{
		"caller":       "dev-analyst",
		"tenant-admin": "dev-tenant-admin",
		"admin":        "dev-admin",
	} {
		certificate := read(t, filepath.Join(directory, file+".pem"))
		if certificate.Subject.CommonName != subject {
			t.Errorf("%s.pem names %q, and the policy binds %q", file, certificate.Subject.CommonName, subject)
		}
		if _, err := certificate.Verify(client); err != nil {
			t.Errorf("%s was refused by the operator authority: %v", subject, err)
		}
		key, err := os.Stat(filepath.Join(directory, file+"-key.pem"))
		if err != nil {
			t.Errorf("%s has no key: %v", subject, err)
			continue
		}
		if key.Mode().Perm() != 0o600 {
			t.Errorf("the key of %s is readable as %v", subject, key.Mode().Perm())
		}
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

// make up runs this on every start, and every agent enrolled under the agent
// authority trusts that one alone; on 2026-11-20 a second make up orphaned them.
func TestARunKeepsWhatAnEarlierRunMinted(t *testing.T) {
	directory := minted(t)
	files := []string{"agent-ca.pem", "agent-ca-key.pem", "agent-trust.pem", "gateway.pem", "gateway-key.pem",
		"control-api-renewal.pem", "agent.pem", "operator-ca.pem", "control-api.pem", "query-api.pem", "admin.pem", "admin-key.pem"}
	before := contents(t, directory, files...)

	run(t, directory, []string{"localhost", "127.0.0.1"}, false, time.Now())
	for name, content := range contents(t, directory, files...) {
		if content != before[name] {
			t.Errorf("a second run replaced %s", name)
		}
	}

	run(t, directory, []string{"localhost", "127.0.0.1"}, true, time.Now())
	rotated := contents(t, directory, "agent-ca.pem", "operator-ca.pem")
	if rotated["agent-ca.pem"] == before["agent-ca.pem"] || rotated["operator-ca.pem"] == before["operator-ca.pem"] {
		t.Error("a rotation kept an authority")
	}
}

func TestAServerCertificateIsIssuedAgainFromTheKeptAuthorityForANewHost(t *testing.T) {
	directory := minted(t)
	before := contents(t, directory, "agent-ca.pem", "gateway.pem", "agent.pem", "operator-ca.pem")

	run(t, directory, []string{"localhost", "127.0.0.1", "192.0.2.10"}, false, time.Now())
	after := contents(t, directory, "agent-ca.pem", "gateway.pem", "agent.pem", "operator-ca.pem")
	if after["agent-ca.pem"] != before["agent-ca.pem"] || after["agent.pem"] != before["agent.pem"] {
		t.Fatal("a new host replaced the agent authority or the agent certificate")
	}
	if after["gateway.pem"] == before["gateway.pem"] {
		t.Fatal("the gateway certificate was kept, and it does not cover the new host")
	}
	server := x509.VerifyOptions{Roots: pool(t, filepath.Join(directory, "agent-ca.pem")), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, host := range []string{"192.0.2.10", "localhost", "ingest-gateway"} {
		server.DNSName = host
		if _, err := read(t, filepath.Join(directory, "gateway.pem")).Verify(server); err != nil {
			t.Errorf("an agent cannot verify the gateway at %s: %v", host, err)
		}
	}
	if after["operator-ca.pem"] == before["operator-ca.pem"] {
		t.Error("the operator domain was kept, and its servers do not cover the new host")
	}

	run(t, directory, []string{"localhost", "127.0.0.1"}, false, time.Now())
	if again := contents(t, directory, "gateway.pem"); again["gateway.pem"] != after["gateway.pem"] {
		t.Error("a run asking for fewer hosts narrowed a certificate agents may reach the gateway by")
	}
}

func TestACertificateNearItsEndIsIssuedAgainUnderTheSameAuthority(t *testing.T) {
	directory := minted(t)
	before := contents(t, directory, "agent-ca.pem", "gateway.pem", "agent.pem")

	run(t, directory, []string{"localhost", "127.0.0.1"}, false, time.Now().Add(55*time.Minute))
	after := contents(t, directory, "agent-ca.pem", "gateway.pem", "agent.pem")
	if after["agent-ca.pem"] != before["agent-ca.pem"] {
		t.Error("the agent authority was replaced, and it is valid for a day more")
	}
	if after["gateway.pem"] == before["gateway.pem"] || after["agent.pem"] == before["agent.pem"] {
		t.Error("a certificate with five minutes left of an hour was kept")
	}
}

func TestATrustBundleAnOperatorWidenedIsKept(t *testing.T) {
	directory := minted(t)
	other := t.TempDir()
	run(t, other, []string{"localhost"}, false, time.Now())
	widened := contents(t, directory, "agent-trust.pem")["agent-trust.pem"] + contents(t, other, "agent-ca.pem")["agent-ca.pem"]
	if err := os.WriteFile(filepath.Join(directory, "agent-trust.pem"), []byte(widened), 0o644); err != nil {
		t.Fatal(err)
	}

	run(t, directory, []string{"localhost", "127.0.0.1"}, false, time.Now())
	if kept := contents(t, directory, "agent-trust.pem")["agent-trust.pem"]; kept != widened {
		t.Error("a run narrowed a trust bundle an operator widened to rotate the authority")
	}
}

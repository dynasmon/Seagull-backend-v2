package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/devpki"
)

func main() {
	directory := flag.String("directory", ".local/pki", "where the development material is written")
	agentID := flag.String("agent-id", "dev-agent-01", "common name of the development agent certificate")
	caller := flag.String("caller", "dev-analyst", "common name of the development query caller certificate")
	tenantAdmin := flag.String("tenant-admin", "dev-tenant-admin", "common name of the development certificate of an administrator of one tenant")
	admin := flag.String("admin", "dev-admin", "common name of the development certificate of an administrator of the platform")
	tenants := flag.String("tenants", "default", "tenants the query caller certificate is authorised to read")
	hosts := flag.String("hosts", "localhost,127.0.0.1", "names and addresses every server certificate covers, on top of its own service name")
	validity := flag.Duration("validity", 90*24*time.Hour, "how long the issued certificates stay valid")
	rotate := flag.Bool("rotate", false, "mint new authorities, which every agent enrolled under the old one stops trusting, instead of keeping what still serves")
	flag.Parse()

	if err := generate(*directory, *agentID, *caller, *tenantAdmin, *admin, strings.Split(*tenants, ","), strings.Split(*hosts, ","), *validity, *rotate, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "devpki: %v\n", err)
		os.Exit(1)
	}
}

// A run keeps what an earlier one minted while it still serves, because every
// agent enrolled under the agent authority trusts that authority alone: minting
// it again on every start orphaned them all. A leaf is kept while a tenth of the
// asked validity is left of it.
func generate(directory, agentID, caller, tenantAdmin, admin string, tenants, hosts []string, validity time.Duration, rotate bool, at time.Time) error {
	var heldAgents, heldOperators devpki.Domain
	if !rotate {
		var err error
		if heldAgents, heldOperators, err = devpki.Read(directory); err != nil {
			return err
		}
	}
	margin := validity / 10
	agents, agentsKept, err := agentDomain(heldAgents, agentID, hosts, validity, at, margin)
	if err != nil {
		return err
	}
	operators, operatorsKept, err := operatorDomain(heldOperators, caller, tenantAdmin, admin, tenants, hosts, validity, at, margin)
	if err != nil {
		return err
	}

	bundle, err := devpki.Write(directory, agents, operators)
	if err != nil {
		return err
	}

	state := func(kept bool) string {
		if kept {
			return "kept"
		}
		return "issued"
	}
	fmt.Printf("agent authority     %s (%s)\n", bundle.AgentAuthority, state(agentsKept["authority"]))
	fmt.Printf("agent authority key %s\n", bundle.AgentAuthorityKey)
	fmt.Printf("agent trust bundle  %s\n", bundle.AgentTrustBundle)
	fmt.Printf("gateway             %s (%s)\n", bundle.GatewayCertificate, state(agentsKept["gateway"]))
	fmt.Printf("control-api renewal %s (%s)\n", bundle.RenewalCertificate, state(agentsKept["renewal"]))
	fmt.Printf("agent               %s (%s)\n", bundle.AgentCertificate, state(agentsKept["agent"]))
	fmt.Printf("operator authority  %s (%s)\n", bundle.OperatorAuthority, state(operatorsKept))
	fmt.Printf("control-api         %s\n", bundle.ControlCertificate)
	fmt.Printf("query-api           %s\n", bundle.QueryCertificate)
	fmt.Printf("caller              %s\n", bundle.CallerCertificate)
	fmt.Printf("tenant admin        %s\n", bundle.TenantAdminCertificate)
	fmt.Printf("administrator       %s\n", bundle.AdminCertificate)

	if len(heldAgents.Authority.CertificatePEM) > 0 && !agentsKept["authority"] {
		fmt.Fprintln(os.Stderr, "devpki: the agent authority was minted anew; every agent enrolled under the previous one has to be enrolled again")
	}
	if len(heldAgents.Authority.CertificatePEM) > 0 && (!agentsKept["gateway"] || !agentsKept["renewal"] || !operatorsKept) {
		fmt.Fprintln(os.Stderr, "devpki: a running stack serves what it read at start; restart it to serve what was issued now")
	}
	return nil
}

// What an agent may authenticate to, and nothing else: the gateway it sends
// telemetry to, the control plane surface it renews its certificate on, and the
// identity it uses for both. The authority's key is written too, because the
// control plane is now the one that signs with it.
func agentDomain(held devpki.Domain, agentID string, hosts []string, validity time.Duration, at time.Time, margin time.Duration) (devpki.Domain, map[string]bool, error) {
	kept := map[string]bool{}
	authority, err := devpki.LoadAuthority(held.Authority, at, margin)
	if err == nil {
		kept["authority"] = true
	} else if authority, err = devpki.NewAuthority("Seagull Development Agent CA", validity+24*time.Hour); err != nil {
		return devpki.Domain{}, nil, err
	}
	domain := devpki.Domain{Authority: authority.Material(), Servers: map[string]devpki.Material{}, Clients: map[string]devpki.Material{}}
	if kept["authority"] && devpki.Carries(held.Trusted, domain.Authority) {
		domain.Trusted = held.Trusted
	}

	leaves := map[string]devpki.Leaf{
		"gateway": {CommonName: "ingest-gateway", Hosts: append([]string{"ingest-gateway"}, hosts...), Usage: x509.ExtKeyUsageServerAuth},
		"renewal": {CommonName: "control-api", Hosts: append([]string{"control-api"}, hosts...), Usage: x509.ExtKeyUsageServerAuth},
		"agent":   {CommonName: agentID, Usage: x509.ExtKeyUsageClientAuth},
	}
	for role, leaf := range leaves {
		previous := held.Servers[role]
		if role == "agent" {
			previous = held.Clients[role]
		}
		material := previous
		if kept[role] = kept["authority"] && devpki.Keeps(domain.Authority, previous, leaf, at, margin) == nil; !kept[role] {
			if material, err = issue(authority, leaf, validity); err != nil {
				return devpki.Domain{}, nil, err
			}
		}
		if role == "agent" {
			domain.Clients[role] = material
			continue
		}
		domain.Servers[role] = material
	}
	return domain, kept, nil
}

// What a person or an automation may authenticate to. Each plane gets a key of
// its own, so the gateway's key is not also the control plane's. The authority's
// key is never written, so the domain is kept whole or minted whole.
func operatorDomain(held devpki.Domain, caller, tenantAdmin, admin string, tenants, hosts []string, validity time.Duration, at time.Time, margin time.Duration) (devpki.Domain, bool, error) {
	servers := map[string]devpki.Leaf{}
	for _, name := range []string{"control-api", "query-api"} {
		servers[name] = devpki.Leaf{CommonName: name, Hosts: append([]string{name}, hosts...), Usage: x509.ExtKeyUsageServerAuth}
	}
	clients := map[string]devpki.Leaf{}
	for name, subject := range map[string]string{"caller": caller, "tenant-admin": tenantAdmin, "admin": admin} {
		clients[name] = devpki.Leaf{CommonName: subject, Organisation: tenants, Usage: x509.ExtKeyUsageClientAuth}
	}

	keeps := devpki.Lasts(held.Authority, at, margin) == nil
	for name, leaf := range servers {
		keeps = keeps && devpki.Keeps(held.Authority, held.Servers[name], leaf, at, margin) == nil
	}
	for name, leaf := range clients {
		keeps = keeps && devpki.Keeps(held.Authority, held.Clients[name], leaf, at, margin) == nil
	}
	if keeps {
		return devpki.Domain{Authority: held.Authority, Servers: held.Servers, Clients: held.Clients}, true, nil
	}

	authority, err := devpki.NewAuthority("Seagull Development Operator CA", validity+24*time.Hour)
	if err != nil {
		return devpki.Domain{}, false, err
	}
	domain := devpki.Domain{Authority: authority.Material(), Servers: map[string]devpki.Material{}, Clients: map[string]devpki.Material{}}
	for name, leaf := range servers {
		if domain.Servers[name], err = issue(authority, leaf, validity); err != nil {
			return devpki.Domain{}, false, err
		}
	}
	for name, leaf := range clients {
		if domain.Clients[name], err = issue(authority, leaf, validity); err != nil {
			return devpki.Domain{}, false, err
		}
	}
	return domain, false, nil
}

func issue(authority *devpki.Authority, leaf devpki.Leaf, validity time.Duration) (devpki.Material, error) {
	switch {
	case leaf.Usage == x509.ExtKeyUsageServerAuth:
		return authority.IssueServer(leaf.CommonName, leaf.Hosts, validity)
	case len(leaf.Organisation) > 0:
		return authority.IssueCaller(leaf.CommonName, leaf.Organisation, validity)
	}
	return authority.IssueClient(leaf.CommonName, validity)
}

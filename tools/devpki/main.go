package main

import (
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
	flag.Parse()

	if err := generate(*directory, *agentID, *caller, *tenantAdmin, *admin, strings.Split(*tenants, ","), strings.Split(*hosts, ","), *validity); err != nil {
		fmt.Fprintf(os.Stderr, "devpki: %v\n", err)
		os.Exit(1)
	}
}

func generate(directory, agentID, caller, tenantAdmin, admin string, tenants, hosts []string, validity time.Duration) error {
	agents, err := agentDomain(agentID, hosts, validity)
	if err != nil {
		return err
	}
	operators, err := operatorDomain(caller, tenantAdmin, admin, tenants, hosts, validity)
	if err != nil {
		return err
	}

	bundle, err := devpki.Write(directory, agents, operators)
	if err != nil {
		return err
	}

	fmt.Printf("agent authority     %s\n", bundle.AgentAuthority)
	fmt.Printf("agent authority key %s\n", bundle.AgentAuthorityKey)
	fmt.Printf("agent trust bundle  %s\n", bundle.AgentTrustBundle)
	fmt.Printf("gateway             %s\n", bundle.GatewayCertificate)
	fmt.Printf("control-api renewal %s\n", bundle.RenewalCertificate)
	fmt.Printf("agent               %s\n", bundle.AgentCertificate)
	fmt.Printf("operator authority  %s\n", bundle.OperatorAuthority)
	fmt.Printf("control-api         %s\n", bundle.ControlCertificate)
	fmt.Printf("query-api           %s\n", bundle.QueryCertificate)
	fmt.Printf("caller              %s\n", bundle.CallerCertificate)
	fmt.Printf("tenant admin        %s\n", bundle.TenantAdminCertificate)
	fmt.Printf("administrator       %s\n", bundle.AdminCertificate)
	return nil
}

// What an agent may authenticate to, and nothing else: the gateway it sends
// telemetry to, the control plane surface it renews its certificate on, and the
// identity it uses for both. The authority's key is written too, because the
// control plane is now the one that signs with it.
func agentDomain(agentID string, hosts []string, validity time.Duration) (devpki.Domain, error) {
	authority, err := devpki.NewAuthority("Seagull Development Agent CA", validity+24*time.Hour)
	if err != nil {
		return devpki.Domain{}, err
	}
	gateway, err := authority.IssueServer("ingest-gateway", append([]string{"ingest-gateway"}, hosts...), validity)
	if err != nil {
		return devpki.Domain{}, err
	}
	renewal, err := authority.IssueServer("control-api", append([]string{"control-api"}, hosts...), validity)
	if err != nil {
		return devpki.Domain{}, err
	}
	agent, err := authority.IssueClient(agentID, validity)
	if err != nil {
		return devpki.Domain{}, err
	}
	return devpki.Domain{
		Authority: authority.Material(),
		Servers:   map[string]devpki.Material{"gateway": gateway, "renewal": renewal},
		Clients:   map[string]devpki.Material{"agent": agent},
	}, nil
}

// What a person or an automation may authenticate to. Each plane gets a key of
// its own, so the gateway's key is not also the control plane's.
func operatorDomain(caller, tenantAdmin, admin string, tenants, hosts []string, validity time.Duration) (devpki.Domain, error) {
	authority, err := devpki.NewAuthority("Seagull Development Operator CA", validity+24*time.Hour)
	if err != nil {
		return devpki.Domain{}, err
	}

	servers := map[string]devpki.Material{}
	for _, name := range []string{"control-api", "query-api"} {
		issued, err := authority.IssueServer(name, append([]string{name}, hosts...), validity)
		if err != nil {
			return devpki.Domain{}, err
		}
		servers[name] = issued
	}

	clients := map[string]devpki.Material{}
	for name, subject := range map[string]string{"caller": caller, "tenant-admin": tenantAdmin, "admin": admin} {
		issued, err := authority.IssueCaller(subject, tenants, validity)
		if err != nil {
			return devpki.Domain{}, err
		}
		clients[name] = issued
	}
	return devpki.Domain{Authority: authority.Material(), Servers: servers, Clients: clients}, nil
}

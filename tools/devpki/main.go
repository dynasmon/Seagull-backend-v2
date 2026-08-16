package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-v2/internal/devpki"
)

func main() {
	directory := flag.String("directory", ".local/pki", "where the development material is written")
	agentID := flag.String("agent-id", "dev-agent-01", "common name of the development agent certificate")
	hosts := flag.String("hosts", "localhost,127.0.0.1,ingest-gateway", "names and addresses the gateway certificate covers")
	validity := flag.Duration("validity", 90*24*time.Hour, "how long the issued certificates stay valid")
	flag.Parse()

	if err := generate(*directory, *agentID, strings.Split(*hosts, ","), *validity); err != nil {
		fmt.Fprintf(os.Stderr, "devpki: %v\n", err)
		os.Exit(1)
	}
}

func generate(directory, agentID string, hosts []string, validity time.Duration) error {
	authority, err := devpki.NewAuthority("Seagull Development Agent CA", validity+24*time.Hour)
	if err != nil {
		return err
	}
	server, err := authority.IssueServer("ingest-gateway", hosts, validity)
	if err != nil {
		return err
	}
	client, err := authority.IssueClient(agentID, validity)
	if err != nil {
		return err
	}

	bundle, err := devpki.Write(directory, authority.Material(), server, client)
	if err != nil {
		return err
	}

	fmt.Printf("authority   %s\n", bundle.AuthorityCertificate)
	fmt.Printf("gateway     %s\n", bundle.ServerCertificate)
	fmt.Printf("gateway key %s\n", bundle.ServerKey)
	fmt.Printf("agent       %s\n", bundle.ClientCertificate)
	fmt.Printf("agent key   %s\n", bundle.ClientKey)
	return nil
}

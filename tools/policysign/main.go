package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentpolicy"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const maxDocumentBytes = 2 << 20

type keys []string

func (k *keys) String() string { return strings.Join(*k, ",") }

func (k *keys) Set(value string) error {
	*k = append(*k, value)
	return nil
}

func main() {
	var signing keys
	flag.Var(&signing, "key", "a PEM private key, ECDSA over P-256, to sign with; repeat it to sign with every key of a rotation")
	document := flag.String("policy", "", "the policy to sign, as the JSON form of seagull.policy.v1.Policy")
	tenant := flag.String("tenant", "", "the tenant the publication is for")
	note := flag.String("note", "", "why the policy is published, kept with what the platform records")
	lifetime := flag.Duration("lifetime", 0, "how long the signer vouches for the policy, when the document gives no expires_at")
	output := flag.String("output", "", "where the publication is written, ready to POST to /v1/agents/policies")
	flag.Parse()

	if err := run(signing, *document, *tenant, *note, *lifetime, *output, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "policysign:", err)
		os.Exit(1)
	}
}

func run(signing []string, document, tenant, note string, lifetime time.Duration, output string, now time.Time) error {
	switch {
	case len(signing) == 0:
		return errors.New("-key names the private key to sign with")
	case document == "":
		return errors.New("-policy names the policy to sign")
	case tenant == "":
		return errors.New("-tenant names the tenant the policy is published into")
	case output == "":
		return errors.New("-output names where the publication is written")
	}

	policy, err := read(document)
	if err != nil {
		return err
	}
	if policy.GetIssuedAt() == nil {
		policy.IssuedAt = timestamppb.New(now.UTC().Truncate(time.Second))
	}
	if policy.GetExpiresAt() == nil && lifetime > 0 {
		policy.ExpiresAt = timestamppb.New(policy.GetIssuedAt().AsTime().Add(lifetime))
	}
	if err := agentpolicy.Validate(policy, now); err != nil {
		return err
	}

	signers := make([]crypto.Signer, 0, len(signing))
	for _, path := range signing {
		key, err := privateKey(path)
		if err != nil {
			return err
		}
		signers = append(signers, key)
	}
	envelope, err := agentpolicy.Sign(policy, signers...)
	if err != nil {
		return err
	}
	encoded, err := proto.Marshal(&policyv1.Publication{TenantId: tenant, Policy: envelope, Note: note})
	if err != nil {
		return fmt.Errorf("encode the publication: %w", err)
	}
	if err := os.WriteFile(output, encoded, 0o600); err != nil {
		return err
	}

	ids := make([]string, 0, len(envelope.GetSignatures()))
	for _, signature := range envelope.GetSignatures() {
		ids = append(ids, signature.GetKeyid())
	}
	fmt.Fprintf(os.Stderr, "policysign: revision %d of %s names %d agents, expires %s, signed by %s\n",
		policy.GetRevision(), policy.GetPolicyId(), len(policy.GetTargets().GetAgentIds()),
		policy.GetExpiresAt().AsTime().Format(time.RFC3339), strings.Join(ids, ", "))
	return nil
}

func read(path string) (*policyv1.Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxDocumentBytes {
		return nil, fmt.Errorf("%s is longer than %d bytes", path, maxDocumentBytes)
	}
	var policy policyv1.Policy
	if err := protojson.Unmarshal(content, &policy); err != nil {
		return nil, fmt.Errorf("%s is not a policy: %w", path, err)
	}
	return &policy, nil
}

func privateKey(path string) (*ecdsa.PrivateKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM key", path)
	}
	var parsed any
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s holds a %s block, and a policy is signed with a private key", path, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ecdsaKey := parsed.(*ecdsa.PrivateKey)
	if !ecdsaKey {
		return nil, fmt.Errorf("%s is not an ECDSA key, and a policy is signed with ECDSA over P-256", path)
	}
	return key, nil
}

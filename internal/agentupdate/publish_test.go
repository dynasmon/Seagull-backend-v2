package agentupdate_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func TestAPublishedRootIsTheNextOneAndSaysWhoPublishedIt(t *testing.T) {
	before, after := newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{before}, 1, []signer{before}, 1), before)
	next := sign(t, rootOf(2, []signer{after}, 1, []signer{after}, 1), agentupdate.RootPayloadType, before, after)

	for name, asked := range map[string]struct {
		publication *updatev1.RootPublication
		actor       string
		want        error
	}{
		"nobody":         {&updatev1.RootPublication{Root: next}, "", agentupdate.ErrNoActor},
		"a long note":    {&updatev1.RootPublication{Root: next, Note: strings.Repeat("n", 513)}, "ops", agentupdate.ErrMalformed},
		"no root at all": {&updatev1.RootPublication{}, "ops", agentupdate.ErrMalformed},
	} {
		if _, err := agentupdate.AcceptRoot(asked.publication, trusted, asked.actor, written); !errors.Is(err, asked.want) {
			t.Errorf("%s: %v, want %v", name, err, asked.want)
		}
	}

	accepted, err := agentupdate.AcceptRoot(&updatev1.RootPublication{Root: next, Note: "rotate the signing keys"}, trusted, "ops", written)
	if err != nil {
		t.Fatalf("the next root was refused: %v", err)
	}
	record := accepted.Record
	if record.GetVersion() != 2 || record.GetDigestSha256() != agentupdate.Digest(accepted.Root.Served()) ||
		len(record.GetSignedBy()) != 2 || record.GetPublishedBy() != "ops" || record.GetNote() != "rotate the signing keys" ||
		!record.GetPublishedAt().AsTime().Equal(written) {
		t.Fatalf("recorded %v", record)
	}
}

func TestARootThatAlreadyRanOutIsNotPublished(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	stale := rootOf(2, []signer{owner}, 1, []signer{owner}, 1)
	stale.IssuedAt = timestamppb.New(written.Add(-200 * 24 * time.Hour))
	stale.ExpiresAt = timestamppb.New(written.Add(-time.Hour))

	if _, err := agentupdate.AcceptRoot(&updatev1.RootPublication{Root: sign(t, stale, agentupdate.RootPayloadType, owner)}, trusted, "ops", written); !errors.Is(err, agentupdate.ErrExpired) {
		t.Fatalf("a root that ran out was published: %v", err)
	}
}

func TestACatalogIsPublishedUnderARootInForceWhileItIsInForceItself(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	arm := releaseOf("v0.2.0", 1)
	arm.Platform.Architecture = "arm64"
	catalog := sign(t, catalogOf(3, releaseOf("v0.2.0", 1), arm, releaseOf("v0.3.0", 2)), agentupdate.CatalogPayloadType, owner)

	accepted, err := agentupdate.AcceptCatalog(&updatev1.CatalogPublication{Catalog: catalog}, trusted, "ops", written)
	if err != nil {
		t.Fatalf("the catalog was refused: %v", err)
	}
	if accepted.Record.GetVersion() != 3 || accepted.Record.GetReleases() != 3 || len(accepted.Packages) != 2 ||
		accepted.Record.GetDigestSha256() != agentupdate.Digest(accepted.Catalog.Served()) {
		t.Fatalf("recorded %v with packages %v", accepted.Record, accepted.Packages)
	}

	if _, err := agentupdate.AcceptCatalog(&updatev1.CatalogPublication{Catalog: catalog}, trusted, "ops", written.Add(181*24*time.Hour)); !errors.Is(err, agentupdate.ErrExpired) {
		t.Fatalf("a catalog was published under a root that ran out: %v", err)
	}
	if _, err := agentupdate.AcceptCatalog(&updatev1.CatalogPublication{Catalog: catalog}, trusted, "ops", written.Add(91*24*time.Hour)); !errors.Is(err, agentupdate.ErrExpired) {
		t.Fatalf("a catalog that ran out was published: %v", err)
	}

	resized := releaseOf("v0.3.0", 1)
	resized.Payload.Size++
	conflicting := sign(t, catalogOf(4, releaseOf("v0.2.0", 1), resized), agentupdate.CatalogPayloadType, owner)
	if _, err := agentupdate.AcceptCatalog(&updatev1.CatalogPublication{Catalog: conflicting}, trusted, "ops", written); !errors.Is(err, agentupdate.ErrMalformed) {
		t.Fatalf("one package of two sizes was published: %v", err)
	}
}

func TestAPackageIsKeptByItsDigestAndForNothingElse(t *testing.T) {
	content := []byte("!<arch>\ndebian-binary")
	accepted, err := agentupdate.AcceptPackage(content, "ops", written)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if !bytes.Equal(accepted.Record.GetSha256(), sum[:]) || accepted.Record.GetSize() != uint64(len(content)) || accepted.Record.GetPublishedBy() != "ops" {
		t.Fatalf("recorded %v", accepted.Record)
	}
	if _, err := agentupdate.AcceptPackage(nil, "ops", written); !errors.Is(err, agentupdate.ErrMalformed) {
		t.Fatalf("an empty package was kept: %v", err)
	}
	if _, err := agentupdate.AcceptPackage(content, "", written); !errors.Is(err, agentupdate.ErrNoActor) {
		t.Fatalf("a package nobody gave was kept: %v", err)
	}
}

func TestAnAssignmentNamesAgentsOfOneTenantAndAVersion(t *testing.T) {
	many := make([]string, agentupdate.MaxAssignedAgents+1)
	for index := range many {
		many[index] = fmt.Sprintf("web-%05d", index)
	}
	for name, asked := range map[string]*updatev1.Assignment{
		"no tenant":            {AgentIds: []string{"web-01"}, Version: "v0.2.0"},
		"no agent":             {TenantId: "acme", Version: "v0.2.0"},
		"too many agents":      {TenantId: "acme", AgentIds: many, Version: "v0.2.0"},
		"an agent named twice": {TenantId: "acme", AgentIds: []string{"web-01", "web-01"}, Version: "v0.2.0"},
		"an unusable agent":    {TenantId: "acme", AgentIds: []string{"web 01"}, Version: "v0.2.0"},
		"no version at all":    {TenantId: "acme", AgentIds: []string{"web-01"}, Version: "0.2.0"},
		"a long note":          {TenantId: "acme", AgentIds: []string{"web-01"}, Version: "v0.2.0", Note: strings.Repeat("n", 513)},
	} {
		if _, err := agentupdate.AcceptAssignment(asked, "ops", written); !errors.Is(err, agentupdate.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}

	accepted, err := agentupdate.AcceptAssignment(&updatev1.Assignment{TenantId: "acme", AgentIds: []string{"web-01", "web-02"}, Version: "v0.2.0"}, "ops", written)
	if err != nil || accepted.Record.GetAgents() != 2 || accepted.Version != "v0.2.0" || accepted.Record.GetAssignedBy() != "ops" {
		t.Fatalf("assigned %v: %v", accepted.Record, err)
	}
	withdrawn, err := agentupdate.AcceptAssignment(&updatev1.Assignment{TenantId: "acme", AgentIds: []string{"web-01"}}, "ops", written)
	if err != nil || withdrawn.Version != "" {
		t.Fatalf("a withdrawal was refused: %v", err)
	}
	if _, err := agentupdate.AcceptAssignment(&updatev1.Assignment{TenantId: "acme", AgentIds: []string{"web-01"}}, "", written); !errors.Is(err, agentupdate.ErrNoActor) {
		t.Fatalf("an assignment nobody made was taken: %v", err)
	}
}

func TestAnOfferCarriesTheNewestRootsTheCatalogAndTheVersionByteForByte(t *testing.T) {
	var roots [][]byte
	for index := range agentupdate.MaxRoots + 6 {
		roots = append(roots, encoded(t, &updatev1.Envelope{Payload: []byte{byte(index)}, PayloadType: agentupdate.RootPayloadType}))
	}
	catalog := encoded(t, &updatev1.Envelope{Payload: []byte("catalog"), PayloadType: agentupdate.CatalogPayloadType})

	served, err := agentupdate.Served{State: agent.Active, Roots: roots, Catalog: catalog, Version: "v0.2.0"}.Offer()
	if err != nil {
		t.Fatal(err)
	}
	var offer updatev1.Offer
	if err := proto.Unmarshal(served, &offer); err != nil {
		t.Fatal(err)
	}
	if len(offer.GetRoots()) != agentupdate.MaxRoots || offer.GetVersion() != "v0.2.0" {
		t.Fatalf("offered %d roots and version %s", len(offer.GetRoots()), offer.GetVersion())
	}
	for index, root := range offer.GetRoots() {
		if !bytes.Equal(encoded(t, root), roots[len(roots)-agentupdate.MaxRoots+index]) {
			t.Fatalf("root %d was not served as it was kept", index)
		}
	}
	if !bytes.Equal(encoded(t, offer.GetCatalog()), catalog) {
		t.Fatal("the catalog was not served as it was kept")
	}

	none, err := agentupdate.Served{State: agent.Active, Roots: roots[:1]}.Offer()
	if err != nil {
		t.Fatal(err)
	}
	var empty updatev1.Offer
	if err := proto.Unmarshal(none, &empty); err != nil || empty.GetCatalog() != nil || empty.GetVersion() != "" {
		t.Fatalf("an offer without a catalog: %v", err)
	}
}

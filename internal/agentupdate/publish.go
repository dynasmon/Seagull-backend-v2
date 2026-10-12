package agentupdate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const MaxAssignedAgents = 10000

var (
	ErrNoActor      = errors.New("a publication is attributable or it does not happen")
	ErrNoPackage    = errors.New("the catalog names a package the platform was not given")
	ErrUncataloged  = errors.New("the newest catalog names no release of that version")
	ErrUnregistered = errors.New("the assignment names agents that are not registered in the tenant")
	ErrUnknown      = errors.New("the platform holds no such package for this agent")
)

type AcceptedRoot struct {
	Record *updatev1.PublishedRoot
	Root   *Root
}

// Whether the version is still the next one is decided again by the store,
// under its lock, because another root can be recorded between here and there.
func AcceptRoot(asked *updatev1.RootPublication, newest *Root, actor string, at time.Time) (AcceptedRoot, error) {
	if err := attributable(actor, asked.GetNote()); err != nil {
		return AcceptedRoot{}, err
	}
	if asked.GetRoot() == nil {
		return AcceptedRoot{}, fmt.Errorf("%w: the publication carries no root", ErrMalformed)
	}
	next, err := newest.Next(asked.GetRoot(), at)
	if err != nil {
		return AcceptedRoot{}, err
	}
	if next.Expired(at) {
		return AcceptedRoot{}, fmt.Errorf("%w: root %d ran out at %s", ErrExpired, next.Version(), next.ExpiresAt().Format(time.RFC3339))
	}
	return AcceptedRoot{
		Record: &updatev1.PublishedRoot{
			Version:      next.Version(),
			IssuedAt:     timestamppb.New(next.IssuedAt()),
			ExpiresAt:    timestamppb.New(next.ExpiresAt()),
			DigestSha256: Digest(next.Served()),
			SignedBy:     next.SignedBy(),
			PublishedBy:  actor,
			PublishedAt:  timestamppb.New(at.UTC()),
			Note:         asked.GetNote(),
		},
		Root: next,
	}, nil
}

type Package struct {
	Sha256 []byte
	Size   uint64
}

type AcceptedCatalog struct {
	Record   *updatev1.PublishedCatalog
	Catalog  *Catalog
	Packages []Package
}

// Whether the version still exceeds the newest catalog and whether every
// package it names was given is decided by the store, under its lock.
func AcceptCatalog(asked *updatev1.CatalogPublication, newest *Root, actor string, at time.Time) (AcceptedCatalog, error) {
	if err := attributable(actor, asked.GetNote()); err != nil {
		return AcceptedCatalog{}, err
	}
	switch {
	case asked.GetCatalog() == nil:
		return AcceptedCatalog{}, fmt.Errorf("%w: the publication carries no catalog", ErrMalformed)
	case newest.Expired(at):
		return AcceptedCatalog{}, fmt.Errorf("%w: root %d, the newest this platform holds, ran out at %s; publish the next root first",
			ErrExpired, newest.Version(), newest.ExpiresAt().Format(time.RFC3339))
	}
	catalog, err := newest.Catalog(asked.GetCatalog(), at)
	if err != nil {
		return AcceptedCatalog{}, err
	}
	if catalog.Expired(at) {
		return AcceptedCatalog{}, fmt.Errorf("%w: catalog %d ran out at %s", ErrExpired, catalog.Version(), catalog.ExpiresAt().Format(time.RFC3339))
	}

	var packages []Package
	for _, release := range catalog.catalog.GetReleases() {
		payload := release.GetPayload()
		index := slices.IndexFunc(packages, func(held Package) bool { return bytes.Equal(held.Sha256, payload.GetSha256()) })
		switch {
		case index < 0:
			packages = append(packages, Package{Sha256: slices.Clone(payload.GetSha256()), Size: payload.GetSize()})
		case packages[index].Size != payload.GetSize():
			return AcceptedCatalog{}, fmt.Errorf("%w: two releases name one package with two sizes", ErrMalformed)
		}
	}
	return AcceptedCatalog{
		Record: &updatev1.PublishedCatalog{
			Version:      catalog.Version(),
			IssuedAt:     timestamppb.New(catalog.IssuedAt()),
			ExpiresAt:    timestamppb.New(catalog.ExpiresAt()),
			Releases:     uint32(len(catalog.catalog.GetReleases())),
			DigestSha256: Digest(catalog.Served()),
			SignedBy:     catalog.SignedBy(),
			PublishedBy:  actor,
			PublishedAt:  timestamppb.New(at.UTC()),
			Note:         asked.GetNote(),
		},
		Catalog:  catalog,
		Packages: packages,
	}, nil
}

type AcceptedPackage struct {
	Record  *updatev1.PublishedPackage
	Content []byte
}

// A package is kept by its digest and trusted for nothing: an agent checks it
// against a catalog a role signed before anything installs it.
func AcceptPackage(content []byte, actor string, at time.Time) (AcceptedPackage, error) {
	switch {
	case actor == "":
		return AcceptedPackage{}, ErrNoActor
	case len(content) == 0 || len(content) > MaxPackageBytes:
		return AcceptedPackage{}, fmt.Errorf("%w: a package holds between 1 and %d bytes, and this one holds %d",
			ErrMalformed, MaxPackageBytes, len(content))
	}
	sum := sha256.Sum256(content)
	return AcceptedPackage{
		Record: &updatev1.PublishedPackage{
			Sha256:      sum[:],
			Size:        uint64(len(content)),
			PublishedBy: actor,
			PublishedAt: timestamppb.New(at.UTC()),
		},
		Content: content,
	}, nil
}

type AcceptedAssignment struct {
	TenantID string
	AgentIDs []string
	Version  string
	Record   *updatev1.Assigned
}

// Whether the newest catalog names the version and every agent is registered
// in the tenant is decided by the store, inside the transaction that records it.
func AcceptAssignment(asked *updatev1.Assignment, actor string, at time.Time) (AcceptedAssignment, error) {
	if err := attributable(actor, asked.GetNote()); err != nil {
		return AcceptedAssignment{}, err
	}
	tenant, agents := asked.GetTenantId(), asked.GetAgentIds()
	switch {
	case tenant == "" || len(tenant) > event.MaxTenantIDLength || !event.ValidIdentifier(tenant):
		return AcceptedAssignment{}, fmt.Errorf("%w: %s is not a usable tenant identifier", ErrMalformed, strconv.Quote(bounded(tenant)))
	case len(agents) == 0 || len(agents) > MaxAssignedAgents:
		return AcceptedAssignment{}, fmt.Errorf("%w: an assignment names between 1 and %d agents, and this one names %d",
			ErrMalformed, MaxAssignedAgents, len(agents))
	}
	if version := asked.GetVersion(); version != "" {
		if _, valid := ParseVersion(version); !valid {
			return AcceptedAssignment{}, fmt.Errorf("%w: %s is not a semantic version with a leading v", ErrMalformed, strconv.Quote(bounded(version)))
		}
	}
	seen := make(map[string]bool, len(agents))
	for _, id := range agents {
		switch {
		case len(id) > event.MaxAgentIDLength || !event.ValidIdentifier(id):
			return AcceptedAssignment{}, fmt.Errorf("%w: %s is not a usable agent identifier", ErrMalformed, strconv.Quote(bounded(id)))
		case seen[id]:
			return AcceptedAssignment{}, fmt.Errorf("%w: agent %s is named twice", ErrMalformed, id)
		}
		seen[id] = true
	}
	return AcceptedAssignment{
		TenantID: tenant,
		AgentIDs: slices.Clone(agents),
		Version:  asked.GetVersion(),
		Record: &updatev1.Assigned{
			TenantId:   tenant,
			Version:    asked.GetVersion(),
			Agents:     uint32(len(agents)),
			AssignedBy: actor,
			AssignedAt: timestamppb.New(at.UTC()),
			Note:       asked.GetNote(),
		},
	}, nil
}

func attributable(actor, note string) error {
	switch {
	case actor == "":
		return ErrNoActor
	case len(note) > MaxNoteLength:
		return fmt.Errorf("%w: the note is longer than %d bytes", ErrMalformed, MaxNoteLength)
	}
	return nil
}

// What an agent is handed when it asks whether to update: the roots oldest
// first, the newest catalog, and the version the platform wants it to run, with
// whether the platform still listens to the agent asking.
type Served struct {
	State   agent.State
	Roots   [][]byte
	Catalog []byte
	Version string
}

// A package an agent asked for, and whether the platform still listens to the
// agent. Content is left unread while it does not.
type ServedPackage struct {
	State   agent.State
	Content []byte
}

func (s Served) Offer() ([]byte, error) {
	roots := s.Roots
	if len(roots) > MaxRoots {
		roots = roots[len(roots)-MaxRoots:]
	}
	offer := &updatev1.Offer{Version: s.Version}
	for _, served := range roots {
		envelope, err := decode(served)
		if err != nil {
			return nil, err
		}
		offer.Roots = append(offer.Roots, envelope)
	}
	if len(s.Catalog) > 0 {
		envelope, err := decode(s.Catalog)
		if err != nil {
			return nil, err
		}
		offer.Catalog = envelope
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("encode the offer: %w", err)
	}
	return encoded, nil
}

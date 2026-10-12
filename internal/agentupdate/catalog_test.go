package agentupdate_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func releaseOf(version string, content byte) *updatev1.Release {
	return &updatev1.Release{
		Version: version,
		Platform: &updatev1.Platform{
			Os:           "linux",
			Architecture: "amd64",
			Format:       updatev1.Format_FORMAT_DEB,
		},
		Payload: &updatev1.Payload{Sha256: bytes.Repeat([]byte{content}, 32), Size: 8 << 20},
		Source: &updatev1.Source{
			Repository: "github.com/dynasmon/Seagull-agent-v2",
			Revision:   strings.Repeat("ab", 20),
		},
		Compatibility: &updatev1.Compatibility{StateGeneration: 1},
	}
}

func catalogOf(version uint64, releases ...*updatev1.Release) *updatev1.Catalog {
	return &updatev1.Catalog{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(written),
		ExpiresAt:     timestamppb.New(written.Add(90 * 24 * time.Hour)),
		Releases:      releases,
	}
}

func TestACatalogIsTakenOnlyUnderTheCatalogRoleOfTheRoot(t *testing.T) {
	owner, publisher := newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{publisher}, 1), owner)
	catalog := catalogOf(1, releaseOf("v0.2.0", 1))

	taken, err := trusted.Catalog(sign(t, catalog, agentupdate.CatalogPayloadType, publisher), written)
	if err != nil {
		t.Fatalf("a catalog the catalog role signed was refused: %v", err)
	}
	if taken.Version() != 1 || len(taken.SignedBy()) != 1 || taken.SignedBy()[0] != publisher.id || !taken.Names("v0.2.0") || taken.Names("v0.3.0") {
		t.Fatalf("took catalog %d signed by %v", taken.Version(), taken.SignedBy())
	}
	if _, err := trusted.Catalog(sign(t, catalog, agentupdate.CatalogPayloadType, owner), written); !errors.Is(err, agentupdate.ErrUnsigned) {
		t.Fatalf("a catalog a root key signed was taken: %v", err)
	}
	if _, err := trusted.Catalog(sign(t, catalog, agentupdate.RootPayloadType, publisher), written); !errors.Is(err, agentupdate.ErrMalformed) {
		t.Fatalf("a catalog signed as a root was taken: %v", err)
	}
}

func TestAKeyTheNextRootDropsSignsNoCatalogUnderIt(t *testing.T) {
	owner, revoked, replacement := newSigner(t), newSigner(t), newSigner(t)
	first := anchored(t, rootOf(1, []signer{owner}, 1, []signer{revoked}, 1), owner)
	second, err := first.Next(sign(t, rootOf(2, []signer{owner}, 1, []signer{replacement}, 1), agentupdate.RootPayloadType, owner), written)
	if err != nil {
		t.Fatal(err)
	}
	signed := sign(t, catalogOf(4, releaseOf("v0.2.0", 1)), agentupdate.CatalogPayloadType, revoked)

	if _, err := first.Catalog(signed, written); err != nil {
		t.Fatalf("the catalog was refused under the root that trusted its key: %v", err)
	}
	if _, err := second.Catalog(signed, written); !errors.Is(err, agentupdate.ErrUnsigned) {
		t.Fatalf("a key the next root dropped still signed a catalog: %v", err)
	}
}

func TestAnEmptyCatalogAuthorizesNothingAndIsTaken(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	taken, err := trusted.Catalog(sign(t, catalogOf(2), agentupdate.CatalogPayloadType, owner), written)
	if err != nil || len(taken.Releases()) != 0 {
		t.Fatalf("an empty catalog: %v", err)
	}
}

func TestACatalogMustStateEveryReleaseWithinItsBounds(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)

	for name, change := range map[string]func(*updatev1.Catalog){
		"another schema":                 func(c *updatev1.Catalog) { c.SchemaVersion = 2 },
		"version zero":                   func(c *updatev1.Catalog) { c.Version = 0 },
		"issued ahead of the clock":      func(c *updatev1.Catalog) { c.IssuedAt = timestamppb.New(written.Add(6 * time.Minute)) },
		"vouched for more than 366 days": func(c *updatev1.Catalog) { c.ExpiresAt = timestamppb.New(written.Add(367 * 24 * time.Hour)) },
		"no expiry":                      func(c *updatev1.Catalog) { c.ExpiresAt = nil },
		"one release twice":              func(c *updatev1.Catalog) { c.Releases = append(c.Releases, releaseOf("v0.2.0", 2)) },
		"more releases than a catalog names": func(c *updatev1.Catalog) {
			for index := range agentupdate.MaxReleases {
				c.Releases = append(c.Releases, releaseOf(fmt.Sprintf("v1.0.%d", index), 3))
			}
		},
		"a version without its v":      func(c *updatev1.Catalog) { c.Releases[0].Version = "0.2.0" },
		"an operating system Go lacks": func(c *updatev1.Catalog) { c.Releases[0].Platform.Os = "Linux" },
		"no architecture":              func(c *updatev1.Catalog) { c.Releases[0].Platform.Architecture = "" },
		"no format":                    func(c *updatev1.Catalog) { c.Releases[0].Platform.Format = updatev1.Format_FORMAT_UNSPECIFIED },
		"a format the contract lacks":  func(c *updatev1.Catalog) { c.Releases[0].Platform.Format = 9 },
		"a digest that is no SHA-256":  func(c *updatev1.Catalog) { c.Releases[0].Payload.Sha256 = c.Releases[0].Payload.Sha256[:31] },
		"an empty package":             func(c *updatev1.Catalog) { c.Releases[0].Payload.Size = 0 },
		"a package beyond the ceiling": func(c *updatev1.Catalog) { c.Releases[0].Payload.Size = agentupdate.MaxPackageBytes + 1 },
		"no repository":                func(c *updatev1.Catalog) { c.Releases[0].Source.Repository = "" },
		"a revision in capitals":       func(c *updatev1.Catalog) { c.Releases[0].Source.Revision = strings.Repeat("AB", 20) },
		"a revision of 39 characters":  func(c *updatev1.Catalog) { c.Releases[0].Source.Revision = strings.Repeat("a", 39) },
		"no state generation":          func(c *updatev1.Catalog) { c.Releases[0].Compatibility.StateGeneration = 0 },
		"a minimum that is no version": func(c *updatev1.Catalog) { c.Releases[0].Compatibility.MinimumVersion = "latest" },
		"a minimum later than itself":  func(c *updatev1.Catalog) { c.Releases[0].Compatibility.MinimumVersion = "v0.3.0" },
		"replacing an earlier release": func(c *updatev1.Catalog) { c.Releases[0].Replaces = []string{"v0.1.0"} },
		"replacing itself":             func(c *updatev1.Catalog) { c.Releases[0].Replaces = []string{"v0.2.0"} },
		"replacing one release twice":  func(c *updatev1.Catalog) { c.Releases[0].Replaces = []string{"v0.3.0", "v0.3.0"} },
		"replacing what is no version": func(c *updatev1.Catalog) { c.Releases[0].Replaces = []string{"v0.3"} },
		"replacing more than it may name": func(c *updatev1.Catalog) {
			for index := range agentupdate.MaxReplaced + 1 {
				c.Releases[0].Replaces = append(c.Releases[0].Replaces, fmt.Sprintf("v0.3.%d", index))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			catalog := catalogOf(1, releaseOf("v0.2.0", 1))
			change(catalog)
			if _, err := trusted.Catalog(sign(t, catalog, agentupdate.CatalogPayloadType, owner), written); !errors.Is(err, agentupdate.ErrMalformed) {
				t.Fatalf("taken: %v", err)
			}
		})
	}
}

func TestARecoveryReleaseNamesTheLaterVersionsItReplaces(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	recovery := releaseOf("v0.2.1", 1)
	recovery.Replaces = []string{"v0.3.0", "v0.3.0-rc.1"}
	recovery.Compatibility.MinimumVersion = "v0.2.0"

	if _, err := trusted.Catalog(sign(t, catalogOf(1, recovery, releaseOf("v0.3.0", 2)), agentupdate.CatalogPayloadType, owner), written); err != nil {
		t.Fatalf("a recovery release was refused: %v", err)
	}
}

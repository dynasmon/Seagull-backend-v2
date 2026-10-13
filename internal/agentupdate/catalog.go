package agentupdate

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// A catalog the catalog role of a trusted root signed, with the envelope it is
// served as.
type Catalog struct {
	catalog  *updatev1.Catalog
	served   []byte
	signedBy []string
}

func (c *Catalog) Version() uint64 { return c.catalog.GetVersion() }

func (c *Catalog) IssuedAt() time.Time { return c.catalog.GetIssuedAt().AsTime() }

func (c *Catalog) ExpiresAt() time.Time { return c.catalog.GetExpiresAt().AsTime() }

func (c *Catalog) Expired(at time.Time) bool { return !at.Before(c.ExpiresAt()) }

func (c *Catalog) Served() []byte { return c.served }

func (c *Catalog) SignedBy() []string { return slices.Clone(c.signedBy) }

func (c *Catalog) Releases() []*updatev1.Release {
	releases := make([]*updatev1.Release, 0, len(c.catalog.GetReleases()))
	for _, release := range c.catalog.GetReleases() {
		cloned, _ := proto.Clone(release).(*updatev1.Release)
		releases = append(releases, cloned)
	}
	return releases
}

func (c *Catalog) Names(version string) bool {
	return slices.ContainsFunc(c.catalog.GetReleases(), func(release *updatev1.Release) bool {
		return release.GetVersion() == version
	})
}

// A catalog is checked under the catalog role of this root before any of it is
// decoded.
func (r *Root) Catalog(envelope *updatev1.Envelope, now time.Time) (*Catalog, error) {
	signed, err := signedBy(r.keys, r.root.GetCatalog(), CatalogPayloadType, envelope)
	if err != nil {
		return nil, fmt.Errorf("the catalog keys of root %d did not sign it: %w", r.Version(), err)
	}
	var catalog updatev1.Catalog
	if err := proto.Unmarshal(envelope.GetPayload(), &catalog); err != nil {
		return nil, fmt.Errorf("%w: its payload is not a catalog", ErrMalformed)
	}
	if err := known(catalog.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := validateCatalog(&catalog, now); err != nil {
		return nil, err
	}
	encoded, err := Encode(envelope)
	if err != nil {
		return nil, err
	}
	return &Catalog{catalog: &catalog, served: encoded, signedBy: signed}, nil
}

func validateCatalog(catalog *updatev1.Catalog, now time.Time) error {
	switch {
	case catalog.GetSchemaVersion() != SchemaVersion:
		return fmt.Errorf("%w: the catalog is written to schema %d, and this platform reads %d",
			ErrMalformed, catalog.GetSchemaVersion(), SchemaVersion)
	case catalog.GetVersion() == 0 || catalog.GetVersion() > MaxVersion:
		return fmt.Errorf("%w: a catalog is counted from version 1 to %d", ErrMalformed, uint64(MaxVersion))
	case len(catalog.GetReleases()) > MaxReleases:
		return fmt.Errorf("%w: a catalog names at most %d releases, and this one names %d",
			ErrMalformed, MaxReleases, len(catalog.GetReleases()))
	}
	if err := lifetime("the catalog", catalog.GetIssuedAt(), catalog.GetExpiresAt(), now); err != nil {
		return err
	}
	seen := make(map[string]bool, len(catalog.GetReleases()))
	for _, release := range catalog.GetReleases() {
		if err := validateRelease(release); err != nil {
			return err
		}
		platform := release.GetPlatform()
		named := release.GetVersion() + " for " + platform.GetOs() + "/" + platform.GetArchitecture() + " " + platform.GetFormat().String()
		if seen[named] {
			return fmt.Errorf("%w: the catalog names %s twice", ErrMalformed, named)
		}
		seen[named] = true
	}
	return nil
}

func validateRelease(release *updatev1.Release) error {
	version, valid := ParseVersion(release.GetVersion())
	if !valid {
		return fmt.Errorf("%w: release %s is not a semantic version with a leading v of at most %d bytes",
			ErrMalformed, strconv.Quote(bounded(release.GetVersion())), MaxVersionLength)
	}
	failed := func(reason string, arguments ...any) error {
		return fmt.Errorf("%w: release %s %s", ErrMalformed, version, fmt.Sprintf(reason, arguments...))
	}

	platform := release.GetPlatform()
	switch {
	case !platformName(platform.GetOs()) || !platformName(platform.GetArchitecture()):
		return failed("does not name an operating system and an architecture as Go names them")
	case platform.GetFormat() == updatev1.Format_FORMAT_UNSPECIFIED:
		return failed("does not say how it is packaged")
	case updatev1.Format_name[int32(platform.GetFormat())] == "":
		return failed("is packaged in a format the contract does not declare")
	}

	payload := release.GetPayload()
	switch {
	case len(payload.GetSha256()) != 32:
		return failed("does not carry the SHA-256 of its package")
	case payload.GetSize() == 0 || payload.GetSize() > MaxPackageBytes:
		return failed("says its package holds %d bytes, and a package holds between 1 and %d", payload.GetSize(), MaxPackageBytes)
	}

	source := release.GetSource()
	switch {
	case source.GetRepository() == "" || len(source.GetRepository()) > MaxRepositoryLength:
		return failed("does not name the repository it was built from in at most %d bytes", MaxRepositoryLength)
	case !revision(source.GetRevision()):
		return failed("does not name the revision it was built from as 40 or 64 lowercase hex characters")
	}

	compatibility := release.GetCompatibility()
	if compatibility.GetStateGeneration() == 0 {
		return failed("does not say which generation of local state it keeps")
	}
	if minimum := compatibility.GetMinimumVersion(); minimum != "" {
		oldest, valid := ParseVersion(minimum)
		switch {
		case !valid:
			return failed("names a minimum version that is not a semantic version")
		case oldest.Compare(version) > 0:
			return failed("may only be installed over %s, which is later than itself", minimum)
		}
	}

	replaced := release.GetReplaces()
	if len(replaced) > MaxReplaced {
		return failed("replaces %d versions, and a release replaces at most %d", len(replaced), MaxReplaced)
	}
	for index, named := range replaced {
		later, valid := ParseVersion(named)
		switch {
		case !valid:
			return failed("replaces %s, which is not a semantic version", strconv.Quote(bounded(named)))
		case later.Compare(version) <= 0:
			return failed("replaces %s, which is not later than itself", named)
		case slices.Contains(replaced[:index], named):
			return failed("replaces %s twice", named)
		}
	}
	return nil
}

func platformName(name string) bool {
	return name != "" && len(name) <= MaxPlatformLength && strings.TrimLeft(name, "abcdefghijklmnopqrstuvwxyz0123456789") == ""
}

func revision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

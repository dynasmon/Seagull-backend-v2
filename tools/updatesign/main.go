package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const maxDocumentBytes = 2 << 20

type list []string

func (l *list) String() string { return strings.Join(*l, ",") }

func (l *list) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: updatesign root|catalog [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "root":
		err = signRoot(os.Args[2:], time.Now())
	case "catalog":
		err = signCatalog(os.Args[2:], time.Now())
	default:
		fmt.Fprintln(os.Stderr, "usage: updatesign root|catalog [flags]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "updatesign:", err)
		os.Exit(1)
	}
}

// A root named by its keys and thresholds, signed by the keys that vouch for
// it, and checked against the root before it so a rotation the chain would
// refuse is never written.
func signRoot(arguments []string, now time.Time) error {
	flags := flag.NewFlagSet("updatesign root", flag.ContinueOnError)
	var signing, rootKeys, catalogKeys list
	flags.Var(&signing, "key", "a PEM private key, ECDSA over P-256, to sign with; a rotation is signed by a threshold of the previous root's root keys and of its own")
	flags.Var(&rootKeys, "root-key", "a PEM public key the root role names; repeat it")
	flags.Var(&catalogKeys, "catalog-key", "a PEM public key the catalog role names; repeat it")
	version := flags.Uint64("version", 0, "1 for the first root, one more than the root it replaces otherwise")
	rootThreshold := flags.Uint("root-threshold", 1, "how many root keys must sign the next root")
	catalogThreshold := flags.Uint("catalog-threshold", 1, "how many catalog keys must sign a catalog")
	lifetime := flags.Duration("lifetime", 365*24*time.Hour, "how long the root is vouched for, at most 366 days")
	previous := flags.String("previous", "", "the root this one replaces, as the signed envelope; required past version 1")
	note := flags.String("note", "", "why the root is published, kept with what the platform records")
	output := flags.String("output", "", "where the publication is written, ready to POST to /v1/agents/update/roots")
	bare := flags.String("envelope", "", "where the signed root alone is written, which is what a control plane and every agent are provisioned with")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	switch {
	case len(signing) == 0:
		return errors.New("-key names a private key to sign with")
	case len(rootKeys) == 0 || len(catalogKeys) == 0:
		return errors.New("-root-key and -catalog-key name the keys of each role")
	case *version == 0:
		return errors.New("-version is the root's version, counted from 1")
	case *version > 1 && *previous == "":
		return errors.New("-previous names the root this one replaces")
	case *output == "" && *bare == "":
		return errors.New("-output or -envelope names where the root is written")
	}

	root := &updatev1.Root{
		SchemaVersion: agentupdate.SchemaVersion,
		Version:       *version,
		IssuedAt:      timestamppb.New(now.UTC().Truncate(time.Second)),
		Root:          &updatev1.Role{Threshold: uint32(*rootThreshold)},
		Catalog:       &updatev1.Role{Threshold: uint32(*catalogThreshold)},
	}
	root.ExpiresAt = timestamppb.New(root.GetIssuedAt().AsTime().Add(*lifetime))
	for _, role := range []struct {
		paths []string
		named *updatev1.Role
	}{{rootKeys, root.Root}, {catalogKeys, root.Catalog}} {
		for _, path := range role.paths {
			der, err := publicKey(path)
			if err != nil {
				return err
			}
			id := agentupdate.KeyID(der)
			if !slices.ContainsFunc(root.Keys, func(key *updatev1.Key) bool { return key.GetKeyid() == id }) {
				root.Keys = append(root.Keys, &updatev1.Key{Keyid: id, PublicKey: der})
			}
			role.named.Keyids = append(role.named.Keyids, id)
		}
	}

	envelope, err := sign(root, agentupdate.RootPayloadType, signing)
	if err != nil {
		return err
	}
	encoded, err := agentupdate.Encode(envelope)
	if err != nil {
		return err
	}
	if *previous == "" {
		if _, err := agentupdate.Anchor(encoded, now); err != nil {
			return err
		}
	} else {
		before, err := readFile(*previous)
		if err != nil {
			return err
		}
		held, err := agentupdate.Anchor(before, now)
		if err != nil {
			return fmt.Errorf("%s: %w", *previous, err)
		}
		if _, err := held.Next(envelope, now); err != nil {
			return err
		}
	}

	if *bare != "" {
		if err := os.WriteFile(*bare, encoded, 0o644); err != nil {
			return err
		}
	}
	if *output != "" {
		if err := write(*output, &updatev1.RootPublication{Root: envelope, Note: *note}); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "updatesign: root %d names %d keys, expires %s, signed by %s\n",
		root.GetVersion(), len(root.GetKeys()), root.GetExpiresAt().AsTime().Format(time.RFC3339), signers(envelope))
	return nil
}

// A catalog as an operator writes it, its payloads filled in from the packages
// themselves, and checked under the newest root before it is written, since
// that is the root every agent checks it under.
func signCatalog(arguments []string, now time.Time) error {
	flags := flag.NewFlagSet("updatesign catalog", flag.ContinueOnError)
	var signing, packages list
	flags.Var(&signing, "key", "a PEM private key, ECDSA over P-256, of the catalog role; repeat it to reach the threshold")
	flags.Var(&packages, "package", "VERSION=PATH, or VERSION/OS/ARCH=PATH, the package of a release the document gives no payload for; repeat it")
	document := flags.String("catalog", "", "the catalog to sign, as the JSON form of seagull.update.v1.Catalog")
	newest := flags.String("root", "", "the newest root, as the signed envelope, that agents verify the catalog under")
	lifetime := flags.Duration("lifetime", 90*24*time.Hour, "how long the catalog is vouched for when the document gives no expires_at")
	note := flags.String("note", "", "why the catalog is published, kept with what the platform records")
	output := flags.String("output", "", "where the publication is written, ready to POST to /v1/agents/update/catalogs")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	switch {
	case len(signing) == 0:
		return errors.New("-key names a private key to sign with")
	case *document == "":
		return errors.New("-catalog names the catalog to sign")
	case *newest == "":
		return errors.New("-root names the newest root, which the catalog is checked under")
	case *output == "":
		return errors.New("-output names where the publication is written")
	}

	content, err := readFile(*document)
	if err != nil {
		return err
	}
	var catalog updatev1.Catalog
	if err := protojson.Unmarshal(content, &catalog); err != nil {
		return fmt.Errorf("%s is not a catalog: %w", *document, err)
	}
	if catalog.GetIssuedAt() == nil {
		catalog.IssuedAt = timestamppb.New(now.UTC().Truncate(time.Second))
	}
	if catalog.GetExpiresAt() == nil {
		catalog.ExpiresAt = timestamppb.New(catalog.GetIssuedAt().AsTime().Add(*lifetime))
	}
	if err := fill(&catalog, packages); err != nil {
		return err
	}

	envelope, err := sign(&catalog, agentupdate.CatalogPayloadType, signing)
	if err != nil {
		return err
	}
	held, err := readFile(*newest)
	if err != nil {
		return err
	}
	root, err := agentupdate.Anchor(held, now)
	if err != nil {
		return fmt.Errorf("%s: %w", *newest, err)
	}
	if _, err := root.Catalog(envelope, now); err != nil {
		return err
	}
	if err := write(*output, &updatev1.CatalogPublication{Catalog: envelope, Note: *note}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "updatesign: catalog %d names %d releases, expires %s, signed by %s\n",
		catalog.GetVersion(), len(catalog.GetReleases()), catalog.GetExpiresAt().AsTime().Format(time.RFC3339), signers(envelope))
	return nil
}

// Every package names exactly one release that carries no payload yet, and every
// such release is named by exactly one package.
func fill(catalog *updatev1.Catalog, packages []string) error {
	for _, given := range packages {
		named, path, found := strings.Cut(given, "=")
		if !found || named == "" || path == "" {
			return fmt.Errorf("-package %s is not VERSION=PATH", given)
		}
		version, platform, _ := strings.Cut(named, "/")
		var matched []*updatev1.Release
		for _, release := range catalog.GetReleases() {
			at := release.GetPlatform().GetOs() + "/" + release.GetPlatform().GetArchitecture()
			if release.GetPayload() == nil && release.GetVersion() == version && (platform == "" || platform == at) {
				matched = append(matched, release)
			}
		}
		if len(matched) != 1 {
			return fmt.Errorf("-package %s names %d releases without a payload, and it must name one", named, len(matched))
		}
		content, err := readPackage(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		matched[0].Payload = &updatev1.Payload{Sha256: sum[:], Size: uint64(len(content))}
		fmt.Fprintf(os.Stderr, "updatesign: %s is %s, %d bytes\n", path, hex.EncodeToString(sum[:]), len(content))
	}
	for _, release := range catalog.GetReleases() {
		if release.GetPayload() == nil {
			return fmt.Errorf("release %s carries no payload and no -package names it", release.GetVersion())
		}
	}
	return nil
}

func sign(message proto.Message, payloadType string, paths []string) (*updatev1.Envelope, error) {
	keys := make([]crypto.Signer, 0, len(paths))
	for _, path := range paths {
		key, err := privateKey(path)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return agentupdate.Sign(message, payloadType, keys...)
}

func signers(envelope *updatev1.Envelope) string {
	ids := make([]string, 0, len(envelope.GetSignatures()))
	for _, signature := range envelope.GetSignatures() {
		ids = append(ids, signature.GetKeyid())
	}
	return strings.Join(ids, ", ")
}

func write(path string, message proto.Message) error {
	encoded, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode the publication: %w", err)
	}
	return os.WriteFile(path, encoded, 0o644)
}

func readFile(path string) ([]byte, error) {
	return readWithin(path, maxDocumentBytes)
}

func readPackage(path string) ([]byte, error) {
	return readWithin(path, agentupdate.MaxPackageBytes)
}

func readWithin(path string, ceiling int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, ceiling+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > ceiling {
		return nil, fmt.Errorf("%s is longer than %d bytes", path, ceiling)
	}
	return content, nil
}

func publicKey(path string) ([]byte, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s holds no PEM PUBLIC KEY", path)
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return block.Bytes, nil
}

func privateKey(path string) (*ecdsa.PrivateKey, error) {
	content, err := readFile(path)
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
		return nil, fmt.Errorf("%s holds a %s block, and metadata is signed with a private key", path, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ecdsaKey := parsed.(*ecdsa.PrivateKey)
	if !ecdsaKey {
		return nil, fmt.Errorf("%s is not an ECDSA key, and metadata is signed with ECDSA over P-256", path)
	}
	return key, nil
}

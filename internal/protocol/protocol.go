package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

const (
	Version    = 1
	MinVersion = 1
	MaxVersion = 1
)

// The names the contract gives what a listener offers an agent beside the
// streams it admits.
const (
	CapabilityRenewal = "renewal"
	CapabilityPolicy  = "policy"
	CapabilityUpdate  = "update"
)

func Supported(version uint32) bool {
	return version >= MinVersion && version <= MaxVersion
}

func Descriptor(now time.Time) *platformv1.Descriptor {
	return &platformv1.Descriptor{
		ProtocolVersion:    Version,
		SupportedProtocol:  &platformv1.VersionRange{Minimum: MinVersion, Maximum: MaxVersion},
		EventSchemaVersion: event.SchemaVersion,
		SupportedEventSchema: &platformv1.VersionRange{
			Minimum: event.MinSchemaVersion,
			Maximum: event.MaxSchemaVersion,
		},
		ServerTime: timestamppb.New(now.UTC()),
	}
}

// A descriptor is named by what it describes and never by when it was asked
// for, so an agent holding one is told nothing changed until something did.
func Tag(described *platformv1.Descriptor) (string, error) {
	timeless := proto.CloneOf(described)
	timeless.ServerTime = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(timeless)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

func Answer(described *platformv1.Descriptor, now time.Time) ([]byte, error) {
	answered := proto.CloneOf(described)
	answered.ServerTime = timestamppb.New(now.UTC())
	return proto.Marshal(answered)
}

package protocol

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
	"github.com/dynasmon/Seagull-v2/internal/event"
)

const (
	Version    = 1
	MinVersion = 1
	MaxVersion = 1
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

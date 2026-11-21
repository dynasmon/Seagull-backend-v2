package listening

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

const (
	SchemaVersion    = 1
	MaxGatewayLength = 64
	MinEvery         = time.Second
	MaxEvery         = time.Minute

	// A gateway still counts as serving until this many of its intervals have
	// passed with no beacon from it, so one beacon lost on the way is not an
	// outage.
	Missed = 3
)

func Beacon(gateway string, at time.Time, every time.Duration, admitting bool) *platformv1.GatewayBeacon {
	return &platformv1.GatewayBeacon{
		SchemaVersion: SchemaVersion,
		Gateway:       gateway,
		At:            timestamppb.New(at.UTC()),
		Every:         durationpb.New(every),
		Admitting:     admitting,
	}
}

func Validate(beacon *platformv1.GatewayBeacon) error {
	switch {
	case beacon == nil:
		return &event.Violation{Field: "beacon", Reason: "is missing"}
	case beacon.GetSchemaVersion() != SchemaVersion:
		return &event.Violation{Field: "schema_version", Reason: fmt.Sprintf("must be %d", SchemaVersion)}
	case beacon.GetGateway() == "" || len(beacon.GetGateway()) > MaxGatewayLength:
		return &event.Violation{Field: "gateway", Reason: fmt.Sprintf("must name the gateway in 1 to %d bytes", MaxGatewayLength)}
	case !beacon.GetAt().IsValid():
		return &event.Violation{Field: "at", Reason: "is missing or not a representable instant"}
	case !beacon.GetEvery().IsValid() || beacon.GetEvery().AsDuration() < MinEvery || beacon.GetEvery().AsDuration() > MaxEvery:
		return &event.Violation{Field: "every", Reason: fmt.Sprintf("must be between %s and %s", MinEvery, MaxEvery)}
	}
	return nil
}

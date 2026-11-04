package ingest

import (
	"math"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const latestSecond = 253402300799

// The most the gateway's stamp adds to a record: what it adds to one that
// carried no origin and no reception, at the longest names the contract allows.
// One that carried either grows by no more, since a reception is replaced whole
// and an origin gains only the two identifiers.
func stamping[R proto.Message](empty R, stamp func(R, agentidentity.Identity, string, *eventv1.Reception)) int {
	stamp(empty, agentidentity.Identity{AgentID: strings.Repeat("a", event.MaxAgentIDLength)}, strings.Repeat("t", event.MaxTenantIDLength),
		&eventv1.Reception{
			IngestTime: &timestamppb.Timestamp{Seconds: latestSecond, Nanos: 999_999_999},
			Gateway:    strings.Repeat("g", event.MaxGatewayLength),
			BatchId:    strings.Repeat("b", event.MaxBatchIDLength),
		})
	return proto.Size(empty)
}

func sendable(ceiling, stamped int) uint64 {
	return uint64(max(ceiling-stamped, 0))
}

func count(value int) uint32 {
	return uint32(min(max(value, 0), math.MaxUint32))
}

func fullName(message proto.Message) string {
	return string(message.ProtoReflect().Descriptor().FullName())
}

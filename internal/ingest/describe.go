package ingest

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

const (
	DescriptorPath  = "/v1/descriptor"
	DescriptorRoute = "GET " + DescriptorPath
)

const latestSecond = 253402300799

// What the gateway admits, told before anything is sent: the streams it routes,
// each described by the admitter that judges its batches, so a limit can only
// be described as it is enforced. It stands behind the same certificate,
// registry and limiter as the streams, and decides nothing they decide.
type describer struct {
	roster    Roster
	limiter   *ratelimit.Limiter
	described *platformv1.Descriptor
	tag       string
	now       func() time.Time
}

func newDescriber(served []*Handler) (*describer, error) {
	if len(served) == 0 {
		return nil, errors.New("the descriptor describes the streams a gateway routes, and it routes none")
	}
	described := protocol.Descriptor(time.Time{})
	described.ServerTime = nil
	ceiling := served[0].maxBodyBytes
	for _, handler := range served {
		described.Streams = append(described.Streams, handler.stream.describe())
		ceiling = min(ceiling, handler.maxBodyBytes)
	}
	described.MaxBodyBytes = uint64(max(ceiling, 0))
	tag, err := protocol.Tag(described)
	if err != nil {
		return nil, err
	}
	return &describer{roster: served[0].roster, limiter: served[0].limiter, described: described, tag: tag, now: time.Now}, nil
}

func (d *describer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identity, err := agentidentity.FromConnection(r.TLS)
	if err != nil {
		refuse(w, http.StatusForbidden, "unauthenticated_agent", err.Error(), "", -1)
		return
	}
	if _, admitted := d.roster.Tenant(identity.AgentID); !admitted {
		code, detail := unadmitted(d.roster, identity.AgentID)
		refuse(w, http.StatusForbidden, code, detail, "", -1)
		return
	}
	if !d.limiter.Allow(identity.AgentID) {
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusTooManyRequests, "rate_limited", "the agent is asking faster than this gateway answers", "", -1)
		return
	}

	w.Header().Set("ETag", d.tag)
	w.Header().Set("Cache-Control", "no-cache")
	if httpx.Unchanged(r, d.tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	encoded, err := protocol.Answer(d.described, d.now())
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

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

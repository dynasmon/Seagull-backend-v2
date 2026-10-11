package agentpolicy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const MaxNoteLength = 512

var (
	ErrNoActor      = errors.New("a publication is attributable or it does not happen")
	ErrStale        = errors.New("the tenant already holds a revision at least as high")
	ErrUnregistered = errors.New("the policy names agents that are not registered in the tenant")
	ErrUnknown      = errors.New("no policy was published under that revision, or it is outside this caller's tenants")
	ErrCursor       = errors.New("the cursor was not issued for this listing")
)

// A publication the platform verified and validated, ready to be recorded: what
// it will answer about the policy, the bytes it will serve and the agents the
// policy names. Whether the revision is still the highest of its tenant and
// whether every agent is registered there is decided by the store, under the
// tenant's lock, because both can change between here and there.
type Accepted struct {
	Record  *policyv1.PublishedPolicy
	Served  []byte
	Targets []string
}

func Accept(asked *policyv1.Publication, signers *Signers, actor string, at time.Time) (Accepted, error) {
	tenant := asked.GetTenantId()
	switch {
	case actor == "":
		return Accepted{}, ErrNoActor
	case tenant == "" || len(tenant) > event.MaxTenantIDLength || !event.ValidIdentifier(tenant):
		return Accepted{}, fmt.Errorf("%w: %s is not a usable tenant identifier", ErrMalformed, strconv.Quote(bounded(tenant)))
	case len(asked.GetNote()) > MaxNoteLength:
		return Accepted{}, fmt.Errorf("%w: the note is longer than %d bytes", ErrMalformed, MaxNoteLength)
	case asked.GetPolicy() == nil:
		return Accepted{}, fmt.Errorf("%w: the publication carries no policy", ErrMalformed)
	}

	verified, err := signers.Verify(asked.GetPolicy())
	if err != nil {
		return Accepted{}, err
	}
	if err := Validate(verified.Policy, at); err != nil {
		return Accepted{}, err
	}
	served, err := proto.MarshalOptions{Deterministic: true}.Marshal(asked.GetPolicy())
	if err != nil {
		return Accepted{}, fmt.Errorf("%w: the envelope cannot be encoded again", ErrMalformed)
	}
	if len(served) > MaxEnvelopeBytes {
		return Accepted{}, fmt.Errorf("%w: the envelope is longer than %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}

	policy := verified.Policy
	return Accepted{
		Record: &policyv1.PublishedPolicy{
			TenantId:     tenant,
			Revision:     policy.GetRevision(),
			PolicyId:     policy.GetPolicyId(),
			IssuedAt:     policy.GetIssuedAt(),
			ExpiresAt:    policy.GetExpiresAt(),
			Targets:      uint32(len(policy.GetTargets().GetAgentIds())),
			DigestSha256: Digest(served),
			SignedBy:     verified.SignedBy,
			PublishedBy:  actor,
			PublishedAt:  timestamppb.New(at.UTC()),
			Note:         asked.GetNote(),
			Policy:       asked.GetPolicy(),
		},
		Served:  served,
		Targets: slices.Clone(policy.GetTargets().GetAgentIds()),
	}, nil
}

// What an agent is handed: the highest revision of its tenant that names it, as
// it was recorded, and whether the platform still listens to the agent asking.
// Envelope is empty when no policy names it.
type Served struct {
	State    agent.State
	Revision uint64
	Envelope []byte
	Digest   string
}

func (s Served) Named() bool { return len(s.Envelope) > 0 }

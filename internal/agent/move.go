package agent

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var (
	ErrNothingAsked = errors.New("the move asks for neither a state nor an identity")
	ErrNoActor      = errors.New("a move is attributable or it does not happen")
	ErrMoved        = errors.New("the agent moved since it was read")
	ErrNeedsReason  = errors.New("a lifecycle change is recorded with the reason for it")
	ErrUnknownState = errors.New("the move names no agent state")
)

func Refused(err error) bool {
	return errors.Is(err, ErrIllegalMove) || errors.Is(err, ErrNothingAsked) ||
		errors.Is(err, ErrNeedsReason) || errors.Is(err, ErrUnknownState) ||
		errors.Is(err, ErrNoActor) || errors.Is(err, ErrMalformedIdentity) ||
		errors.Is(err, ErrMalformed)
}

// One act on a registered agent: a state, a certificate identity, or both.
// Binding an identity is what makes a pending agent active, which is why that
// move is not in the state machine — an agent becomes active by being given
// something to authenticate with and never by being declared active.
type Move struct {
	To       State
	Identity *agentv1.Identity
	Note     string
	Actor    string
	At       time.Time

	// The revision the caller believed it was acting on. Zero acts on whatever
	// the agent currently is; anything else is refused when the agent has moved,
	// so two operators acting at once means the second is told rather than
	// losing silently to the first.
	Expected uint64
}

// Pure, so the store's only job is to make it atomic: it reads the agent, calls
// this, and writes both results in one transaction or neither.
func Apply(current *agentv1.Agent, move Move) (*agentv1.Agent, *agentv1.Transition, error) {
	from, known := FromWire(current.GetState())
	if !known {
		return nil, nil, fmt.Errorf("the stored agent is in no state this build knows: %s", current.GetState())
	}
	if move.Actor == "" {
		return nil, nil, ErrNoActor
	}
	if move.Expected != 0 && move.Expected != current.GetRevision() {
		return nil, nil, fmt.Errorf("%w: it is at revision %d and the move expected %d",
			ErrMoved, current.GetRevision(), move.Expected)
	}
	if err := within("note", move.Note, MaxNoteLength); err != nil {
		return nil, nil, err
	}

	binding := move.Identity != nil
	changing := move.To != "" && move.To != from
	switch {
	case move.To != "" && !move.To.Valid():
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownState, move.To)
	case !changing && !binding:
		return nil, nil, ErrNothingAsked
	case binding && from.Final():
		return nil, nil, fmt.Errorf("%w: an agent that is %s takes no further identity",
			ErrMalformedIdentity, from)
	case changing && !Legal(from, move.To):
		return nil, nil, Illegal(from, move.To)
	case changing && move.Note == "":
		return nil, nil, fmt.Errorf("%w: becoming %s from %s needs a reason", ErrNeedsReason, move.To, from)
	}
	if binding {
		if err := Bindable(current.GetAgentId(), move.Identity, move.At); err != nil {
			return nil, nil, err
		}
	}

	moved, _ := proto.Clone(current).(*agentv1.Agent)
	at := timestamppb.New(move.At.UTC())
	moved.Revision = current.GetRevision() + 1
	moved.ChangedBy = move.Actor
	moved.ChangedAt = at
	if binding {
		moved.Identity = move.Identity
		if from == Pending {
			moved.State = Active.Wire()
		}
	}
	if changing {
		moved.State = move.To.Wire()
	}

	return moved, &agentv1.Transition{
		AgentId:  moved.GetAgentId(),
		Revision: moved.GetRevision(),
		From:     current.GetState(),
		To:       moved.GetState(),
		Actor:    move.Actor,
		At:       at,
		Note:     move.Note,
	}, nil
}

// What the data plane is told, which is less than what was decided: the state
// and the revision it was decided at, and neither the reason nor the operator.
func Admission(moved *agentv1.Agent) *agentv1.Admission {
	return &agentv1.Admission{
		AgentId:   moved.GetAgentId(),
		TenantId:  moved.GetTenantId(),
		State:     moved.GetState(),
		Revision:  moved.GetRevision(),
		ChangedAt: moved.GetChangedAt(),
	}
}

package incident

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

var (
	ErrNothingAsked    = errors.New("the move asks for neither a state nor an assignee")
	ErrNoActor         = errors.New("a move is attributable or it does not happen")
	ErrMoved           = errors.New("the incident moved since it was read")
	ErrNeedsReason     = errors.New("this move says an earlier reading of the story was wrong and has to say why")
	ErrUnknownState    = errors.New("the move names no incident state")
	ErrUnknownIncident = errors.New("no incident was raised under that id, or it is outside this caller's tenants")
	ErrCursor          = errors.New("the cursor was not issued for this listing")
)

func Refused(err error) bool {
	return errors.Is(err, ErrIllegalMove) || errors.Is(err, ErrNothingAsked) ||
		errors.Is(err, ErrNeedsReason) || errors.Is(err, ErrUnknownState) ||
		errors.Is(err, ErrNoActor)
}

// One act on an incident. A state, an assignee, or both: handing a story to
// somebody changes nothing about triage and is still a change the trail has to
// carry, so both travel the same path and are decided the same way. `Refused`
// separates what a caller asked wrongly from what the store could not do.
type Move struct {
	To       State
	Assignee *string
	Note     string
	Actor    string
	At       time.Time

	// The revision the caller believed it was acting on. Zero acts on whatever
	// the incident currently is; anything else is refused when it has moved, so
	// two people acting at once means the second is told rather than losing
	// silently to the first.
	Expected uint64
}

func Assigning(to string) *string { return &to }

// Pure, so the store's only job is to make it atomic: it reads the incident,
// calls this, and writes both results in one transaction or neither. Nothing
// here reaches the detection or the events the story is made of — an operator
// moves the incident and the record it was read from stays as it was.
func Apply(current *incidentv1.Incident, move Move) (*incidentv1.Incident, *incidentv1.Transition, error) {
	from, known := FromWire(current.GetState())
	if !known {
		return nil, nil, fmt.Errorf("the stored incident is in no state this build knows: %s", current.GetState())
	}
	if move.Actor == "" {
		return nil, nil, ErrNoActor
	}
	if move.Expected != 0 && move.Expected != current.GetRevision() {
		return nil, nil, fmt.Errorf("%w: it is at revision %d and the move expected %d",
			ErrMoved, current.GetRevision(), move.Expected)
	}

	changing := move.To != "" && move.To != from
	reassigning := move.Assignee != nil && *move.Assignee != current.GetAssignee()
	switch {
	case move.To != "" && !move.To.Valid():
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownState, move.To)
	case !changing && !reassigning:
		return nil, nil, ErrNothingAsked
	case changing && !Legal(from, move.To):
		return nil, nil, Illegal(from, move.To)
	case changing && Explains(from, move.To) && move.Note == "":
		return nil, nil, fmt.Errorf("%w: becoming %s from %s needs a reason", ErrNeedsReason, move.To, from)
	}

	moved := clone(current)
	at := timestamppb.New(move.At.UTC())
	moved.Revision = current.GetRevision() + 1
	moved.ChangedBy = move.Actor
	moved.ChangedAt = at
	if reassigning {
		moved.Assignee = *move.Assignee
	}
	if changing {
		moved.State = move.To.Wire()
		moved.Closure = closure(move, at)
	}

	return moved, &incidentv1.Transition{
		IncidentId: moved.GetIncidentId(),
		Revision:   moved.GetRevision(),
		From:       current.GetState(),
		To:         moved.GetState(),
		Assignee:   moved.GetAssignee(),
		Actor:      move.Actor,
		At:         at,
		Note:       move.Note,
	}, nil
}

// An incident that leaves an ending carries no closure: what closed it is in
// the trail, and leaving it on the record would say the story is closed when it
// is open again.
func closure(move Move, at *timestamppb.Timestamp) *incidentv1.Closure {
	if !move.To.Closed() {
		return nil
	}
	return &incidentv1.Closure{
		State:    move.To.Wire(),
		Reason:   move.Note,
		ClosedBy: move.Actor,
		ClosedAt: at,
	}
}

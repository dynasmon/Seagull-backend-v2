package advisoryfeed

import (
	"context"
	"errors"
	"time"

	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// The feed no longer has a record its own index listed. Nothing is concluded
// from it: the advisory the platform holds, if any, stays exactly as it was.
var ErrGone = errors.New("the feed no longer has what its index listed")

// Worth asking again: the origin could not be reached or said it was busy.
// Anything else is an answer, and asking again would get the same one.
type Unavailable struct{ Err error }

func (u *Unavailable) Error() string { return "the feed is unavailable: " + u.Err.Error() }

func (u *Unavailable) Unwrap() error { return u.Err }

type Listing struct {
	ID       string
	Modified time.Time
}

type Index struct {
	Listings  []Listing
	Version   string
	Unchanged bool
	Malformed int
}

type Fetched struct {
	Body     []byte
	Location string
}

type Origin interface {
	Index(ctx context.Context, feed, known string) (Index, error)
	Record(ctx context.Context, feed, id string) (Fetched, error)
}

// What the feed's format says, translated. The translation knows the format it
// read and the rules it applied; where and when the bytes came from is the
// importer's to write.
type Translate func(raw []byte) (*vulnerabilityv1.Advisory, error)

type Log interface {
	Publish(ctx context.Context, records []*vulnerabilityv1.Record) error
}

type History interface {
	Replay(ctx context.Context, learn func(*vulnerabilityv1.Record)) error
}

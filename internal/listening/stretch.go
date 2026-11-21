package listening

import "time"

// How long the platform has been listening without a break. Any moment it was
// not ends the stretch, so a silence judged against it is one the platform could
// have heard the end of throughout.
type Stretch struct {
	since time.Time
}

func (s *Stretch) Mark(now time.Time, listening bool) {
	switch {
	case !listening:
		s.since = time.Time{}
	case s.since.IsZero():
		s.since = now
	}
}

func (s *Stretch) Lasted(now time.Time, atLeast time.Duration) bool {
	return !s.since.IsZero() && now.Sub(s.since) >= atLeast
}

func (s *Stretch) Since() time.Time { return s.since }

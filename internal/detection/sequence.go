package detection

import (
	"strings"
	"time"
)

// An ordered story a rule detects, rather than a single event.
//
// A rule carries a Sequence or a Match and never both: the stages are what it
// matches with. They are satisfied in the order they are written, in event time
// and inside one window, by events that share a group — so the match of each
// stage stays a pure function of one event, and the order is the one part
// answered from state.
type Sequence struct {
	Stages []Stage
	Within time.Duration

	// What makes two events part of the same story. The tenant is never named
	// here and is always part of the grouping, for the reason a count never
	// names it. Empty follows every event the tenant produced.
	GroupBy []Field
}

type Stage struct {
	Name  string
	Match Expression
}

func (s Sequence) Correlates() bool { return len(s.Stages) > 0 || s.Within != 0 || len(s.GroupBy) > 0 }

type Stages uint8

func (s Stages) Add(stage int) Stages { return s | 1<<uint(stage) }

func (s Stages) Has(stage int) bool { return s&(1<<uint(stage)) != 0 }

func (s Stages) Any() bool { return s != 0 }

func (s Stages) String() string { return string([]byte{byte(s)}) }

func StagesOf(value string) Stages {
	if len(value) != 1 {
		return 0
	}
	return Stages(value[0])
}

type Correlated struct {
	Group  []Binding
	Stages []Satisfied

	// Ordering is decided in event time, which is the producer's clock. This is
	// the spread of what the platform saw of those clocks, so a sequence whose
	// spread is wider than its own span is one the order of which the data does
	// not establish.
	ClockSpread time.Duration
}

type Satisfied struct {
	Name  string
	Event string
	At    time.Time
}

func (c Correlated) Events() []string {
	events := make([]string, 0, len(c.Stages))
	for _, stage := range c.Stages {
		events = append(events, stage.Event)
	}
	return events
}

func (c Correlated) Span() time.Duration {
	if len(c.Stages) < 2 {
		return 0
	}
	return c.Stages[len(c.Stages)-1].At.Sub(c.Stages[0].At)
}

// Whether the clocks disagreed by more than the story lasted. An ordering that
// rests on two clocks further apart than the events they separate is one the
// platform reports and does not vouch for.
func (c Correlated) Ordered() bool { return c.ClockSpread < c.Span() }

func (s Sequence) Named() string {
	names := make([]string, 0, len(s.Stages))
	for _, stage := range s.Stages {
		names = append(names, stage.Name)
	}
	return strings.Join(names, " then ")
}

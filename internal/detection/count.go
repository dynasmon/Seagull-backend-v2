package detection

import "time"

// What a rule counts before it decides anything.
//
// A rule without one answers for the event in front of it. A rule with one
// answers for how many matching events shared a group inside a window, which is
// a different security statement made of the same match: one failed password is
// a fact, and twenty from one address in a minute is an attack. Any part of it
// written means a rule that counts, so half a count is refused for what it is
// missing rather than read as no count at all.
type Count struct {
	AtLeast int
	Within  time.Duration

	// What makes two matching events the same thing being counted. The tenant
	// is never named here and is always part of the grouping, because a count
	// that could span one is a number somebody could read past. Empty counts
	// everything the tenant produced that matched.
	GroupBy []Field
}

func (c Count) Counts() bool { return !c.empty() }

func (c Count) empty() bool {
	return c.AtLeast == 0 && c.Within == 0 && len(c.GroupBy) == 0
}

// One field a counting rule groups by, and what an event held in it. Absent is
// its own group: an event carrying no source address must not be counted
// alongside every address that was named.
type Binding struct {
	Field  Field
	Value  string
	Absent bool
}

const (
	tenantField   Field = "origin.tenant_id"
	identityField Field = "event_id"
)

func (b Binding) String() string {
	if b.Absent {
		return string(b.Field) + " absent"
	}
	return string(b.Field) + " " + b.Value
}

// What a counting rule's window held when it decided. Zero on a rule that
// counts nothing: the rule's own count says what was asked for and this says
// what was there, so a detection can report the two together.
type Counted struct {
	Group     []Binding
	Count     int
	First     time.Time
	Saturated bool
}

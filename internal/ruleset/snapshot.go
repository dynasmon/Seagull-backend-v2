package ruleset

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"iter"
	"slices"
	"strconv"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The compiled rules a process is pinned to. A snapshot never changes after it
// is composed: what a reader holds is what it keeps for the whole of its work,
// so a ruleset arriving behind it cannot move a rule out from under an event
// halfway through being decided.
type Snapshot struct {
	id       ID
	programs []*detection.Program
	byClass  map[eventv1.EventClass][]*detection.Program
	running  int
}

// What is in a ruleset rather than when it was loaded, so two processes given
// the same rules name the same ruleset and a detection can be traced back to
// exactly what decided it. A counter could not do either: it says where one
// process has got to, and says nothing about what it is running.
type ID string

// Everything the compiled rules say, held to being one ruleset. Order does not
// change identity — the same rules in two files are the same ruleset — and a
// rule that arrives twice is refused rather than silently kept once.
func Compose(programs []*detection.Program) (*Snapshot, error) {
	held := slices.Clone(programs)
	for index, program := range held {
		if program == nil {
			return nil, fmt.Errorf("a ruleset holds compiled rules and program %d is nothing", index)
		}
	}
	slices.SortFunc(held, func(one, other *detection.Program) int {
		return cmp.Compare(one.Rule().ID, other.Rule().ID)
	})

	snapshot := &Snapshot{programs: held, byClass: make(map[eventv1.EventClass][]*detection.Program)}
	for index, program := range held {
		rule := program.Rule()
		if index > 0 && held[index-1].Rule().ID == rule.ID {
			return nil, fmt.Errorf("a ruleset holds one rule per id and %q arrives twice", rule.ID)
		}
		if !rule.Status.Runs() {
			continue
		}
		snapshot.byClass[rule.Class] = append(snapshot.byClass[rule.Class], program)
		snapshot.running++
	}

	snapshot.id = identify(held)
	return snapshot, nil
}

func (s *Snapshot) ID() ID { return s.id }

// Every rule the ruleset holds, whether or not it runs.
func (s *Snapshot) Rules() int { return len(s.programs) }

// The rules an event is actually decided by: a draft is written and a disabled
// one is kept, and neither is evaluated.
func (s *Snapshot) Running() int { return s.running }

// The rules that run for a class, in rule order, which is the same order in
// every process holding the same ruleset. A sequence rather than a slice
// because what a worker is handed here is shared with every other worker: a
// slice would let one of them write into what the rest are reading.
func (s *Snapshot) For(class eventv1.EventClass) iter.Seq[*detection.Program] {
	return func(yield func(*detection.Program) bool) {
		for _, program := range s.byClass[class] {
			if !yield(program) {
				return
			}
		}
	}
}

// Everything a rule carries that a detection could name or that changes what a
// rule does, length prefixed so that no two rulesets can write the same bytes.
// The compiled form stands in for the expression, which is what makes two rules
// that ask the same thing in different words the same rule here.
func identify(programs []*detection.Program) ID {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	for _, program := range programs {
		rule := program.Rule()
		for _, part := range []string{
			string(rule.ID),
			strconv.Itoa(rule.Revision),
			strconv.Itoa(int(rule.Class)),
			string(rule.Severity),
			string(rule.Status),
			rule.Technique.Tactic,
			rule.Technique.ID,
			rule.Technique.Name,
			rule.Name,
			rule.Description,
			rule.FalsePositives,
			rule.Response,
			program.String(),
		} {
			write(part)
		}
	}
	return ID(hex.EncodeToString(digest.Sum(nil)[:16]))
}

package rulefile

import (
	"fmt"
	"io/fs"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

// A case that did not hold, and the file it was written in.
type Unheld struct {
	*detection.Failure
	Source string
}

func (u *Unheld) Error() string { return u.Source + ": " + u.Failure.Error() }

// What checking a tree of rule files came to: how much ran, every case that did
// not hold, and every rule nothing was written for.
//
// A rule with no cases is reported rather than refused. Whether an estate ships
// an untested rule is its own decision and belongs where the ruleset is chosen;
// what this must not do is let one pass quietly, which is how a harness ends up
// proving nothing.
type Report struct {
	Rules    int
	Cases    int
	Unheld   []*Unheld
	Untested []detection.ID
}

func (r Report) Held() bool { return len(r.Unheld) == 0 }

func (r Report) String() string {
	return fmt.Sprintf("%d rules, %d cases, %d unheld, %d untested",
		r.Rules, r.Cases, len(r.Unheld), len(r.Untested))
}

// Run every case written beside every rule under the tree.
//
// Nothing outside the files is read and nothing is started, so a rule answers
// the same here, in a pipeline and in a control plane as it does in the engine:
// checking a case is the same pure function the engine calls on every event.
func Check(fsys fs.FS) (Report, error) {
	written, err := Rules(fsys)
	if err != nil {
		return Report{}, err
	}

	report := Report{Rules: len(written)}
	for _, rule := range written {
		if len(rule.Cases) == 0 {
			report.Untested = append(report.Untested, rule.Program.Rule().ID)
			continue
		}
		for _, subject := range rule.Cases {
			report.Cases++
			if failure := rule.Program.Check(subject); failure != nil {
				report.Unheld = append(report.Unheld, &Unheld{Failure: failure, Source: rule.Source})
			}
		}
	}
	return report, nil
}

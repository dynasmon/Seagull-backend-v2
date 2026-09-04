package sigma

import (
	"fmt"
	"strings"
)

// Where a Sigma document could not be translated and why, in the shape a rule
// file fault has: the file, the position in it, the rule, the part of the
// document, and what it would have had to say instead.
type Fault struct {
	Source string
	Line   int
	Column int
	Rule   string
	Part   string
	Reason string

	cause error
}

func (f *Fault) Error() string {
	written := []string{fmt.Sprintf("%s:%d:%d:", f.Source, f.Line, f.Column)}
	if f.Rule != "" {
		written = append(written, fmt.Sprintf("rule %q:", f.Rule))
	}
	if f.Part != "" {
		written = append(written, f.Part)
	}
	return strings.Join(append(written, f.Reason), " ")
}

// A refusal from the domain keeps its own type underneath, so what refused a
// translated rule can still be asked about after the Sigma document has said
// where it was written.
func (f *Fault) Unwrap() error { return f.cause }

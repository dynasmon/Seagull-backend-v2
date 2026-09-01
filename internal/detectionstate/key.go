// Package detectionstate says what a rule remembers between events, and bounds
// it: a window of observations under a key, measured in event time.
package detectionstate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

type Key string

// The tenant is never declared, because state spanning one is a count somebody
// could read past; the revision is, because a revised rule asks another
// question and must not inherit the answer to the old one.
func KeyFor(tenant string, rule detection.ID, revision int, group []detection.Binding) Key {
	digest := sha256.New()
	write := func(value string) { fmt.Fprintf(digest, "%d:%s", len(value), value) }

	write(tenant)
	write(string(rule))
	write(strconv.Itoa(revision))

	ordered := slices.Clone(group)
	slices.SortFunc(ordered, func(a, b detection.Binding) int { return strings.Compare(a.String(), b.String()) })
	for _, bound := range slices.Compact(ordered) {
		write(string(bound.Field))
		if bound.Absent {
			write("\x00absent")
			continue
		}
		write(bound.Value)
	}
	return Key(hex.EncodeToString(digest.Sum(nil)[:16]))
}

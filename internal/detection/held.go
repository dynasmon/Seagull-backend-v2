package detection

import (
	"strconv"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// What a detection says the events it was decided from held in a field, as an
// event carries it: read from what the rule compared, where text is written the
// way a rule writes a literal, and from what a rule that counts or orders
// grouped by. It answers false both when the event did not carry the field and
// when the detection says nothing about it, which Speaks tells apart.
func HeldIn(made *detectionv1.Detection, field Field) (string, bool) {
	held, absent, spoken := find(made, field)
	return held, spoken && !absent
}

func Speaks(made *detectionv1.Detection, field Field) bool {
	_, _, spoken := find(made, field)
	return spoken
}

func find(made *detectionv1.Detection, field Field) (held string, absent, spoken bool) {
	for _, seen := range made.GetEvidence() {
		if Field(seen.GetField()) == field {
			return carried(field, seen.GetHeld()), seen.GetAbsent(), true
		}
	}
	for _, group := range [][]*detectionv1.Grouping{made.GetAggregation().GetGroup(), made.GetCorrelation().GetGroup()} {
		for _, bound := range group {
			if Field(bound.GetField()) == field {
				return bound.GetValue(), bound.GetAbsent(), true
			}
		}
	}
	return "", false, false
}

func carried(field Field, held string) string {
	if kind, _ := KindOf(field); kind != Text {
		return held
	}
	if unquoted, err := strconv.Unquote(held); err == nil {
		return unquoted
	}
	return held
}

package alertstore

import (
	"log/slog"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// Rule identifiers arrive in records, so how many pairs the writer remembers
// having told about is bounded rather than trusted to stay small; past the bound
// the counter still says how often. Only the batch being considered touches the
// set, one batch at a time, so it holds no lock.
const maxToldUnspoken = 1024

type unspokenPart struct {
	rule string
	part alert.Part
}

// A key part a detection says nothing about keeps no two detections of its rule
// apart, which hides attackers rather than noise. Which rules are active is the
// ruleset's to say and this process never reads it, so the writer learns it from
// the first detection of each rule and says it then.
func (w *Writer) unspoken(made *detectionv1.Detection, parts []alert.Part) {
	for _, part := range parts {
		w.metrics.unspoken(part)

		told := unspokenPart{rule: made.GetRule().GetId(), part: part}
		if _, already := w.told[told]; already || len(w.told) >= maxToldUnspoken {
			continue
		}
		w.told[told] = struct{}{}
		w.logger.Warn("alert_key_part_unspoken",
			slog.String("rule", told.rule),
			slog.String("part", part.String()),
			slog.String("tuning", w.tuning.ID()),
		)
	}
}

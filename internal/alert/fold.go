package alert

import (
	"time"

	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
)

// What became of a detection on its way to being somebody's work. Four
// different things, counted separately, because an operator answers them
// differently: nothing to do, one more of something already open, something the
// estate said it does not want, and something it closed too recently to hear
// about again.
type Outcome string

const (
	OutcomeRaised     Outcome = "raised"
	OutcomeFolded     Outcome = "folded"
	OutcomeRepeated   Outcome = "repeated"
	OutcomeSuppressed Outcome = "suppressed"
	OutcomeCooledDown Outcome = "cooled_down"
)

func (o Outcome) String() string { return string(o) }

// One detection, decided against the tuning and ready for the store: the alert
// it would raise, the key it folds on, and the two windows the store compares
// against. Everything here is derived from the detection and the document, so
// the store adds no policy of its own.
type Candidate struct {
	Alert       *alertv1.Alert
	DetectionID string
	Key         string
	At          time.Time
	Window      time.Duration
	Cooldown    time.Duration
}

// The instant every window is measured against is the detection's event time
// rather than the clock, so replaying a batch a week later decides exactly what
// it decided the first time. v1 compared against `utcnow()` and could not.
func Consider(made *detectionv1.Detection, tuning *Tuning, at time.Time) (Candidate, error) {
	raised, err := Raise(made, at)
	if err != nil {
		return Candidate{}, err
	}

	fold := tuning.Fold(made.GetRule().GetId())
	raised.CorrelationKey = CorrelationKey(made, fold.Keyed)

	return Candidate{
		Alert:       raised,
		DetectionID: made.GetDetectionId(),
		Key:         raised.GetCorrelationKey(),
		At:          Happened(made, at),
		Window:      fold.Window,
		Cooldown:    fold.Cooldown,
	}, nil
}

func Happened(made *detectionv1.Detection, fallback time.Time) time.Time {
	if made.GetEventTime() == nil {
		return fallback.UTC()
	}
	return made.GetEventTime().AsTime().UTC()
}

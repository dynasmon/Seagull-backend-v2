package agentstatus

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestAnAgentIsActiveWhileItsReportsArriveAndSilentOnceThreeAreMissing(t *testing.T) {
	received := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	held := Report{Received: received, Status: report()}
	for _, one := range []struct {
		after time.Duration
		want  agentv1.Liveness
	}{
		{0, agentv1.Liveness_LIVENESS_ACTIVE},
		{2 * time.Minute, agentv1.Liveness_LIVENESS_ACTIVE},
		{2*time.Minute + time.Second, agentv1.Liveness_LIVENESS_LATE},
		{5 * time.Minute, agentv1.Liveness_LIVENESS_LATE},
		{5*time.Minute + time.Second, agentv1.Liveness_LIVENESS_SILENT},
		{30 * 24 * time.Hour, agentv1.Liveness_LIVENESS_SILENT},
		{-time.Minute, agentv1.Liveness_LIVENESS_ACTIVE},
	} {
		if got := held.Liveness(received.Add(one.after)); got != one.want {
			t.Errorf("%s after a report announcing a minute, the agent is %s and %s was expected", one.after, got, one.want)
		}
	}
}

func TestAnAgentThatSaidItWasStoppingStaysStopped(t *testing.T) {
	received := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	stopping := mutate(func(r *agentv1.Status) { r.Condition = agentv1.Status_CONDITION_STOPPED })
	for _, after := range []time.Duration{0, time.Hour, 365 * 24 * time.Hour} {
		if got := (Report{Received: received, Status: stopping}).Liveness(received.Add(after)); got != agentv1.Liveness_LIVENESS_STOPPED {
			t.Errorf("%s after it said it was stopping, the agent is %s", after, got)
		}
	}
}

// An interval the platform never admitted, read back from a store written by
// an older build, is judged at the nearest one it admits rather than as zero,
// which would make every agent silent the moment it reported.
func TestAnIntervalOutsideTheBoundsIsJudgedAtTheNearestBound(t *testing.T) {
	received := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	for _, one := range []struct {
		announced, after time.Duration
		want             agentv1.Liveness
	}{
		{0, 2 * MinInterval, agentv1.Liveness_LIVENESS_ACTIVE},
		{0, Silence*MinInterval + time.Second, agentv1.Liveness_LIVENESS_SILENT},
		{48 * time.Hour, 2 * MaxInterval, agentv1.Liveness_LIVENESS_ACTIVE},
		{48 * time.Hour, Silence*MaxInterval + time.Second, agentv1.Liveness_LIVENESS_SILENT},
	} {
		announcing := mutate(func(r *agentv1.Status) { r.Interval = durationpb.New(one.announced) })
		if got := (Report{Received: received, Status: announcing}).Liveness(received.Add(one.after)); got != one.want {
			t.Errorf("%s after a report announcing %s, the agent is %s and %s was expected", one.after, one.announced, got, one.want)
		}
	}
}

func TestNothingHeldIsNoLiveness(t *testing.T) {
	now := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	for _, held := range []Report{{}, {Received: now}, {Status: report()}} {
		if got := held.Liveness(now); got != agentv1.Liveness_LIVENESS_UNSPECIFIED {
			t.Errorf("%+v was judged %s", held, got)
		}
	}
}

package agentupdate

import (
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What an agent a rollout reached says of its release.
type Outcome int

const (
	Pending Outcome = iota
	Running
	Failed
	Ineligible
)

// Judge reads one agent's newest report against the release a rollout moves it
// to, as the newest catalog names it. Everything in a report is the agent's
// claim, so this tells a rollout what agents say and never what they run: an
// agent that says it failed pauses a rollout sooner, which is the side a lie
// can only push it to, and one that says it runs a release it does not run
// opens the next wave sooner, which is the side the soak and the count of
// failures exist to hold.
func Judge(report *agentv1.Status, target string, catalog *Catalog) Outcome {
	if report == nil {
		return Pending
	}
	build := report.GetBuild()
	if build.GetVersion() == target {
		return Running
	}
	if update := report.GetUpdate(); update.GetVersion() == target {
		switch update.GetStage() {
		case agentv1.Status_Update_STAGE_ROLLED_BACK:
			return Failed
		case agentv1.Status_Update_STAGE_FAILED:
			switch update.GetFailure() {
			case agentv1.Status_Update_FAILURE_UNVERIFIED, agentv1.Status_Update_FAILURE_INSTALLATION, agentv1.Status_Update_FAILURE_UNHEALTHY:
				return Failed
			case agentv1.Status_Update_FAILURE_REFUSED:
				return Ineligible
			}
		}
	}
	if catalog != nil && !Takes(report, target, catalog) {
		return Ineligible
	}
	return Pending
}

// Takes says whether an agent could install the release, by what it reports of
// itself and by what the release and the one it runs say: the checks the agent
// makes before installing, made before asking it. An agent that predates
// reporting how it takes updates is held only to what its build says.
func Takes(report *agentv1.Status, target string, catalog *Catalog) bool {
	build := report.GetBuild()
	running, valid := ParseVersion(build.GetVersion())
	wanted, _ := ParseVersion(target)
	if !valid {
		return false
	}
	updates := report.GetCompatibility().GetUpdates()
	described := report.GetCompatibility() != nil
	if described && !updates.GetEnabled() {
		return false
	}

	matching := func(version string) *updatev1.Release {
		for _, release := range catalog.catalog.GetReleases() {
			platform := release.GetPlatform()
			if release.GetVersion() == version && platform.GetOs() == build.GetOs() && platform.GetArchitecture() == build.GetArchitecture() &&
				(!described || platform.GetFormat() == updates.GetFormat()) {
				return release
			}
		}
		return nil
	}
	release, current := matching(target), matching(running.String())
	switch {
	case release == nil || current == nil:
		return false
	case described && release.GetCompatibility().GetStateGeneration() < updates.GetStateGeneration():
		return false
	}
	switch order := wanted.Compare(running); {
	case order < 0:
		return slices.Contains(release.GetReplaces(), running.String())
	case order > 0:
		minimum := release.GetCompatibility().GetMinimumVersion()
		if oldest, named := ParseVersion(minimum); minimum != "" && named && running.Compare(oldest) < 0 {
			return false
		}
	}
	return true
}

// What a rollout counts of the agents it reached, and the agents it counts as
// failing, which an operator resuming it takes as known.
type Tally struct {
	Progress *updatev1.RolloutProgress
	Failing  []string
}

func (t *Tally) Count(agentID string, outcome Outcome, acknowledged bool) {
	progress := t.Progress
	switch outcome {
	case Running:
		progress.Running++
	case Failed:
		if acknowledged {
			progress.Acknowledged++
			return
		}
		progress.Failed++
		t.Failing = append(t.Failing, agentID)
	case Ineligible:
		progress.Ineligible++
	default:
		progress.Pending++
	}
}

// What a gate does with a rollout once the platform read how far it went.
type Step int

const (
	Hold Step = iota
	Pause
	Open
)

// Gate decides whether an active rollout opens its next wave or pauses, from
// what the platform last read of the agents it reached. A failure count that
// reached the rollout's `failures` pauses it before anything else is weighed.
func Gate(record *updatev1.RolloutRecord, progress *updatev1.RolloutProgress, now time.Time) (Step, string) {
	rollout := record.GetRollout()
	if record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE {
		return Hold, ""
	}
	if failed := progress.GetFailed(); failed >= rollout.GetFailures() {
		return Pause, fmt.Sprintf("%d of the agents reached failed %s, and %d failing pause the rollout", failed, rollout.GetVersion(), rollout.GetFailures())
	}
	waves := rollout.GetWaves()
	index := int(record.GetWave())
	if index+1 >= len(waves) {
		return Hold, ""
	}
	wave := waves[index]
	soak := wave.GetSoak()
	if soak == nil {
		return Hold, ""
	}
	if now.Before(record.GetWaveOpenedAt().AsTime().Add(soak.AsDuration())) || progress.GetRunning() < wave.GetRunning() {
		return Hold, ""
	}
	return Open, fmt.Sprintf("wave %d ran for %s with %d of the agents reached running %s", index, soak.AsDuration(), progress.GetRunning(), rollout.GetVersion())
}

// Opened is the rollout with its next wave open, as a gate opened it.
func Opened(record *updatev1.RolloutRecord, reason string, at time.Time) *updatev1.RolloutRecord {
	return changed(record, func(next *updatev1.RolloutRecord) {
		next.Wave, next.WaveOpenedAt = record.GetWave()+1, timestamppb.New(at.UTC())
	}, reason, at)
}

// Paused is the rollout as a gate paused it.
func Paused(record *updatev1.RolloutRecord, reason string, at time.Time) *updatev1.RolloutRecord {
	return changed(record, func(next *updatev1.RolloutRecord) {
		next.State = updatev1.RolloutRecord_STATE_PAUSED
	}, reason, at)
}

func changed(record *updatev1.RolloutRecord, change func(*updatev1.RolloutRecord), reason string, at time.Time) *updatev1.RolloutRecord {
	next := &updatev1.RolloutRecord{
		RolloutId:    record.GetRolloutId(),
		Rollout:      record.GetRollout(),
		State:        record.GetState(),
		Wave:         record.GetWave(),
		WaveOpenedAt: record.GetWaveOpenedAt(),
		CreatedBy:    record.GetCreatedBy(),
		CreatedAt:    record.GetCreatedAt(),
		ChangedBy:    Platform,
		ChangedAt:    timestamppb.New(at.UTC()),
		Reason:       reason,
		Progress:     record.GetProgress(),
	}
	change(next)
	return next
}

package fleetjudge

import (
	"slices"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// An agent's places are the runs heard within their silence threshold, and its
// episodes the copies and shared identities found among them: both bounded by
// the reports a finding names, so a key held in several places costs the judge
// a constant and never what the holder chooses. An episode beyond them is
// counted and not opened, since an operator answers an identity, not a finding.
const (
	maxPlaces = agentfinding.MaxReports
	maxOpen   = agentfinding.MaxReports
	maxClosed = agentfinding.MaxReports
)

type place struct {
	highest    *agentv1.Heard
	latest     *agentv1.Heard
	previously time.Time
}

func (p *place) heard() time.Time { return p.latest.GetIngestTime().AsTime() }

func (p *place) away(at time.Time) bool {
	return !at.Before(p.heard().Add(agentfinding.Threshold(p.latest)))
}

type episode struct {
	finding  *agentv1.Finding
	members  []*agentv1.Heard
	observed bool
	every    time.Duration
}

func (e *episode) open() bool { return e.finding.GetState() == agentv1.Finding_STATE_OPEN }

func (e *episode) holds(member, report *agentv1.Heard) bool {
	if e.finding.GetKind() == agentv1.Finding_KIND_SHARED_IDENTITY {
		return member.GetInstallationId() == report.GetInstallationId()
	}
	return sameRun(member, report)
}

func (e *episode) join(report *agentv1.Heard) {
	for index, member := range e.members {
		if e.holds(member, report) {
			e.members[index] = report
			return
		}
	}
	e.members = append(e.members, report)
	if len(e.members) > agentfinding.MaxReports {
		e.members = slices.Delete(e.members, quietest(e.members), quietest(e.members)+1)
	}
}

func (e *episode) observe(report, other *agentv1.Heard) {
	e.join(other)
	e.join(report)
	e.finding = agentfinding.Observed(e.finding, report.GetIngestTime().AsTime(), e.members, e.finding.GetDecidedAt().AsTime())
	e.observed, e.every = true, agentfinding.Threshold(report)
}

// The instant every place but one had stayed away its threshold, when exactly
// one is still heard and the platform listened through each one's absence.
func (e *episode) oneSource(now time.Time, stretch *listening.Stretch) (time.Time, bool) {
	heard := 0
	var since time.Time
	for _, member := range e.members {
		threshold := agentfinding.Threshold(member)
		from := member.GetIngestTime().AsTime().Add(threshold)
		switch {
		case now.Before(from):
			heard++
		case !stretch.Lasted(now, threshold):
			return time.Time{}, false
		case from.After(since):
			since = from
		}
	}
	return since, heard == 1
}

func sameRun(a, b *agentv1.Heard) bool {
	return a.GetInstallationId() == b.GetInstallationId() && a.GetBootId() == b.GetBootId() &&
		a.GetRunStartedAt().AsTime().Equal(b.GetRunStartedAt().AsTime())
}

func quietest(reports []*agentv1.Heard) int {
	oldest := 0
	for index, one := range reports {
		if one.GetIngestTime().AsTime().Before(reports[oldest].GetIngestTime().AsTime()) {
			oldest = index
		}
	}
	return oldest
}

func (h *held) place(report *agentv1.Heard) *place {
	for _, one := range h.places {
		if sameRun(one.latest, report) {
			return one
		}
	}
	return nil
}

func (h *held) passer(here *place, report *agentv1.Heard) *agentv1.Heard {
	for _, other := range h.places {
		if other != here && other.latest.GetInstallationId() == report.GetInstallationId() &&
			agentfinding.Passed(report, other.highest, other.previously) {
			return other.latest
		}
	}
	return nil
}

func (h *held) turner(report *agentv1.Heard) *agentv1.Heard {
	var mine *agentv1.Heard
	for _, one := range h.places {
		if one.highest.GetInstallationId() == report.GetInstallationId() && (mine == nil || one.highest.GetSequence() > mine.GetSequence()) {
			mine = one.highest
		}
	}
	if mine == nil {
		return nil
	}
	for _, other := range h.places {
		if other.highest.GetInstallationId() != report.GetInstallationId() && agentfinding.Turn(report, mine, other.highest) {
			return other.latest
		}
	}
	return nil
}

func (h *held) fold(here *place, report *agentv1.Heard, status *agentv1.Status) {
	for _, one := range h.episodes {
		for index, member := range one.members {
			if one.holds(member, report) {
				one.members[index] = report
			}
		}
	}
	if here != nil {
		if report.GetSequence() > here.highest.GetSequence() {
			here.highest = report
		}
		here.latest = report
		return
	}
	here = &place{highest: report, latest: report}
	if seen := status.GetRun().GetPreviousSeenAt(); seen.IsValid() {
		here.previously = seen.AsTime()
	}
	if len(h.places) == maxPlaces {
		latest := make([]*agentv1.Heard, 0, len(h.places))
		for _, one := range h.places {
			latest = append(latest, one.latest)
		}
		h.places = slices.Delete(h.places, quietest(latest), quietest(latest)+1)
	}
	h.places = append(h.places, here)
}

func (h *held) copyOf(installation string) *episode {
	for _, one := range h.episodes {
		if one.open() && one.finding.GetKind() == agentv1.Finding_KIND_COPIED_INSTALLATION && one.members[0].GetInstallationId() == installation {
			return one
		}
	}
	return nil
}

func (h *held) full(kind agentv1.Finding_Kind) bool {
	open := 0
	for _, one := range h.episodes {
		if one.open() && one.finding.GetKind() == kind {
			open++
		}
	}
	return open >= maxOpen
}

func (h *held) episode(findingID string) *episode {
	for _, one := range h.episodes {
		if one.finding.GetFindingId() == findingID {
			return one
		}
	}
	return nil
}

// A copy that closed is never decided again, since another copy of the same
// installation starts at another sequence; a shared identity stays, since the
// same two installations taking turns again is the same finding open again.
func (h *held) keep(found *episode) {
	h.episodes = slices.DeleteFunc(h.episodes, func(one *episode) bool {
		return !one.open() && one.finding.GetKind() != agentv1.Finding_KIND_SHARED_IDENTITY
	})
	if found != nil {
		h.episodes = append(h.episodes, found)
	}
	for closed := 0; ; closed = 0 {
		oldest := -1
		for index, one := range h.episodes {
			if !one.open() {
				closed++
				if oldest < 0 || one.finding.GetDecidedAt().AsTime().Before(h.episodes[oldest].finding.GetDecidedAt().AsTime()) {
					oldest = index
				}
			}
		}
		if closed <= maxClosed {
			return
		}
		h.episodes = slices.Delete(h.episodes, oldest, oldest+1)
	}
}

func (j *Judge) locate(one *held, agentID string, status *agentv1.Status, report *agentv1.Heard, live bool, now time.Time) {
	at := report.GetIngestTime().AsTime()
	one.places = slices.DeleteFunc(one.places, func(gone *place) bool { return gone.away(at) && !sameRun(gone.latest, report) })
	here := one.place(report)
	passed, turned := one.passer(here, report), one.turner(report)
	one.fold(here, report, status)
	known, admitted := j.admitted[agentID]
	if !admitted || !known.admits {
		return
	}
	if passed != nil {
		j.copied(one, known.tenant, agentID, report, passed, live, now)
	}
	if turned != nil {
		j.shared(one, known.tenant, agentID, report, turned, live, now)
	}
}

func (j *Judge) copied(one *held, tenant, agentID string, report, other *agentv1.Heard, live bool, now time.Time) {
	if found := one.copyOf(report.GetInstallationId()); found != nil {
		if live || report.GetIngestTime().AsTime().After(found.finding.GetLastObservedAt().AsTime()) {
			found.observe(report, other)
		}
		return
	}
	if live && j.room(one, agentv1.Finding_KIND_COPIED_INSTALLATION) {
		found := &episode{finding: agentfinding.Copied(tenant, agentID, report, other, now), members: []*agentv1.Heard{other, report}, every: agentfinding.Threshold(report)}
		one.keep(found)
		j.decide(found.finding)
	}
}

func (j *Judge) shared(one *held, tenant, agentID string, report, other *agentv1.Heard, live bool, now time.Time) {
	opened := agentfinding.Shared(tenant, agentID, report, other, now)
	found := one.episode(opened.GetFindingId())
	switch {
	case found != nil && found.open():
		if live || report.GetIngestTime().AsTime().After(found.finding.GetLastObservedAt().AsTime()) {
			found.observe(report, other)
		}
	case !live:
	case !j.room(one, agentv1.Finding_KIND_SHARED_IDENTITY):
	case found != nil:
		found.join(other)
		found.join(report)
		found.finding = agentfinding.Reopened(found.finding, report.GetIngestTime().AsTime(), found.members, now)
		found.observed, found.every = false, agentfinding.Threshold(report)
		j.decide(found.finding)
	default:
		found = &episode{finding: opened, members: []*agentv1.Heard{other, report}, every: agentfinding.Threshold(report)}
		one.keep(found)
		j.decide(found.finding)
	}
}

func (j *Judge) room(one *held, kind agentv1.Finding_Kind) bool {
	if !one.full(kind) {
		return true
	}
	j.metrics.unopened.WithLabelValues(agentfinding.KindName(kind)).Inc()
	return false
}

func (j *Judge) settle(one *held, now time.Time) {
	for _, found := range one.episodes {
		if !found.open() {
			continue
		}
		if at, quiet := found.oneSource(now, &j.stretch); quiet {
			found.finding = agentfinding.Closed(found.finding, agentv1.Finding_CLOSURE_ONE_SOURCE, at, now)
			j.decide(found.finding)
			continue
		}
		since := now.Sub(found.finding.GetDecidedAt().AsTime())
		if (found.observed && since >= found.every) || since >= j.again {
			found.finding = agentfinding.Again(found.finding, now)
			found.observed = false
			j.decide(found.finding)
		}
	}
	one.keep(nil)
}

func (j *Judge) dismiss(one *held, at, now time.Time) {
	for _, found := range one.episodes {
		if found.open() {
			found.finding = agentfinding.Closed(found.finding, agentv1.Finding_CLOSURE_NOT_ADMITTED, at, now)
			j.decide(found.finding)
		}
	}
	one.keep(nil)
}

func (j *Judge) restore() {
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for id, recalled := range j.recalled {
		if recalled.GetKind() == agentv1.Finding_KIND_SILENCE {
			continue
		}
		delete(j.recalled, id)
		if recalled.GetKind() == agentv1.Finding_KIND_REPLACED_CERTIFICATE {
			j.restoreRefusals(recalled, now)
			continue
		}
		known := j.admitted[recalled.GetAgentId()]
		open := recalled.GetState() == agentv1.Finding_STATE_OPEN
		switch {
		case open && !known.admits:
			j.decide(agentfinding.Closed(recalled, agentv1.Finding_CLOSURE_NOT_ADMITTED, whenever(known.changed, now), now))
		case open || recalled.GetKind() == agentv1.Finding_KIND_SHARED_IDENTITY:
			one := j.agents[recalled.GetAgentId()]
			if one == nil {
				one = &held{}
				j.agents[recalled.GetAgentId()] = one
			}
			reports := recalled.GetReports()
			one.keep(&episode{finding: recalled, members: slices.Clone(reports), every: agentfinding.Threshold(reports[len(reports)-1])})
		}
	}
}

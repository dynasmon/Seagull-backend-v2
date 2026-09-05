package detectionstate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

func byAgent() detectionstate.Partitioning {
	return detectionstate.Partitioning{By: []detection.Field{"origin.agent_id"}}
}

func counting(group ...detection.Field) detection.Count {
	return detection.Count{AtLeast: 20, Within: time.Minute, GroupBy: group}
}

func ordering(group ...detection.Field) detection.Sequence {
	return detection.Sequence{
		Stages:  []detection.Stage{{Name: "first"}, {Name: "then"}},
		Within:  time.Minute,
		GroupBy: group,
	}
}

func TestAGroupCarryingWhatTheStreamIsKeyedByIsExactAtAnyNumberOfReaders(t *testing.T) {
	held := byAgent()

	for _, group := range [][]detection.Field{
		{"origin.agent_id"},
		{"origin.agent_id", "authentication.network.source.ip"},
		{"authentication.network.source.ip", "origin.agent_id"},
	} {
		if !held.Colocates(group) {
			t.Errorf("%v was reported as split between readers", group)
		}
		if err := held.Admits(counting(group...)); err != nil {
			t.Errorf("a colocated count was refused: %v", err)
		}
		if err := held.Orders(ordering(group...)); err != nil {
			t.Errorf("a colocated sequence was refused: %v", err)
		}
	}
}

// One address seen by three agents lands on three partitions, so no single
// store holds the count.
func TestAGroupTheStreamDoesNotKeepTogetherIsRefused(t *testing.T) {
	held := byAgent()

	for _, group := range [][]detection.Field{
		{"authentication.network.source.ip"},
		{"authentication.user.name"},
		nil,
	} {
		if held.Colocates(group) {
			t.Errorf("%v was reported as colocated", group)
		}
		if err := held.Admits(counting(group...)); !errors.Is(err, detectionstate.ErrSplitState) {
			t.Errorf("a split count was admitted: %v", err)
		}
		if err := held.Orders(ordering(group...)); !errors.Is(err, detectionstate.ErrSplitState) {
			t.Errorf("a split sequence was admitted: %v", err)
		}
	}
}

func TestARuleThatRemembersNothingIsAdmittedByEveryPartitioning(t *testing.T) {
	held := byAgent()

	if err := held.Admits(detection.Count{}); err != nil {
		t.Errorf("a rule that counts nothing was refused: %v", err)
	}
	if err := held.Orders(detection.Sequence{}); err != nil {
		t.Errorf("a rule that orders nothing was refused: %v", err)
	}
}

func TestOneReaderHoldingTheWholeStreamAnswersAnyGroup(t *testing.T) {
	held := detectionstate.Partitioning{By: []detection.Field{"origin.agent_id"}, Sole: true}

	if err := held.Admits(counting("authentication.network.source.ip")); err != nil {
		t.Errorf("a sole reader was refused a group that spans agents: %v", err)
	}
	if held.Colocates([]detection.Field{"authentication.network.source.ip"}) {
		t.Error("holding the whole stream was reported as the stream keeping the group together")
	}
}

// Every group is inside one tenant already.
func TestAStreamKeyedByTheTenantKeepsEveryGroupTogether(t *testing.T) {
	held := detectionstate.Partitioning{By: []detection.Field{"origin.tenant_id"}}

	if !held.Colocates([]detection.Field{"authentication.network.source.ip"}) {
		t.Error("a tenant-keyed stream was reported as splitting a group inside one tenant")
	}
}

func TestAStreamThatPromisesNothingKeepsNoGroupTogether(t *testing.T) {
	var held detectionstate.Partitioning

	if held.Colocates([]detection.Field{"origin.agent_id"}) {
		t.Error("an unkeyed stream was reported as keeping a group together")
	}
	if err := held.Validate(); !errors.Is(err, detectionstate.ErrNoPartitioning) {
		t.Errorf("an unkeyed stream validated: %v", err)
	}
}

func TestAPartitioningNamingAFieldTheContractDoesNotDeclareIsRefused(t *testing.T) {
	held := detectionstate.Partitioning{By: []detection.Field{"origin.agent"}}

	if err := held.Validate(); !errors.Is(err, detectionstate.ErrNoPartitioning) {
		t.Errorf("a misspelled partition field validated: %v", err)
	}
	if err := byAgent().Validate(); err != nil {
		t.Errorf("the partitioning the backbone declares was refused: %v", err)
	}
}

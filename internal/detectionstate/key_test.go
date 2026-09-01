package detectionstate_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
)

const (
	tenant = "dev-tenant"
	rule   = detection.ID("repeated.ssh.password.failure")
)

func bound(field, value string) detection.Binding {
	return detection.Binding{Field: detection.Field(field), Value: value}
}

func TestOneGroupIsOneKeyHoweverItIsWritten(t *testing.T) {
	agent := bound("origin.agent_id", "dev-agent-01")
	source := bound("authentication.source.ip", "203.0.113.10")

	forwards := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{agent, source})
	backwards := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{source, agent})
	if forwards != backwards {
		t.Error("the order the group was written in changed the key")
	}

	repeated := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{agent, source, agent})
	if repeated != forwards {
		t.Error("naming a bound twice changed the key")
	}
}

func TestAKeyNeverSpansATenantARuleOrARevision(t *testing.T) {
	group := []detection.Binding{bound("origin.agent_id", "dev-agent-01")}
	here := detectionstate.KeyFor(tenant, rule, 1, group)

	if detectionstate.KeyFor("another-tenant", rule, 1, group) == here {
		t.Error("two tenants shared a key")
	}
	if detectionstate.KeyFor(tenant, "some.other.rule", 1, group) == here {
		t.Error("two rules shared a key")
	}
	if detectionstate.KeyFor(tenant, rule, 2, group) == here {
		t.Error("two revisions of a rule shared a key, so a revision would inherit the answer to the old question")
	}
}

func TestAnAbsentFieldIsAGroupOfItsOwn(t *testing.T) {
	field := detection.Field("authentication.source.ip")
	absent := []detection.Binding{{Field: field, Absent: true}}
	empty := []detection.Binding{{Field: field}}

	if detectionstate.KeyFor(tenant, rule, 1, absent) == detectionstate.KeyFor(tenant, rule, 1, empty) {
		t.Error("events carrying no source address were counted alongside events carrying an empty one")
	}
}

func TestTwoDifferentGroupsAreTwoKeys(t *testing.T) {
	here := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{bound("authentication.source.ip", "203.0.113.10")})
	elsewhere := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{bound("authentication.source.ip", "198.51.100.9")})
	if here == elsewhere {
		t.Error("two source addresses shared a key")
	}

	ungrouped := detectionstate.KeyFor(tenant, rule, 1, nil)
	if ungrouped == here || ungrouped == "" {
		t.Error("a rule that groups by nothing has no key of its own")
	}
}

// A group value is attacker-supplied and a key is held in memory for as long as
// the window lasts, so its size may not follow the value's.
func TestAKeyIsTheSameSizeWhateverTheEventHeld(t *testing.T) {
	short := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{bound("authentication.user.name", "root")})

	long := strings.Repeat("a", 1024)
	sprawling := detectionstate.KeyFor(tenant, rule, 1, []detection.Binding{bound("authentication.user.name", long)})

	if len(short) != len(sprawling) {
		t.Errorf("a %d byte value made a %d byte key against a %d byte one", len(long), len(sprawling), len(short))
	}
}

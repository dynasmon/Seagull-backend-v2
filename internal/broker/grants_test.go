package broker

import (
	"slices"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"
)

func writersOf(grants []Grant, topic Topic) []Component {
	var writers []Component
	for _, grant := range grants {
		if slices.ContainsFunc(grant.Writes, func(written Topic) bool { return written.Name == topic.Name }) {
			writers = append(writers, grant.Component)
		}
	}
	return writers
}

func TestEveryTopicIsWrittenByAComponentItIsGrantedTo(t *testing.T) {
	topology := declared(t, map[string]string{})
	grants := topology.Grants()
	for _, topic := range topology.Topics() {
		if len(writersOf(grants, topic)) == 0 {
			t.Errorf("no component is granted writing %s, so nothing the platform runs can fill it", topic.Name)
		}
	}
}

func TestEveryComponentIsGrantedOnce(t *testing.T) {
	seen := map[Component]bool{}
	for _, grant := range declared(t, map[string]string{}).Grants() {
		if seen[grant.Component] {
			t.Errorf("%s is granted twice", grant.Component)
		}
		seen[grant.Component] = true
	}
}

func TestWhatDecidesForTheWholePlatformHasOneWriter(t *testing.T) {
	topology := declared(t, map[string]string{})
	grants := topology.Grants()
	for _, sole := range []struct {
		topic  Topic
		writer Component
	}{
		{topology.Agents, ControlAPI},
		{topology.Rulesets, ControlAPI},
		{topology.Advisories, AdvisoryImporter},
	} {
		if writers := writersOf(grants, sole.topic); !slices.Equal(writers, []Component{sole.writer}) {
			t.Errorf("%s is written by %v and only %s may write it", sole.topic.Name, writers, sole.writer)
		}
	}
}

func TestNoComponentWritesWhatItConsumesInItsGroup(t *testing.T) {
	for _, grant := range declared(t, map[string]string{}).Grants() {
		for _, consumed := range grant.Consumes {
			if slices.ContainsFunc(grant.Writes, func(written Topic) bool { return written.Name == consumed.Name }) {
				t.Errorf("%s writes %s, which it consumes in its group", grant.Component, consumed.Name)
			}
		}
	}
}

func TestAComponentReadsInItsOwnGroupAndOnlyDescribesTheGroupsItObserves(t *testing.T) {
	for _, grant := range declared(t, map[string]string{}).Grants() {
		for _, permission := range grant.Permissions() {
			if permission.Resource != kmsg.ACLResourceTypeGroup {
				continue
			}
			own := permission.Name == grant.Component.Group()
			observed := slices.ContainsFunc(grant.Observes, func(c Component) bool { return c.Group() == permission.Name })
			switch {
			case own && len(grant.Consumes) == 0:
				t.Errorf("%s consumes nothing in a group and is granted %s on its own", grant.Component, permission.Operation)
			case !own && !observed:
				t.Errorf("%s is granted %s on group %s, which is neither its own nor one it observes", grant.Component, permission.Operation, permission.Name)
			case !own && permission.Operation != kmsg.ACLOperationDescribe:
				t.Errorf("%s is granted %s on %s's group and may only read where it stands", grant.Component, permission.Operation, permission.Name)
			}
		}
		if len(grant.Consumes) > 0 && !slices.Contains(grant.Permissions(), Permission{Resource: kmsg.ACLResourceTypeGroup, Name: grant.Component.Group(), Operation: kmsg.ACLOperationRead}) {
			t.Errorf("%s consumes in its group and is not granted reading it", grant.Component)
		}
	}
}

func TestNoComponentIsGrantedAnythingAdministrative(t *testing.T) {
	allowed := []kmsg.ACLOperation{kmsg.ACLOperationRead, kmsg.ACLOperationWrite, kmsg.ACLOperationDescribe, kmsg.ACLOperationDescribeConfigs}
	for _, grant := range declared(t, map[string]string{}).Grants() {
		for _, permission := range grant.Permissions() {
			if !slices.Contains(allowed, permission.Operation) {
				t.Errorf("%s is granted %s on %s", grant.Component, permission.Operation, permission.Name)
			}
			if permission.Resource != kmsg.ACLResourceTypeTopic && permission.Resource != kmsg.ACLResourceTypeGroup {
				t.Errorf("%s is granted %s on a %s", grant.Component, permission.Operation, permission.Resource)
			}
		}
	}
}

func TestAComponentIsGrantedEveryTopicItTouchesAndNoOther(t *testing.T) {
	topology := declared(t, map[string]string{})
	gateway := topology.Grants()[0]
	if gateway.Component != IngestGateway {
		t.Fatalf("the first grant is %s", gateway.Component)
	}
	touched := map[string][]kmsg.ACLOperation{}
	for _, permission := range gateway.Permissions() {
		if permission.Resource == kmsg.ACLResourceTypeGroup {
			t.Errorf("the gateway consumes in no group and is granted %s on %s", permission.Operation, permission.Name)
			continue
		}
		touched[permission.Name] = append(touched[permission.Name], permission.Operation)
	}
	written := []kmsg.ACLOperation{kmsg.ACLOperationWrite, kmsg.ACLOperationDescribe, kmsg.ACLOperationDescribeConfigs}
	followed := []kmsg.ACLOperation{kmsg.ACLOperationRead, kmsg.ACLOperationDescribe, kmsg.ACLOperationDescribeConfigs}
	want := map[string][]kmsg.ACLOperation{
		topology.Events.Name:      written,
		topology.Inventory.Name:   written,
		topology.Status.Name:      written,
		topology.Assessments.Name: written,
		topology.Gateways.Name:    written,
		topology.Refusals.Name:    written,
		topology.Agents.Name:      followed,
	}
	for name, operations := range want {
		slices.Sort(operations)
		got := touched[name]
		slices.Sort(got)
		if !slices.Equal(got, operations) {
			t.Errorf("the gateway is granted %v on %s and needs %v", got, name, operations)
		}
	}
	if len(touched) != len(want) {
		t.Errorf("the gateway is granted %d topics and touches %d", len(touched), len(want))
	}
}

func TestAGrantNamesTheTopicsTheDeploymentConfigured(t *testing.T) {
	topology := declared(t, map[string]string{"SEAGULL_BACKBONE_EVENTS_TOPIC": "tenant-a.events"})
	for _, grant := range topology.Grants() {
		for _, permission := range grant.Permissions() {
			if permission.Name == "security.events.raw" {
				t.Errorf("%s is granted the default events topic after the deployment renamed it", grant.Component)
			}
		}
	}
	engine := topology.Grants()[2]
	if engine.Component != AnalysisEngine || !slices.Contains(engine.Permissions(), Permission{Resource: kmsg.ACLResourceTypeTopic, Name: "tenant-a.events", Operation: kmsg.ACLOperationRead}) {
		t.Errorf("the engine is not granted reading the events topic the deployment named")
	}
}

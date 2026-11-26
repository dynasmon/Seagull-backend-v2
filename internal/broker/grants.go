package broker

import (
	"sort"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// A component reaches the backbone as itself: its principal and its consumer
// group are its name, so two processes cannot share a group, and what it may do
// there is its grant and nothing else.
type Component string

const (
	IngestGateway        Component = "ingest-gateway"
	ControlAPI           Component = "control-api"
	AnalysisEngine       Component = "analysis-engine"
	EventWriter          Component = "event-writer"
	DetectionWriter      Component = "detection-writer"
	AlertWriter          Component = "alert-writer"
	InventoryProjector   Component = "inventory-projector"
	StatusProjector      Component = "status-projector"
	FleetJudge           Component = "fleet-judge"
	AgentFindingWriter   Component = "agent-finding-writer"
	AssessmentProjector  Component = "assessment-projector"
	AdvisoryImporter     Component = "advisory-importer"
	AdvisoryWriter       Component = "advisory-writer"
	FindingWriter        Component = "finding-writer"
	VulnerabilityMatcher Component = "vulnerability-matcher"
	AuditWriter          Component = "audit-writer"
)

func (c Component) Principal() string { return "User:" + string(c) }

func (c Component) Group() string { return string(c) }

// Consumes is read in the component's own group, which commits its position;
// Follows is read whole from the start with no group, as a state log is; Observes
// names the groups whose committed positions the component reads.
type Grant struct {
	Component Component
	Writes    []Topic
	Consumes  []Topic
	Follows   []Topic
	Observes  []Component
}

func (t Topology) Grants() []Grant {
	return []Grant{
		{Component: IngestGateway, Writes: []Topic{t.Events, t.Inventory, t.Status, t.Assessments, t.Gateways, t.Refusals}, Follows: []Topic{t.Agents}},
		{Component: ControlAPI, Writes: []Topic{t.Agents, t.AgentFindings, t.Rulesets, t.Audit}, Follows: []Topic{t.Rulesets}},
		{Component: AnalysisEngine, Writes: []Topic{t.Detections}, Consumes: []Topic{t.Events}, Follows: []Topic{t.Rulesets}},
		{Component: EventWriter, Writes: []Topic{t.Quarantine}, Consumes: []Topic{t.Events}},
		{Component: DetectionWriter, Writes: []Topic{t.DetectionsQuarantine}, Consumes: []Topic{t.Detections}},
		{Component: AlertWriter, Consumes: []Topic{t.Detections}},
		{Component: InventoryProjector, Writes: []Topic{t.InventoryQuarantine}, Consumes: []Topic{t.Inventory}},
		{Component: StatusProjector, Writes: []Topic{t.StatusQuarantine}, Consumes: []Topic{t.Status}},
		{Component: FleetJudge, Writes: []Topic{t.AgentFindings}, Follows: []Topic{t.Status, t.Agents, t.Gateways, t.AgentFindings, t.Refusals}},
		{Component: AgentFindingWriter, Writes: []Topic{t.AgentFindingsQuarantine}, Consumes: []Topic{t.AgentFindings}},
		{Component: AssessmentProjector, Writes: []Topic{t.AssessmentsQuarantine}, Consumes: []Topic{t.Assessments}},
		{Component: AdvisoryImporter, Writes: []Topic{t.Advisories}, Follows: []Topic{t.Advisories}},
		{Component: AdvisoryWriter, Writes: []Topic{t.AdvisoriesQuarantine}, Consumes: []Topic{t.Advisories}},
		{Component: FindingWriter, Writes: []Topic{t.FindingsQuarantine}, Consumes: []Topic{t.Findings}},
		{
			Component: VulnerabilityMatcher,
			Writes:    []Topic{t.Findings},
			Consumes:  []Topic{t.Inventory, t.Advisories},
			Observes:  []Component{InventoryProjector, AdvisoryWriter, FindingWriter},
		},
		{Component: AuditWriter, Writes: []Topic{t.AuditQuarantine}, Consumes: []Topic{t.Audit}},
	}
}

type Permission struct {
	Resource  kmsg.ACLResourceType
	Name      string
	Operation kmsg.ACLOperation
}

// Every topic a component touches is also described and has its configuration
// read, because every process verifies the topics it uses before it serves.
func (g Grant) Permissions() []Permission {
	held := map[Permission]struct{}{}
	topic := func(name string, operations ...kmsg.ACLOperation) {
		for _, operation := range append(operations, kmsg.ACLOperationDescribe, kmsg.ACLOperationDescribeConfigs) {
			held[Permission{Resource: kmsg.ACLResourceTypeTopic, Name: name, Operation: operation}] = struct{}{}
		}
	}
	group := func(name string, operations ...kmsg.ACLOperation) {
		for _, operation := range operations {
			held[Permission{Resource: kmsg.ACLResourceTypeGroup, Name: name, Operation: operation}] = struct{}{}
		}
	}
	for _, written := range g.Writes {
		topic(written.Name, kmsg.ACLOperationWrite)
	}
	for _, read := range append(append([]Topic{}, g.Consumes...), g.Follows...) {
		topic(read.Name, kmsg.ACLOperationRead)
	}
	if len(g.Consumes) > 0 {
		group(g.Component.Group(), kmsg.ACLOperationRead, kmsg.ACLOperationDescribe)
	}
	for _, observed := range g.Observes {
		group(observed.Group(), kmsg.ACLOperationDescribe)
	}

	permissions := make([]Permission, 0, len(held))
	for permission := range held {
		permissions = append(permissions, permission)
	}
	sort.Slice(permissions, func(i, j int) bool {
		a, b := permissions[i], permissions[j]
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Operation < b.Operation
	})
	return permissions
}

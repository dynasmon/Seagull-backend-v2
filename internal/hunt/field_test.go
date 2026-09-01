package hunt_test

import (
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
)

// Every field of each contract a query may name, which is every field the store
// keeps of it. A leaf added to the contract fails this until it is listed, which
// is the rule running from the contract towards the query and never the other
// way: a caller can ask about anything the platform stored and nothing else.
var addressable = map[hunt.Dataset][]hunt.Field{
	hunt.Events: {
		"authentication.activity",
		"authentication.method",
		"authentication.network.destination.ip",
		"authentication.network.destination.port",
		"authentication.network.source.ip",
		"authentication.network.source.port",
		"authentication.network.transport",
		"authentication.outcome",
		"authentication.outcome_reason",
		"authentication.raw_record",
		"authentication.service.name",
		"authentication.service.protocol",
		"authentication.user.domain",
		"authentication.user.name",
		"authentication.user.uid",
		"collection.collector",
		"collection.sequence",
		"collection.source",
		"event_class",
		"event_id",
		"origin.agent_id",
		"origin.host.architecture",
		"origin.host.hostname",
		"origin.host.ip",
		"origin.host.os",
		"origin.tenant_id",
		"reception.batch_id",
		"reception.gateway",
		"reception.ingest_time",
		"schema_version",
		"time.event_time",
		"time.observed_time",
	},
	hunt.Detections: {
		"aggregation.count",
		"aggregation.first_event_time",
		"aggregation.group.absent",
		"aggregation.group.field",
		"aggregation.group.value",
		"aggregation.saturated",
		"aggregation.threshold",
		"detected_time",
		"detection_id",
		"event_class",
		"event_time",
		"evidence.absent",
		"evidence.field",
		"evidence.held",
		"evidence.negated",
		"evidence.operator",
		"origin.agent_id",
		"origin.host.architecture",
		"origin.host.hostname",
		"origin.host.ip",
		"origin.host.os",
		"origin.tenant_id",
		"rule.id",
		"rule.name",
		"rule.revision",
		"rule.source.catalogue",
		"rule.source.identifier",
		"ruleset_id",
		"schema_version",
		"severity",
		"source_event_ids",
		"technique.id",
		"technique.name",
		"technique.tactic",
	},
}

func TestEveryStoredFieldCanBeAskedAbout(t *testing.T) {
	for dataset, expected := range addressable {
		if got := hunt.Fields(dataset); !slices.Equal(got, expected) {
			t.Errorf("%s addresses %d fields and the contract declares %d:\n got %v\nwant %v",
				dataset, len(got), len(expected), got, expected)
		}
	}
}

// A rule cannot address time and a query has to: the whole point of a hunt is a
// window, and the store keeps every instant the contract carries.
func TestTimeIsAddressable(t *testing.T) {
	for _, field := range []hunt.Field{"time.event_time", "time.observed_time", "reception.ingest_time"} {
		if kind, declared := hunt.KindOf(hunt.Events, field); !declared || kind != hunt.Instant {
			t.Errorf("%s is %q and declared=%v, wanted an instant", field, kind, declared)
		}
	}
}

func TestAFieldKeptAsAListSaysSo(t *testing.T) {
	for _, field := range []hunt.Field{"source_event_ids", "evidence.field", "evidence.held", "evidence.absent"} {
		if !hunt.Repeated(hunt.Detections, field) {
			t.Errorf("%s is kept as a list and the vocabulary does not say so", field)
		}
	}
	if hunt.Repeated(hunt.Detections, "rule.id") {
		t.Error("rule.id is one value per detection")
	}
}

// A choice is offered the way a person says it, and the value the contract uses
// for nothing at all is not offered: the store writes an empty column for it, so
// `not present` is the question that finds it.
func TestAChoiceIsOfferedTheWayItIsWritten(t *testing.T) {
	outcomes := hunt.ChoicesOf(hunt.Events, "authentication.outcome")
	if !slices.Equal(outcomes, []string{"success", "failure"}) {
		t.Errorf("authentication.outcome offers %v", outcomes)
	}
	if slices.Contains(hunt.ChoicesOf(hunt.Detections, "severity"), "unspecified") {
		t.Error("severity offers the unspecified value, which the store never writes")
	}
}

func TestADatasetNobodyDeclaredIsNotKnown(t *testing.T) {
	if hunt.Known("alerts") {
		t.Error("alerts is answerable and no store holds one")
	}
	if fields := hunt.Fields("alerts"); len(fields) != 0 {
		t.Errorf("alerts addresses %v", fields)
	}
}

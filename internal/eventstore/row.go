package eventstore

import (
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The contract reaches the year 9999 and the store does not. Outside these
// bounds UnixNano wraps silently instead of failing.
var (
	epoch    = time.Unix(0, 0).UTC()
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

type Row struct {
	EventID       string
	SchemaVersion uint32
	EventClass    string
	EventTime     time.Time
	ObservedTime  time.Time
	IngestTime    time.Time

	TenantID         string
	AgentID          string
	HostHostname     string
	HostIP           string
	HostOS           string
	HostArchitecture string

	Collector string
	Source    string
	Sequence  uint64

	Gateway string
	BatchID string

	AuthActivity        string
	AuthOutcome         string
	AuthOutcomeReason   string
	AuthMethod          string
	AuthUserName        string
	AuthUserDomain      string
	AuthUserUID         string
	AuthServiceName     string
	AuthServiceProtocol string
	AuthSourceIP        string
	AuthSourcePort      uint16
	AuthDestinationIP   string
	AuthDestinationPort uint16
	AuthTransport       string
	AuthRawRecord       string
}

// Every contract leaf this projection keeps. A field added to the contract fails
// the coverage test until it is listed here.
var carried = []string{
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
}

func Project(record *eventv1.Event) Row {
	authentication := record.GetAuthentication()
	network := authentication.GetNetwork()

	return Row{
		EventID:       record.GetEventId(),
		SchemaVersion: record.GetSchemaVersion(),
		EventClass:    name(record.GetEventClass().String(), "EVENT_CLASS_"),
		EventTime:     instant(record.GetTime().GetEventTime()),
		ObservedTime:  instant(record.GetTime().GetObservedTime()),
		IngestTime:    instant(record.GetReception().GetIngestTime()),

		TenantID:         record.GetOrigin().GetTenantId(),
		AgentID:          record.GetOrigin().GetAgentId(),
		HostHostname:     record.GetOrigin().GetHost().GetHostname(),
		HostIP:           record.GetOrigin().GetHost().GetIp(),
		HostOS:           record.GetOrigin().GetHost().GetOs(),
		HostArchitecture: record.GetOrigin().GetHost().GetArchitecture(),

		Collector: record.GetCollection().GetCollector(),
		Source:    record.GetCollection().GetSource(),
		Sequence:  record.GetCollection().GetSequence(),

		Gateway: record.GetReception().GetGateway(),
		BatchID: record.GetReception().GetBatchId(),

		AuthActivity:        name(authentication.GetActivity().String(), "ACTIVITY_"),
		AuthOutcome:         name(authentication.GetOutcome().String(), "OUTCOME_"),
		AuthOutcomeReason:   authentication.GetOutcomeReason(),
		AuthMethod:          authentication.GetMethod(),
		AuthUserName:        authentication.GetUser().GetName(),
		AuthUserDomain:      authentication.GetUser().GetDomain(),
		AuthUserUID:         authentication.GetUser().GetUid(),
		AuthServiceName:     authentication.GetService().GetName(),
		AuthServiceProtocol: authentication.GetService().GetProtocol(),
		AuthSourceIP:        network.GetSource().GetIp(),
		AuthSourcePort:      port(network.GetSource()),
		AuthDestinationIP:   network.GetDestination().GetIp(),
		AuthDestinationPort: port(network.GetDestination()),
		AuthTransport:       name(network.GetTransport().String(), "TRANSPORT_"),
		AuthRawRecord:       authentication.GetRawRecord(),
	}
}

func name(value, prefix string) string {
	trimmed := strings.TrimPrefix(value, prefix)
	if trimmed == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(trimmed)
}

// Absent is the epoch, not the year one, which the column cannot hold. Only
// reception can be absent on a record that passed the contract.
func instant(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return epoch
	}
	return value.AsTime().UTC()
}

// Checked before the batch is built, so one unrepresentable record is refused to
// quarantine rather than failing the batch it shares.
func storable(row Row) error {
	if err := representable("time.event_time", row.EventTime); err != nil {
		return err
	}
	if err := representable("time.observed_time", row.ObservedTime); err != nil {
		return err
	}
	return representable("reception.ingest_time", row.IngestTime)
}

func representable(field string, at time.Time) error {
	if at.Before(earliest) || at.After(latest) {
		return fmt.Errorf("%s is outside the %s..%s the store can hold",
			field, earliest.Format(time.DateOnly), latest.Format(time.DateOnly))
	}
	return nil
}

func port(endpoint *eventv1.Endpoint) uint16 {
	value := endpoint.GetPort()
	if value > math.MaxUint16 {
		return 0
	}
	return uint16(value)
}

package eventstore

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The inverse of Project. The store is a materialisation of what crossed the
// backbone, so what is read back out of it is the contract message again and not
// a shape of the store's own: a reader never learns a second vocabulary, and the
// round trip is a test rather than a claim.
func Restore(row Row) *eventv1.Event {
	record := &eventv1.Event{
		EventId:       row.EventID,
		SchemaVersion: row.SchemaVersion,
		EventClass:    eventv1.EventClass(enum(eventv1.EventClass_value, "EVENT_CLASS_", row.EventClass)),
		Time: &eventv1.Timestamps{
			EventTime:    moment(row.EventTime),
			ObservedTime: moment(row.ObservedTime),
		},
		Origin: &eventv1.Origin{
			TenantId: row.TenantID,
			AgentId:  row.AgentID,
			Host: &eventv1.Host{
				Hostname:     row.HostHostname,
				Ip:           row.HostIP,
				Os:           row.HostOS,
				Architecture: row.HostArchitecture,
			},
		},
		Collection: &eventv1.Collection{
			Collector: row.Collector,
			Source:    row.Source,
			Sequence:  row.Sequence,
		},
		Reception: &eventv1.Reception{
			IngestTime: moment(row.IngestTime),
			Gateway:    row.Gateway,
			BatchId:    row.BatchID,
		},
	}

	if record.GetEventClass() == eventv1.EventClass_EVENT_CLASS_AUTHENTICATION {
		record.Body = &eventv1.Event_Authentication{Authentication: authentication(row)}
	}
	return record
}

func authentication(row Row) *eventv1.Authentication {
	return &eventv1.Authentication{
		Activity:      eventv1.Authentication_Activity(enum(eventv1.Authentication_Activity_value, "ACTIVITY_", row.AuthActivity)),
		Outcome:       eventv1.Outcome(enum(eventv1.Outcome_value, "OUTCOME_", row.AuthOutcome)),
		OutcomeReason: row.AuthOutcomeReason,
		Method:        row.AuthMethod,
		User: &eventv1.User{
			Name:   row.AuthUserName,
			Domain: row.AuthUserDomain,
			Uid:    row.AuthUserUID,
		},
		Service: &eventv1.Service{
			Name:     row.AuthServiceName,
			Protocol: row.AuthServiceProtocol,
		},
		Network: &eventv1.Network{
			Source:      &eventv1.Endpoint{Ip: row.AuthSourceIP, Port: uint32(row.AuthSourcePort)},
			Destination: &eventv1.Endpoint{Ip: row.AuthDestinationIP, Port: uint32(row.AuthDestinationPort)},
			Transport:   eventv1.Transport(enum(eventv1.Transport_value, "TRANSPORT_", row.AuthTransport)),
		},
		RawRecord: row.AuthRawRecord,
	}
}

// The store writes an enumeration the way a person says it and writes nothing at
// all for the zero value, so the name is rebuilt from the contract rather than
// from a table this file would have to keep in step.
func enum(declared map[string]int32, prefix, stored string) int32 {
	if stored == "" {
		return 0
	}
	return declared[prefix+strings.ToUpper(stored)]
}

// Absence was written as the epoch on the way in and is absence again on the way
// out: a record the contract accepted never carries an instant from 1970.
func moment(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() || at.Equal(epoch) {
		return nil
	}
	return timestamppb.New(at)
}

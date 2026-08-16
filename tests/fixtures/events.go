package fixtures

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type SSHAuthentication struct {
	EventID    string
	AgentID    string
	Hostname   string
	At         time.Time
	Username   string
	SourceIP   string
	SourcePort uint32
	Outcome    eventv1.Outcome
	Reason     string
	Method     string
	Sequence   uint64
}

func (s SSHAuthentication) Event() *eventv1.Event {
	if s.EventID == "" {
		s.EventID = "11111111-2222-3333-4444-555555555555"
	}
	if s.AgentID == "" {
		s.AgentID = "dev-agent-01"
	}
	if s.At.IsZero() {
		s.At = time.Now().UTC()
	}
	if s.Username == "" {
		s.Username = "root"
	}
	if s.SourceIP == "" {
		s.SourceIP = "203.0.113.10"
	}
	if s.SourcePort == 0 {
		s.SourcePort = 54321
	}
	if s.Outcome == eventv1.Outcome_OUTCOME_UNSPECIFIED {
		s.Outcome = eventv1.Outcome_OUTCOME_FAILURE
	}
	if s.Reason == "" {
		s.Reason = "failed_password"
	}
	if s.Method == "" {
		s.Method = "password"
	}

	at := timestamppb.New(s.At)
	return &eventv1.Event{
		EventId:       s.EventID,
		SchemaVersion: event.SchemaVersion,
		EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:          &eventv1.Timestamps{EventTime: at, ObservedTime: at},
		Origin: &eventv1.Origin{
			AgentId:  s.AgentID,
			TenantId: "default",
			Host:     &eventv1.Host{Hostname: s.Hostname, Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{
			Collector: "ssh.authlog",
			Source:    "/var/log/auth.log",
			Sequence:  s.Sequence,
		},
		Body: &eventv1.Event_Authentication{
			Authentication: &eventv1.Authentication{
				Activity:      eventv1.Authentication_ACTIVITY_LOGON,
				Outcome:       s.Outcome,
				OutcomeReason: s.Reason,
				Method:        s.Method,
				User:          &eventv1.User{Name: s.Username},
				Service:       &eventv1.Service{Name: "sshd", Protocol: "ssh"},
				Network: &eventv1.Network{
					Source:      &eventv1.Endpoint{Ip: s.SourceIP, Port: s.SourcePort},
					Destination: &eventv1.Endpoint{Ip: "198.51.100.5", Port: 22},
					Transport:   eventv1.Transport_TRANSPORT_TCP,
				},
				RawRecord: "Failed password for root from 203.0.113.10 port 54321 ssh2",
			},
		},
	}
}

func Batch(batchID string, events ...*eventv1.Event) *ingestv1.EventBatch {
	return &ingestv1.EventBatch{
		BatchId:         batchID,
		ProtocolVersion: protocol.Version,
		Events:          events,
	}
}

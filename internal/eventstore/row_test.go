package eventstore

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const timestampMessage = "google.protobuf.Timestamp"

// The rule runs from the contract towards the store, never the other way, so
// telemetry cannot start arriving and quietly stop being stored.
func TestTheContractCannotGrowWithoutTheStoreNoticing(t *testing.T) {
	walked := leaves((&eventv1.Event{}).ProtoReflect().Descriptor(), "")
	slices.Sort(walked)

	stored := slices.Clone(carried)
	slices.Sort(stored)

	if slices.Equal(walked, stored) {
		return
	}
	for _, path := range walked {
		if !slices.Contains(stored, path) {
			t.Errorf("the contract carries %s and the store does not keep it", path)
		}
	}
	for _, path := range stored {
		if !slices.Contains(walked, path) {
			t.Errorf("the store claims to keep %s and the contract has no such field", path)
		}
	}
}

// A repeated or mapped message is a leaf on purpose: how a collection is stored
// is a decision, and undecided fields have to fail here.
func leaves(message protoreflect.MessageDescriptor, prefix string) []string {
	var paths []string
	fields := message.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		path := prefix + string(field.Name())

		nested := field.Kind() == protoreflect.MessageKind &&
			!field.IsList() && !field.IsMap() &&
			string(field.Message().FullName()) != timestampMessage
		if nested {
			paths = append(paths, leaves(field.Message(), path+".")...)
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func TestADeclaredFieldActuallyLands(t *testing.T) {
	row := Project(populated())

	value := reflect.ValueOf(row)
	for index := range value.NumField() {
		if value.Field(index).IsZero() {
			t.Errorf("%s stays at its zero value although the contract set it",
				value.Type().Field(index).Name)
		}
	}
}

func TestAnEnumIsStoredUnderItsOwnNameWithoutThePrefix(t *testing.T) {
	row := Project(populated())

	for _, expected := range []struct {
		field string
		want  string
		got   string
	}{
		{"event_class", "authentication", row.EventClass},
		{"authentication.activity", "logon", row.AuthActivity},
		{"authentication.outcome", "failure", row.AuthOutcome},
		{"authentication.network.transport", "tcp", row.AuthTransport},
	} {
		if expected.got != expected.want {
			t.Errorf("%s reached the store as %q, want %q", expected.field, expected.got, expected.want)
		}
	}
}

func TestAnUnspecifiedEnumIsStoredAsAbsent(t *testing.T) {
	row := Project(&eventv1.Event{})

	if row.EventClass != "" || row.AuthActivity != "" || row.AuthOutcome != "" || row.AuthTransport != "" {
		t.Fatalf("an unspecified enum did not reach the store as absent: %+v", row)
	}
}

func TestAnAbsentTimestampIsStoredAsTheEpoch(t *testing.T) {
	row := Project(&eventv1.Event{})

	if !row.IngestTime.Equal(epoch) {
		t.Fatalf("an absent ingest_time reached the store as %s, want the epoch", row.IngestTime)
	}
	if err := storable(row); err != nil {
		t.Fatalf("a record without reception is not storable: %v", err)
	}
}

// Left alone the driver folds such an instant into a wrapped-around one, so the
// record is refused to quarantine instead.
func TestAnInstantTheStoreCannotHoldIsNotStorable(t *testing.T) {
	for _, testCase := range []struct {
		name string
		at   time.Time
	}{
		{"after the store's window", time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"before the store's window", time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			record := populated()
			record.Time.EventTime = timestamppb.New(testCase.at)

			if err := storable(Project(record)); err == nil {
				t.Fatalf("%s was accepted as storable", testCase.at)
			}
		})
	}
}

func TestAPortAboveTheStoresWidthIsNotInvented(t *testing.T) {
	record := populated()
	record.GetAuthentication().GetNetwork().GetSource().Port = 1 << 20

	if got := Project(record).AuthSourcePort; got != 0 {
		t.Fatalf("a port outside the contract's range reached the store as %d", got)
	}
}

// Every contract leaf set to a non-zero value. Not taken from tests/fixtures,
// which exists to be realistic rather than complete.
func populated() *eventv1.Event {
	at := timestamppb.New(time.Date(2026, time.August, 17, 10, 30, 0, 0, time.UTC))

	return &eventv1.Event{
		EventId:       "11111111-2222-4333-8444-555555555555",
		SchemaVersion: 1,
		EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:          &eventv1.Timestamps{EventTime: at, ObservedTime: at},
		Origin: &eventv1.Origin{
			TenantId: "acme",
			AgentId:  "web-01",
			Host: &eventv1.Host{
				Hostname:     "web-01.acme.example",
				Ip:           "198.51.100.7",
				Os:           "linux",
				Architecture: "amd64",
			},
		},
		Collection: &eventv1.Collection{
			Collector: "ssh.authlog",
			Source:    "/var/log/auth.log",
			Sequence:  42,
		},
		Reception: &eventv1.Reception{
			IngestTime: at,
			Gateway:    "ingest-gateway",
			BatchId:    "batch-1",
		},
		Body: &eventv1.Event_Authentication{
			Authentication: &eventv1.Authentication{
				Activity:      eventv1.Authentication_ACTIVITY_LOGON,
				Outcome:       eventv1.Outcome_OUTCOME_FAILURE,
				OutcomeReason: "failed_password",
				Method:        "password",
				User:          &eventv1.User{Name: "root", Domain: "acme", Uid: "0"},
				Service:       &eventv1.Service{Name: "sshd", Protocol: "ssh"},
				Network: &eventv1.Network{
					Source:      &eventv1.Endpoint{Ip: "203.0.113.10", Port: 54321},
					Destination: &eventv1.Endpoint{Ip: "198.51.100.5", Port: 22},
					Transport:   eventv1.Transport_TRANSPORT_TCP,
				},
				RawRecord: "Failed password for root from 203.0.113.10 port 54321 ssh2",
			},
		},
	}
}

package event_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var policy = event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour}

func now() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }

func valid() *eventv1.Event {
	return fixtures.SSHAuthentication{At: now().Add(-time.Second)}.Event()
}

func violationField(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected a violation")
	}
	var violation *event.Violation
	if !errors.As(err, &violation) {
		t.Fatalf("expected a typed violation, got %T", err)
	}
	return violation.Field
}

func TestWellFormedEventIsAccepted(t *testing.T) {
	if err := event.Validate(valid(), now(), policy); err != nil {
		t.Fatalf("unexpected violation: %v", err)
	}
}

func TestEventIdentityIsRequired(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"too short": "abc",
		"unsafe":    "id with spaces and $ signs",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			record := valid()
			record.EventId = id
			if field := violationField(t, event.Validate(record, now(), policy)); field != "event_id" {
				t.Fatalf("expected event_id to be named, got %q", field)
			}
		})
	}
}

func TestSchemaVersionOutsideTheSupportedRangeIsRefused(t *testing.T) {
	record := valid()
	record.SchemaVersion = event.MaxSchemaVersion + 1

	if field := violationField(t, event.Validate(record, now(), policy)); field != "schema_version" {
		t.Fatalf("expected schema_version to be named, got %q", field)
	}
}

func TestBothProducerTimestampsAreRequired(t *testing.T) {
	record := valid()
	record.Time.ObservedTime = nil

	if field := violationField(t, event.Validate(record, now(), policy)); field != "time.observed_time" {
		t.Fatalf("expected time.observed_time to be named, got %q", field)
	}
}

func TestEventFromTheFutureBeyondTheSkewWindowIsRefused(t *testing.T) {
	record := valid()
	record.Time.EventTime = timestamppb.New(now().Add(policy.MaxClockSkew + time.Minute))

	err := event.Validate(record, now(), policy)
	if field := violationField(t, err); field != "time.event_time" {
		t.Fatalf("expected time.event_time to be named, got %q", field)
	}
	if !strings.Contains(err.Error(), "ahead of the platform clock") {
		t.Fatalf("the reason does not explain the refusal: %v", err)
	}
}

func TestEventOlderThanTheAdmissionWindowIsRefused(t *testing.T) {
	record := valid()
	record.Time.EventTime = timestamppb.New(now().Add(-policy.MaxAge - time.Hour))

	if field := violationField(t, event.Validate(record, now(), policy)); field != "time.event_time" {
		t.Fatalf("expected time.event_time to be named, got %q", field)
	}
}

func TestDelayedButRecentEventIsAccepted(t *testing.T) {
	record := valid()
	record.Time.EventTime = timestamppb.New(now().Add(-48 * time.Hour))
	record.Time.ObservedTime = timestamppb.New(now().Add(-time.Minute))

	if err := event.Validate(record, now(), policy); err != nil {
		t.Fatalf("delayed telemetry must stay admissible: %v", err)
	}
}

func TestAgentIdentityMustMatchTheIdentifierShape(t *testing.T) {
	record := valid()
	record.Origin.AgentId = "../../etc/passwd"

	if field := violationField(t, event.Validate(record, now(), policy)); field != "origin.agent_id" {
		t.Fatalf("expected origin.agent_id to be named, got %q", field)
	}
}

func TestTenantIdentityIsRequired(t *testing.T) {
	record := valid()
	record.Origin.TenantId = ""

	if field := violationField(t, event.Validate(record, now(), policy)); field != "origin.tenant_id" {
		t.Fatalf("expected origin.tenant_id to be named, got %q", field)
	}
}

func TestCollectorIsRequired(t *testing.T) {
	record := valid()
	record.Collection.Collector = ""

	if field := violationField(t, event.Validate(record, now(), policy)); field != "collection.collector" {
		t.Fatalf("expected collection.collector to be named, got %q", field)
	}
}

func TestBodyMustMatchTheDeclaredClass(t *testing.T) {
	record := valid()
	record.Body = nil

	if field := violationField(t, event.Validate(record, now(), policy)); field != "authentication" {
		t.Fatalf("expected authentication to be named, got %q", field)
	}
}

func TestUnspecifiedClassIsRefused(t *testing.T) {
	record := valid()
	record.EventClass = eventv1.EventClass_EVENT_CLASS_UNSPECIFIED

	if field := violationField(t, event.Validate(record, now(), policy)); field != "event_class" {
		t.Fatalf("expected event_class to be named, got %q", field)
	}
}

func TestAddressesMustParse(t *testing.T) {
	record := valid()
	record.GetAuthentication().Network.Source.Ip = "not-an-address"

	field := violationField(t, event.Validate(record, now(), policy))
	if field != "authentication.network.source.ip" {
		t.Fatalf("expected the source address to be named, got %q", field)
	}
}

func TestOversizedTextIsRefusedAtTheBoundary(t *testing.T) {
	record := valid()
	record.GetAuthentication().RawRecord = strings.Repeat("A", event.MaxRawRecordLength+1)

	field := violationField(t, event.Validate(record, now(), policy))
	if field != "authentication.raw_record" {
		t.Fatalf("expected authentication.raw_record to be named, got %q", field)
	}
}

func TestTextAtTheLimitIsAccepted(t *testing.T) {
	record := valid()
	record.GetAuthentication().RawRecord = strings.Repeat("A", event.MaxRawRecordLength)

	if err := event.Validate(record, now(), policy); err != nil {
		t.Fatalf("a value exactly at the limit must be accepted: %v", err)
	}
}

func TestUnspecifiedAuthenticationOutcomeIsRefused(t *testing.T) {
	record := valid()
	record.GetAuthentication().Outcome = eventv1.Outcome_OUTCOME_UNSPECIFIED

	if field := violationField(t, event.Validate(record, now(), policy)); field != "authentication.outcome" {
		t.Fatalf("expected authentication.outcome to be named, got %q", field)
	}
}

func TestMissingEventIsRefusedWithoutPanicking(t *testing.T) {
	if err := event.Validate(nil, now(), policy); err == nil {
		t.Fatal("a missing event must be refused")
	}
}

package detectionstore

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const timestampMessage = "google.protobuf.Timestamp"

// The rule runs from the contract towards the store, never the other way, so a
// detection cannot start carrying something and quietly stop being kept. Unlike
// the event store, evidence is walked into rather than treated as a leaf: how it
// is stored has been decided, and it is stored field by field.
func TestTheContractCannotGrowWithoutTheDetectionStoreNoticing(t *testing.T) {
	walked := leaves((&detectionv1.Detection{}).ProtoReflect().Descriptor(), "")
	slices.Sort(walked)

	kept := slices.Clone(carried)
	slices.Sort(kept)

	if slices.Equal(walked, kept) {
		return
	}
	for _, path := range walked {
		if !slices.Contains(kept, path) {
			t.Errorf("a detection carries %s and the store does not keep it", path)
		}
	}
	for _, path := range kept {
		if !slices.Contains(walked, path) {
			t.Errorf("the store claims to keep %s and the contract has no such field", path)
		}
	}
}

func leaves(message protoreflect.MessageDescriptor, prefix string) []string {
	var paths []string
	fields := message.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		path := prefix + string(field.Name())

		nested := field.Kind() == protoreflect.MessageKind && !field.IsMap() &&
			string(field.Message().FullName()) != timestampMessage
		if nested {
			paths = append(paths, leaves(field.Message(), path+".")...)
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func populated() *detectionv1.Detection {
	at := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	return &detectionv1.Detection{
		DetectionId:   "bc84b318fe13e6f6ad86d64da0730a07",
		SchemaVersion: 1,
		Rule: &detectionv1.Rule{
			Id:       "ssh.failed_password_from_outside",
			Revision: 3,
			Name:     "Failed SSH password from outside the estate",
			Source:   &detectionv1.Source{Catalogue: "sigma", Identifier: "5013fd8a"},
		},
		RulesetId: "3538ec98f5ce3e22e8e65f47cd0344ee",
		Severity:  detectionv1.Severity_SEVERITY_MEDIUM,
		Technique: &detectionv1.Technique{
			Tactic: "credential_access", Id: "T1110.001", Name: "Brute Force: Password Guessing",
		},
		EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Origin: &eventv1.Origin{
			TenantId: "default",
			AgentId:  "dev-agent-01",
			Host:     &eventv1.Host{Hostname: "web-01", Ip: "10.0.0.5", Os: "linux", Architecture: "amd64"},
		},
		SourceEventIds: []string{"11111111-2222-3333-4444-555555555555"},
		EventTime:      timestamppb.New(at.Add(-time.Minute)),
		DetectedTime:   timestamppb.New(at),
		Evidence: []*detectionv1.Evidence{
			{Field: "authentication.outcome", Operator: "equals", Held: "failure"},
			{Field: "authentication.network.source.ip", Operator: "starts_with", Negated: true, Absent: true},
		},
	}
}

// Every field the contract set has to land somewhere, or the projection is
// dropping something the coverage list says it keeps.
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

// An enum is stored as the word an analyst reads, without the prefix protobuf
// needs to keep its names unique, and an unspecified one is stored as nothing.
func TestAnEnumIsStoredUnderItsOwnNameWithoutThePrefix(t *testing.T) {
	row := Project(populated())
	if row.Severity != "medium" {
		t.Errorf("severity is stored as %q", row.Severity)
	}
	if row.EventClass != "authentication" {
		t.Errorf("event class is stored as %q", row.EventClass)
	}

	empty := Project(&detectionv1.Detection{DetectionId: "x"})
	if empty.Severity != "" || empty.EventClass != "" {
		t.Errorf("an unspecified enum is stored as %q and %q", empty.Severity, empty.EventClass)
	}
}

// The five evidence arrays are one table read sideways. A reader zipping them is
// entitled to assume they line up, so the projection builds them together and
// the writer refuses a row where they do not.
func TestEvidenceIsStoredAsColumnsThatLineUp(t *testing.T) {
	row := Project(populated())

	widths := []int{
		len(row.EvidenceField), len(row.EvidenceOperator),
		len(row.EvidenceNegated), len(row.EvidenceHeld), len(row.EvidenceAbsent),
	}
	for _, width := range widths {
		if width != 2 {
			t.Fatalf("two pieces of evidence were projected as %v", widths)
		}
	}
	if row.EvidenceField[0] != "authentication.outcome" || row.EvidenceHeld[0] != "failure" {
		t.Errorf("the first evidence is %q holding %q", row.EvidenceField[0], row.EvidenceHeld[0])
	}
	if !row.EvidenceNegated[1] || !row.EvidenceAbsent[1] {
		t.Error("a negated question about a field the event did not carry lost one of the two")
	}

	row.EvidenceHeld = row.EvidenceHeld[:1]
	if err := storable(row); err == nil {
		t.Error("a row whose evidence arrays disagree in length was accepted")
	}
}

// A detection with no evidence and no source events is still a row: empty is not
// null, and the arrays have to be present so a reader never has to ask.
func TestEmptyCollectionsAreStoredAsEmptyRatherThanMissing(t *testing.T) {
	row := Project(&detectionv1.Detection{DetectionId: "x", EventTime: timestamppb.New(time.Now())})

	if row.SourceEventIDs == nil || row.EvidenceField == nil || row.EvidenceAbsent == nil {
		t.Error("an empty collection was projected as nil rather than as an empty array")
	}
	if err := storable(row); err != nil {
		t.Errorf("a detection with nothing in its collections was refused: %v", err)
	}
}

// The store cannot hold what the contract can express, and the record that
// cannot be held is refused on its own rather than failing the batch it shares.
func TestATimeTheStoreCannotHoldIsRefused(t *testing.T) {
	made := populated()
	made.EventTime = timestamppb.New(time.Date(9999, time.January, 1, 0, 0, 0, 0, time.UTC))

	if err := storable(Project(made)); err == nil {
		t.Error("a detection outside the range the store can hold was accepted")
	}
}

// A detection is named by what decided it, and a row with no name cannot be
// replaced by the replay that produced it.
func TestARowWithNoNameIsRefused(t *testing.T) {
	made := populated()
	made.DetectionId = ""

	if err := storable(Project(made)); err == nil {
		t.Error("a detection with no identity was accepted into a table keyed by it")
	}
}

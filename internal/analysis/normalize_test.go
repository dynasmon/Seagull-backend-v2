package analysis_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	folded    = "folded"    // trimmed, then lowercased
	named     = "named"     // a DNS name: folded, without the trailing dot
	addressed = "addressed" // one text form per address
	trimmed   = "trimmed"   // surrounding space removed and nothing else
	untouched = "untouched" // left exactly as it arrived
)

type decision struct {
	kind   string
	reason string
}

// What the engine decided about every string the contract carries, and why.
// A field missing from here fails the suite, so a string added to the contract
// cannot arrive without somebody deciding whether its representation carries
// meaning.
var decisions = map[string]decision{
	"event_id":                              {untouched, "identity the producer derived: the platform reads it and never rewrites it"},
	"reception.gateway":                     {untouched, "the platform wrote it, so it is canonical by construction"},
	"reception.batch_id":                    {untouched, "the platform wrote it, so it is canonical by construction"},
	"origin.tenant_id":                      {untouched, "assigned by the gateway from the certificate, not by a producer"},
	"origin.agent_id":                       {untouched, "assigned by the gateway from the certificate, not by a producer"},
	"origin.host.hostname":                  {named, "DNS is case insensitive and a trailing dot only says the name is absolute"},
	"origin.host.ip":                        {addressed, "one host has one address however the collector spelled it"},
	"origin.host.os":                        {folded, "a vocabulary the collector fills in, matched exactly by later stages"},
	"origin.host.architecture":              {folded, "a vocabulary the collector fills in, matched exactly by later stages"},
	"collection.collector":                  {folded, "the platform's own name for where telemetry came from"},
	"collection.source":                     {untouched, "may be a path, and a path is case sensitive"},
	"authentication.method":                 {folded, "PASSWORD and password are one method"},
	"authentication.outcome_reason":         {untouched, "a message written for a human, not a field to match on"},
	"authentication.raw_record":             {untouched, "the line as it was collected: the evidence the rest of the event was derived from"},
	"authentication.user.name":              {trimmed, "case is meaning here: a Unix account named Bob is not bob, and a merge cannot be undone"},
	"authentication.user.domain":            {folded, "a Windows domain is case insensitive"},
	"authentication.user.uid":               {trimmed, "an opaque identifier: only the space around it is representation"},
	"authentication.service.name":           {folded, "SSHD and sshd are one service"},
	"authentication.service.protocol":       {folded, "SSH and ssh are one protocol"},
	"authentication.network.source.ip":      {addressed, "one peer has one address however the collector spelled it"},
	"authentication.network.destination.ip": {addressed, "one peer has one address however the collector spelled it"},
}

func TestEveryStringInTheContractHasADecision(t *testing.T) {
	for _, path := range stringFields(t, (&eventv1.Event{}).ProtoReflect().Descriptor(), "", 0) {
		if _, decided := decisions[path]; !decided {
			t.Errorf("%s has no normalization decision: name it in normalize_test.go and normalize it, or say why its representation is meaning", path)
		}
	}
}

func TestEveryDecisionNamesAFieldTheContractCarries(t *testing.T) {
	carried := make(map[string]struct{})
	for _, path := range stringFields(t, (&eventv1.Event{}).ProtoReflect().Descriptor(), "", 0) {
		carried[path] = struct{}{}
	}
	for path := range decisions {
		if _, exists := carried[path]; !exists {
			t.Errorf("%s is decided about and the contract no longer carries it", path)
		}
	}
}

func TestEachStringIsNormalizedAsDecided(t *testing.T) {
	probes := map[string]struct{ given, want string }{
		folded:    {"  MiXeD-Case  ", "mixed-case"},
		named:     {"  WEB-01.  ", "web-01"},
		addressed: {"  ::ffff:10.0.0.5  ", "10.0.0.5"},
		trimmed:   {"  MiXeD-Case  ", "MiXeD-Case"},
		untouched: {"  MiXeD-Case  ", "  MiXeD-Case  "},
	}

	for path, decided := range decisions {
		t.Run(path, func(t *testing.T) {
			probe, defined := probes[decided.kind]
			if !defined {
				t.Fatalf("%s is decided as %q, which no probe describes", path, decided.kind)
			}

			record := &eventv1.Event{EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION}
			setString(t, record, path, probe.given)

			rewritten := canonicalise(t, record)
			if reached := getString(t, record, path); reached != probe.want {
				t.Errorf("%s reads %q after normalization and should read %q, because %s",
					path, reached, probe.want, decided.reason)
			}
			if expected := probe.given != probe.want; rewritten != expected {
				t.Errorf("normalizing %s reported rewritten=%v and changed=%v", path, rewritten, expected)
			}
		})
	}
}

// An event that arrives in the form the engine wants is not touched, which is
// what makes the counter worth reading: it says how much of the telemetry a
// deployment produces is already canonical.
func TestAnEventThatArrivesCanonicalIsNotRewritten(t *testing.T) {
	record := fixtures.SSHAuthentication{}.Event()
	before := proto.Clone(record)

	if canonicalise(t, record) {
		t.Error("a canonical event was reported as rewritten")
	}
	if !proto.Equal(before, record) {
		t.Errorf("a canonical event was changed:\nbefore %v\nafter  %v", before, record)
	}
}

func TestNormalizingAgainChangesNothing(t *testing.T) {
	record := fixtures.SSHAuthentication{
		Hostname: "WEB-01.",
		Username: "  Bob  ",
		SourceIP: "::ffff:203.0.113.10",
		Method:   "PASSWORD",
	}.Event()

	if !canonicalise(t, record) {
		t.Fatal("an event that arrived in four non-canonical forms was reported unchanged")
	}
	once := proto.Clone(record)

	if canonicalise(t, record) {
		t.Error("normalizing an already normalized event reported a rewrite")
	}
	if !proto.Equal(once, record) {
		t.Errorf("normalization is not idempotent:\nonce  %v\ntwice %v", once, record)
	}
	if name := record.GetAuthentication().GetUser().GetName(); name != "Bob" {
		t.Errorf("the account name reads %q: folding it would merge two Unix accounts", name)
	}
}

func TestEveryRouteHasACanonicalForm(t *testing.T) {
	for value, name := range eventv1.EventClass_name {
		stage, routed := analysis.StageFor(eventv1.EventClass(value))
		if !routed {
			continue
		}
		if stage.Normalize == nil {
			t.Errorf("%s is routed to %q with no canonical form: a stage without one hands raw text to detection", name, stage.Route)
		}
	}
}

func canonicalise(t *testing.T, record *eventv1.Event) bool {
	t.Helper()

	stage, routed := analysis.StageFor(record.GetEventClass())
	if !routed {
		t.Fatalf("the class %v has no stage", record.GetEventClass())
	}
	return stage.Normalize(record)
}

// Every string the contract carries, as a dotted path from the event.
func stringFields(t *testing.T, descriptor protoreflect.MessageDescriptor, prefix string, depth int) []string {
	t.Helper()
	if depth > 8 {
		t.Fatalf("%s nests deeper than this walk goes", prefix)
	}

	var paths []string
	fields := descriptor.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		if field.IsList() || field.IsMap() {
			t.Fatalf("%s%s is repeated, which this walk does not describe", prefix, field.Name())
		}
		path := prefix + string(field.Name())

		switch field.Kind() {
		case protoreflect.StringKind:
			paths = append(paths, path)
		case protoreflect.MessageKind:
			if strings.HasPrefix(string(field.Message().FullName()), "google.protobuf.") {
				continue
			}
			paths = append(paths, stringFields(t, field.Message(), path+".", depth+1)...)
		}
	}
	return paths
}

func setString(t *testing.T, record *eventv1.Event, path, value string) {
	t.Helper()

	message := record.ProtoReflect()
	segments := strings.Split(path, ".")
	for _, segment := range segments[:len(segments)-1] {
		message = message.Mutable(fieldNamed(t, message, path, segment)).Message()
	}
	message.Set(fieldNamed(t, message, path, segments[len(segments)-1]), protoreflect.ValueOfString(value))
}

func getString(t *testing.T, record *eventv1.Event, path string) string {
	t.Helper()

	message := record.ProtoReflect()
	segments := strings.Split(path, ".")
	for _, segment := range segments[:len(segments)-1] {
		message = message.Get(fieldNamed(t, message, path, segment)).Message()
	}
	return message.Get(fieldNamed(t, message, path, segments[len(segments)-1])).String()
}

func fieldNamed(t *testing.T, message protoreflect.Message, path, segment string) protoreflect.FieldDescriptor {
	t.Helper()

	field := message.Descriptor().Fields().ByName(protoreflect.Name(segment))
	if field == nil {
		t.Fatalf("%s: the contract has no field %q on %s", path, segment, message.Descriptor().FullName())
	}
	return field
}

package ingest

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

type route struct {
	name  string
	batch func() proto.Message
}

var routes = []route{
	{name: "events", batch: func() proto.Message { return &ingestv1.EventBatch{} }},
	{name: "inventory", batch: func() proto.Message { return &inventoryv1.RecordBatch{} }},
	{name: "status", batch: func() proto.Message { return &agentv1.StatusBatch{} }},
	{name: "assessments", batch: func() proto.Message { return &assessmentv1.AssessmentBatch{} }},
}

type body struct {
	name    string
	route   route
	payload []byte
}

func allocatedDecoding(t *testing.T, payload []byte, batch func() proto.Message) uint64 {
	t.Helper()

	var least uint64
	for attempt := range 3 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		decoded := batch()
		err := proto.Unmarshal(payload, decoded)
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(decoded)
		if err != nil {
			return 0
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; attempt == 0 || allocated < least {
			least = allocated
		}
	}
	return least
}

func weighed(t *testing.T, payload []byte, batch func() proto.Message) int64 {
	t.Helper()

	scale, err := newWeigher(batch())
	if err != nil {
		t.Fatalf("build the weigher: %v", err)
	}
	weight, err := scale.weigh(payload)
	if err != nil {
		t.Fatalf("weigh: %v", err)
	}
	return weight
}

func element(number protowire.Number, kind protowire.Type) []byte {
	field := protowire.AppendTag(nil, number, kind)
	switch kind {
	case protowire.BytesType:
		return protowire.AppendBytes(field, nil)
	case protowire.Fixed32Type:
		return protowire.AppendFixed32(field, 0)
	case protowire.Fixed64Type:
		return protowire.AppendFixed64(field, 0)
	default:
		return protowire.AppendVarint(field, 0)
	}
}

func repeated(one []byte, budget int) []byte {
	var held []byte
	for len(held)+len(one) <= budget {
		held = append(held, one...)
	}
	return held
}

func wireTypeOf(field protoreflect.FieldDescriptor) protowire.Type {
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.StringKind, protoreflect.BytesKind:
		return protowire.BytesType
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	default:
		return protowire.VarintType
	}
}

func wrapped(path []protowire.Number, inner []byte) []byte {
	for index := len(path) - 1; index >= 0; index-- {
		inner = protowire.AppendBytes(protowire.AppendTag(nil, path[index], protowire.BytesType), inner)
	}
	return inner
}

// Every field each route can reach, repeated at its emptiest inside the
// shortest path of empty messages that reaches it, sent with the wrong wire
// type, and beside a field its message does not declare: a contract that
// grows a field grows these bodies with it.
func hostile(t *testing.T, budget int) []body {
	t.Helper()

	var bodies []body
	for _, carried := range routes {
		type reached struct {
			message protoreflect.MessageDescriptor
			path    []protowire.Number
		}
		queue := []reached{{message: carried.batch().ProtoReflect().Descriptor()}}
		seen := map[protoreflect.FullName]bool{queue[0].message.FullName(): true}
		for len(queue) > 0 {
			at := queue[0]
			queue = queue[1:]

			undeclared := protowire.Number(1)
			for index := range at.message.Fields().Len() {
				undeclared = max(undeclared, at.message.Fields().Get(index).Number()+1)
			}
			bodies = append(bodies, body{
				name:    fmt.Sprintf("%s: %s beside an undeclared field", carried.name, at.message.FullName()),
				route:   carried,
				payload: wrapped(at.path, repeated(element(undeclared, protowire.VarintType), budget)),
			})

			fields := at.message.Fields()
			for index := range fields.Len() {
				field := fields.Get(index)
				right, wrong := wireTypeOf(field), protowire.VarintType
				if right == protowire.VarintType {
					wrong = protowire.Fixed64Type
				}
				bodies = append(bodies,
					body{
						name:    fmt.Sprintf("%s: %s repeated at its emptiest", carried.name, field.FullName()),
						route:   carried,
						payload: wrapped(at.path, repeated(element(field.Number(), right), budget)),
					},
					body{
						name:    fmt.Sprintf("%s: %s sent as the wrong wire type", carried.name, field.FullName()),
						route:   carried,
						payload: wrapped(at.path, repeated(element(field.Number(), wrong), budget)),
					},
				)
				if field.IsList() && right != protowire.BytesType {
					bodies = append(bodies, body{
						name:    fmt.Sprintf("%s: %s packed", carried.name, field.FullName()),
						route:   carried,
						payload: wrapped(at.path, protowire.AppendBytes(protowire.AppendTag(nil, field.Number(), protowire.BytesType), make([]byte, budget))),
					})
				}
				if child := field.Message(); child != nil && !seen[child.FullName()] {
					seen[child.FullName()] = true
					queue = append(queue, reached{message: child, path: append(append([]protowire.Number(nil), at.path...), field.Number())})
				}
			}
		}
	}
	return bodies
}

func honest(t *testing.T) []body {
	t.Helper()

	encode := func(message proto.Message) []byte {
		encoded, err := proto.Marshal(message)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return encoded
	}

	at := time.Date(2026, time.October, 28, 12, 0, 0, 0, time.UTC)
	events := make([]*eventv1.Event, 0, 1000)
	for index := range 1000 {
		events = append(events, fixtures.SSHAuthentication{EventID: fmt.Sprintf("ev-%09d", index), At: at, Sequence: uint64(index)}.Event())
	}
	reports := make([]*agentv1.Status, 0, 16)
	postures := make([]*assessmentv1.Assessment, 0, 16)
	for range 16 {
		reports = append(reports, fixtures.Report{At: at}.Status())
		postures = append(postures, fixtures.Posture{At: at}.Assessment())
	}

	return []body{
		{name: "a thousand authentications", route: routes[0], payload: encode(fixtures.Batch("batch-0001", events...))},
		{name: "ten thousand packages", route: routes[1], payload: encode(fixtures.InventoryBatch("batch-0002",
			fixtures.PackageScan{Packages: fixtures.DebianPackages(10_000), At: at}.Record()))},
		{name: "sixteen reports", route: routes[2], payload: encode(fixtures.StatusBatch("batch-0003", reports...))},
		{name: "sixteen assessments", route: routes[3], payload: encode(fixtures.AssessmentBatch("batch-0004", postures...))},
	}
}

func crafted(t *testing.T, budget int) []body {
	t.Helper()

	var switching []byte
	for len(switching) < budget {
		switching = append(switching, element(18, protowire.BytesType)...)
		switching = append(switching, element(17, protowire.BytesType)...)
	}

	var edges []byte
	for _, length := range []int{1, 7, 8, 9, 15, 16, 17, 24, 25, 32, 33, 48, 49, 64, 65, 128, 129, 256, 257, 512, 513, 1024, 1025, 4096, 4097, 8192, 8193} {
		identifier := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte(strings.Repeat("e", length)))
		edges = append(edges, protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), identifier)...)
	}

	raw := protowire.AppendBytes(protowire.AppendTag(nil, 15, protowire.BytesType), []byte(strings.Repeat("r", budget)))
	return []body{
		{name: "an item switching between two kinds", route: routes[1], payload: wrapped([]protowire.Number{3, 9}, switching)},
		{name: "identifiers at every allocation class edge", route: routes[0], payload: edges},
		{name: "a raw record as long as the body", route: routes[0], payload: wrapped([]protowire.Number{3, 16}, raw)},
	}
}

func TestDecodingABodyAllocatesNoMoreThanTheGatewayWeighedItAt(t *testing.T) {
	bodies := append(append(hostile(t, 16<<10+2), honest(t)...), crafted(t, 64<<10+2)...)
	for _, held := range bodies {
		allocated := allocatedDecoding(t, held.payload, held.route.batch)
		if weight := weighed(t, held.payload, held.route.batch); uint64(weight) < allocated {
			t.Errorf("%s: decoding %d bytes allocated %d and the gateway weighed them at %d", held.name, len(held.payload), allocated, weight)
		}
	}
}

func TestAnHonestBatchWeighsLittleMoreThanDecodingItAllocates(t *testing.T) {
	for _, held := range honest(t) {
		allocated := allocatedDecoding(t, held.payload, held.route.batch)
		if weight := weighed(t, held.payload, held.route.batch); uint64(weight) > 5*allocated/2 {
			t.Errorf("%s: decoding %d bytes allocated %d and the gateway weighed them at %d, so it holds room for batches nobody sent",
				held.name, len(held.payload), allocated, weight)
		}
	}
}

func TestABodyThatIsNotProtobufCannotBeWeighed(t *testing.T) {
	scale, err := newWeigher(&ingestv1.EventBatch{})
	if err != nil {
		t.Fatalf("build the weigher: %v", err)
	}
	for name, payload := range map[string][]byte{
		"a truncated length":    {0x1a, 0x05, 0x0a},
		"a field numbered zero": {0x00, 0x00},
		"a group never closed":  {0x1b},
	} {
		if _, err := scale.weigh(payload); err == nil {
			t.Errorf("%s was weighed, so it would be decoded", name)
		}
	}
}

func TestEveryBatchTheGatewayAdmitsCanBeWeighed(t *testing.T) {
	for _, carried := range routes {
		if _, err := newWeigher(carried.batch()); err != nil {
			t.Errorf("the %s route cannot weigh what it admits: %v", carried.name, err)
		}
	}
}

func TestAMessageHoldingAMapCannotBeWeighed(t *testing.T) {
	if _, err := newWeigher(&structpb.Struct{}); err == nil {
		t.Error("a message holding a map was given a weight nobody measured")
	}
}

func TestAOneofOfTheWrongWireTypeIsWeighedForTheWrapperADecoderMakesFirst(t *testing.T) {
	events := routes[0].batch
	mismatched := wrapped([]protowire.Number{3}, repeated(element(16, protowire.VarintType), 16<<10+2))
	undeclared := wrapped([]protowire.Number{3}, repeated(element(17, protowire.VarintType), 16<<10+2))
	if len(mismatched) != len(undeclared) {
		t.Fatalf("the two bodies weigh %d and %d bytes", len(mismatched), len(undeclared))
	}

	wrappers := int64(allocatedDecoding(t, mismatched, events)) - int64(allocatedDecoding(t, undeclared, events))
	if wrappers <= 0 {
		t.Fatalf("decoding a oneof of the wrong wire type allocates %d bytes more than an undeclared field, so a decoder no longer makes its wrapper first", wrappers)
	}
	if weight := weighed(t, mismatched, events) - weighed(t, undeclared, events); weight < wrappers {
		t.Errorf("the wrappers a decoder makes before reading the wire type cost %d bytes and were weighed at %d", wrappers, weight)
	}
}

func BenchmarkWeighBatch(b *testing.B) {
	at := time.Now().UTC()
	events := make([]*eventv1.Event, 0, 1000)
	for index := range 1000 {
		events = append(events, fixtures.SSHAuthentication{EventID: fmt.Sprintf("bench-%09d", index), At: at, Sequence: uint64(index)}.Event())
	}
	payload, err := proto.Marshal(fixtures.Batch("bench-batch", events...))
	if err != nil {
		b.Fatalf("encode batch: %v", err)
	}
	scale, err := newWeigher(&ingestv1.EventBatch{})
	if err != nil {
		b.Fatalf("build the weigher: %v", err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := scale.weigh(payload); err != nil {
			b.Fatalf("weigh: %v", err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/1000, "ns/event")
}

package ingest

import (
	"errors"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// What decoding a body would allocate, weighed from its wire form before any
// of it is decoded. A message costs the struct it is decoded into, a text its
// copy, a list element its slot and an undeclared field its bytes, kept as they
// arrived; a slice grown one element at a time allocates up to eight times what
// it ends up holding, and an allocation takes up to a quarter more than it asks
// for, plus sixteen bytes. Every term is a bound rather than an estimate, so a
// body of empty messages, which decodes to over a hundred times its length, is
// weighed at what it would cost and not at what it weighs.
type weigher struct {
	root *shape
}

type shape struct {
	size   int64
	dense  []*field
	sparse map[protowire.Number]*field
}

type field struct {
	wire    protowire.Type
	list    bool
	oneof   bool
	text    bool
	message *shape
}

const (
	growth         = 8
	slot           = 24
	wrapper        = 24
	indexedNumbers = 256
)

var errUnweighable = errors.New("cannot be weighed")

func newWeigher(batch proto.Message) (*weigher, error) {
	root, err := shapeOf(batch.ProtoReflect().Descriptor(), map[protoreflect.FullName]*shape{})
	if err != nil {
		return nil, err
	}
	return &weigher{root: root}, nil
}

func shapeOf(message protoreflect.MessageDescriptor, shapes map[protoreflect.FullName]*shape) (*shape, error) {
	if known, found := shapes[message.FullName()]; found {
		return known, nil
	}
	held, err := protoregistry.GlobalTypes.FindMessageByName(message.FullName())
	if err != nil {
		return nil, fmt.Errorf("%s %w: %w", message.FullName(), errUnweighable, err)
	}
	built := &shape{
		size:   allocation(int64(reflect.TypeOf(held.Zero().Interface()).Elem().Size())),
		sparse: map[protowire.Number]*field{},
	}
	shapes[message.FullName()] = built

	fields := message.Fields()
	for index := range fields.Len() {
		declared := fields.Get(index)
		if declared.IsMap() || declared.Kind() == protoreflect.GroupKind {
			return nil, fmt.Errorf("%s %w: how a decoder allocates it is not modelled", declared.FullName(), errUnweighable)
		}
		described := &field{
			wire:  wireType(declared),
			list:  declared.IsList(),
			oneof: declared.ContainingOneof() != nil,
			text:  declared.Kind() == protoreflect.StringKind || declared.Kind() == protoreflect.BytesKind,
		}
		if child := declared.Message(); child != nil {
			if described.message, err = shapeOf(child, shapes); err != nil {
				return nil, err
			}
		}
		if number := declared.Number(); number < indexedNumbers {
			for len(built.dense) <= int(number) {
				built.dense = append(built.dense, nil)
			}
			built.dense[number] = described
		} else {
			built.sparse[number] = described
		}
	}
	return built, nil
}

func (s *shape) field(number protowire.Number) *field {
	if int(number) < len(s.dense) {
		return s.dense[number]
	}
	return s.sparse[number]
}

func (w *weigher) weigh(payload []byte) (int64, error) {
	weight, err := w.root.weigh(payload, protowire.DefaultRecursionLimit)
	if err != nil {
		return 0, err
	}
	return w.root.size + weight, nil
}

func (s *shape) weigh(payload []byte, depth int) (int64, error) {
	if depth == 0 {
		return 0, errors.New("messages nest deeper than a decoder follows")
	}

	var weight int64
	for len(payload) > 0 {
		number, kind, tagged := protowire.ConsumeTag(payload)
		if tagged < 0 {
			return 0, protowire.ParseError(tagged)
		}
		var inner []byte
		var valued int
		if kind == protowire.BytesType {
			inner, valued = protowire.ConsumeBytes(payload[tagged:])
		} else {
			valued = protowire.ConsumeFieldValue(number, kind, payload[tagged:])
		}
		if valued < 0 {
			return 0, protowire.ParseError(valued)
		}
		whole := payload[:tagged+valued]
		payload = payload[tagged+valued:]

		// A decoder makes a oneof's wrapper before it reads the wire type, and
		// keeps a field of the wrong wire type as one it does not declare.
		described := s.field(number)
		if described != nil && described.oneof {
			weight += allocation(wrapper)
		}
		packed := described != nil && described.list && kind == protowire.BytesType && described.wire != protowire.BytesType
		if described == nil || (kind != described.wire && !packed) {
			weight += growth * int64(len(whole))
			continue
		}

		switch {
		case described.message != nil:
			nested, err := described.message.weigh(inner, depth-1)
			if err != nil {
				return 0, err
			}
			weight += described.message.size + nested
			if described.list {
				weight += growth * slot
			}
		case described.text:
			weight += allocation(int64(len(inner)))
			if described.list {
				weight += growth * slot
			}
		case packed:
			weight += growth * slot * int64(len(inner))
		case described.list:
			weight += growth * slot
		}
	}
	return weight, nil
}

func wireType(declared protoreflect.FieldDescriptor) protowire.Type {
	switch declared.Kind() {
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

func allocation(size int64) int64 {
	if size == 0 {
		return 0
	}
	return size + size/4 + 16
}

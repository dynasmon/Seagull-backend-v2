package fixtures

import (
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// A field number no contract declares, carried as bytes the way a producer
// speaking a newer contract, or none, would send it.
const undeclared protowire.Number = 4095

// Appends one undeclared field until the message encodes to exactly size bytes:
// a decoder keeps what it does not know and the encoder writes it again, so
// every field bound can hold and the record still weigh this much.
func Bloat(message proto.Message, size int) bool {
	tag := protowire.AppendTag(nil, undeclared, protowire.BytesType)
	missing := size - proto.Size(message)
	for length := max(0, missing-len(tag)-protowire.SizeVarint(uint64(max(0, missing)))); length <= missing; length++ {
		if len(tag)+protowire.SizeVarint(uint64(length))+length != missing {
			continue
		}
		reflected := message.ProtoReflect()
		reflected.SetUnknown(append(reflected.GetUnknown(), protowire.AppendBytes(tag, make([]byte, length))...))
		return proto.Size(message) == size
	}
	return false
}

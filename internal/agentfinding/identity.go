package agentfinding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"slices"
	"strings"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Derived and never read off the wire, so judging an episode again, after a
// restart or a replay, names the finding it named before. The digest covers the
// kind and the length of every part, so no two episodes can be spelled into each
// other by a part that contains a separator.
func ID(tenantID, agentID string, kind agentv1.Finding_Kind, episode ...string) string {
	digest := sha256.New()
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(kind))
	digest.Write(header[:])
	for _, part := range append([]string{tenantID, agentID}, episode...) {
		binary.BigEndian.PutUint64(header[:], uint64(len(part)))
		digest.Write(header[:])
		digest.Write([]byte(part))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// The contract's own names, lowercased and without their prefix, and "unknown"
// for a number it does not declare: they fill a column and label a metric, and a
// value from a newer producer must not be able to open either.
func KindName(kind agentv1.Finding_Kind) string {
	return named(agentv1.Finding_Kind_name, int32(kind), "KIND_")
}

func StateName(state agentv1.Finding_State) string {
	return named(agentv1.Finding_State_name, int32(state), "STATE_")
}

func ClosureName(closure agentv1.Finding_Closure) string {
	return named(agentv1.Finding_Closure_name, int32(closure), "CLOSURE_")
}

func Kinds() []agentv1.Finding_Kind {
	numbers := slices.Sorted(maps.Keys(agentv1.Finding_Kind_name))
	kinds := make([]agentv1.Finding_Kind, 0, len(numbers))
	for _, number := range numbers {
		if kind := agentv1.Finding_Kind(number); kind != agentv1.Finding_KIND_UNSPECIFIED {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

func named(names map[int32]string, value int32, prefix string) string {
	name, declared := names[value]
	if !declared {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, prefix))
}

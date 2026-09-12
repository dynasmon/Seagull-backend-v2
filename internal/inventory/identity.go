package inventory

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"

	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What one kind of item is, in the one place a kind is described: whether an
// asset can hold more than one, which body an item of it carries, and what
// tells two of them apart within the same asset. A kind the contract declares
// and this table does not name is refused by the suite.
type shape struct {
	singleton bool
	present   func(*inventoryv1.Item) bool
	identify  func(*inventoryv1.Item) []string
}

var shapes = map[inventoryv1.Kind]shape{
	inventoryv1.Kind_KIND_OPERATING_SYSTEM: {
		singleton: true,
		present:   func(item *inventoryv1.Item) bool { return item.GetOperatingSystem() != nil },
		identify:  func(*inventoryv1.Item) []string { return nil },
	},
	inventoryv1.Kind_KIND_KERNEL: {
		singleton: true,
		present:   func(item *inventoryv1.Item) bool { return item.GetKernel() != nil },
		identify:  func(*inventoryv1.Item) []string { return nil },
	},
	inventoryv1.Kind_KIND_HARDWARE: {
		singleton: true,
		present:   func(item *inventoryv1.Item) bool { return item.GetHardware() != nil },
		identify:  func(*inventoryv1.Item) []string { return nil },
	},
	inventoryv1.Kind_KIND_PACKAGE: {
		present: func(item *inventoryv1.Item) bool { return item.GetPackage() != nil },
		identify: func(item *inventoryv1.Item) []string {
			installed := item.GetPackage()
			return []string{installed.GetName(), installed.GetArchitecture(), installed.GetManager()}
		},
	},
	inventoryv1.Kind_KIND_SERVICE: {
		present:  func(item *inventoryv1.Item) bool { return item.GetService() != nil },
		identify: func(item *inventoryv1.Item) []string { return []string{item.GetService().GetName()} },
	},
	inventoryv1.Kind_KIND_NETWORK_INTERFACE: {
		present:  func(item *inventoryv1.Item) bool { return item.GetNetworkInterface() != nil },
		identify: func(item *inventoryv1.Item) []string { return []string{item.GetNetworkInterface().GetName()} },
	},
	inventoryv1.Kind_KIND_USER: {
		present: func(item *inventoryv1.Item) bool { return item.GetUser() != nil },
		identify: func(item *inventoryv1.Item) []string {
			account := item.GetUser()
			// The account identifier and not the name: a renamed account is the
			// same account, and a name freed and reused is a different one.
			if identifier := account.GetUid(); identifier != "" {
				return []string{identifier}
			}
			return []string{account.GetName()}
		},
	},
	inventoryv1.Kind_KIND_PROCESS: {
		present: func(item *inventoryv1.Item) bool { return item.GetProcess() != nil },
		identify: func(item *inventoryv1.Item) []string {
			running := item.GetProcess()
			started := ""
			if at := running.GetStartedAt(); at != nil {
				started = strconv.FormatInt(at.AsTime().UTC().UnixNano(), 10)
			}
			return []string{strconv.FormatUint(uint64(running.GetPid()), 10), started}
		},
	},
}

func Shaped(kind inventoryv1.Kind) bool {
	_, shaped := shapes[kind]
	return shaped
}

func Singleton(kind inventoryv1.Kind) bool {
	return shapes[kind].singleton
}

// What tells one item apart from every other of its kind on the same asset.
//
// Derived here and never read off the wire: two collectors that named the same
// package differently would otherwise leave an asset holding it twice, and a
// replay would not land on the row it wrote the first time. The digest covers
// the kind and the length of every part, so no two identities can be spelled
// into each other by a name that contains a separator.
func ItemID(kind inventoryv1.Kind, item *inventoryv1.Item) string {
	shape, shaped := shapes[kind]
	if !shaped {
		return ""
	}

	digest := sha256.New()
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(kind))
	digest.Write(header[:])
	for _, part := range shape.identify(item) {
		binary.BigEndian.PutUint64(header[:], uint64(len(part)))
		digest.Write(header[:])
		digest.Write([]byte(part))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// The contract's own name for a kind, and "unknown" for a number it does not
// declare. Bounded by the enum on purpose: it labels a metric and fills a
// column, and a kind from a newer producer must not be able to open either.
func KindName(kind inventoryv1.Kind) string {
	name, declared := inventoryv1.Kind_name[int32(kind)]
	if !declared {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, "KIND_"))
}

func ModeName(mode inventoryv1.Mode) string {
	name, declared := inventoryv1.Mode_name[int32(mode)]
	if !declared {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, "MODE_"))
}

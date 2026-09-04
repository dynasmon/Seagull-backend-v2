package detection

import (
	"slices"
	"strings"
	"sync"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// The name a rule writes for a class, which is the contract's own name with the
// enumeration's prefix taken off it: EVENT_CLASS_AUTHENTICATION is written
// `authentication`. The same short form a choice is written in, so a rule reads
// one way wherever it names the contract.
func className(class eventv1.EventClass) string {
	name, declared := eventv1.EventClass_name[int32(class)]
	if !declared {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(name, "EVENT_CLASS_"))
}

var classes = sync.OnceValue(func() map[string]eventv1.EventClass {
	named := make(map[string]eventv1.EventClass, len(eventv1.EventClass_name))
	for value := range eventv1.EventClass_name {
		class := eventv1.EventClass(value)
		if class == eventv1.EventClass_EVENT_CLASS_UNSPECIFIED {
			continue
		}
		named[className(class)] = class
	}
	return named
})

// The name a class is written under, which is empty for a class the contract
// does not declare.
func ClassName(class eventv1.EventClass) string { return className(class) }

// The class a written name stands for. Unspecified is not one of them: a rule
// that names no class reads nothing, and the contract's zero value is how an
// event says it did not say.
func ClassNamed(name string) (eventv1.EventClass, bool) {
	class, declared := classes()[name]
	return class, declared
}

// Every class a rule can be written for, sorted, so a refusal can say what was
// available instead.
func Classes() []string {
	named := classes()
	names := make([]string, 0, len(named))
	for name := range named {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

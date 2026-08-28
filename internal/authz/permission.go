// Package authz states who a caller is, what they may do and where. It decides;
// it does not authenticate and reads no policy from anywhere.
package authz

import (
	"fmt"
	"slices"
	"strings"
)

type Resource string

const (
	Events     Resource = "events"
	Detections Resource = "detections"
	Rulesets   Resource = "rulesets"
	Alerts     Resource = "alerts"
	Agents     Resource = "agents"
	Policies   Resource = "policies"
	Sessions   Resource = "sessions"
)

var resources = []Resource{Events, Detections, Rulesets, Alerts, Agents, Policies, Sessions}

func (r Resource) Valid() bool { return slices.Contains(resources, r) }

func (r Resource) String() string { return string(r) }

func Resources() []Resource { return slices.Clone(resources) }

type Action string

const (
	Read   Action = "read"
	Write  Action = "write"
	Delete Action = "delete"
)

var actions = []Action{Read, Write, Delete}

func (a Action) Valid() bool { return slices.Contains(actions, a) }

func (a Action) String() string { return string(a) }

func Actions() []Action { return slices.Clone(actions) }

type Permission struct {
	Resource Resource
	Action   Action
}

func (p Permission) Valid() bool { return p.Resource.Valid() && p.Action.Valid() }

func (p Permission) String() string { return string(p.Resource) + ":" + string(p.Action) }

// An undeclared resource or action is refused rather than kept as an opaque
// string, which would grant nothing while reading as a grant.
func ParsePermission(written string) (Permission, error) {
	resource, action, found := strings.Cut(written, ":")
	if !found {
		return Permission{}, fmt.Errorf("a permission is written `resource:action` and %q is not", written)
	}

	permission := Permission{Resource: Resource(resource), Action: Action(action)}
	if !permission.Resource.Valid() {
		return Permission{}, fmt.Errorf("%q names no resource; there are %s", resource, join(resources))
	}
	if !permission.Action.Valid() {
		return Permission{}, fmt.Errorf("%q names no action; there are %s", action, join(actions))
	}
	return permission, nil
}

func join[T ~string](values []T) string {
	written := make([]string, len(values))
	for index, value := range values {
		written[index] = string(value)
	}
	return strings.Join(written, ", ")
}

func sortPermissions(permissions []Permission) {
	slices.SortFunc(permissions, func(one, other Permission) int {
		if one.Resource != other.Resource {
			return strings.Compare(string(one.Resource), string(other.Resource))
		}
		return strings.Compare(string(one.Action), string(other.Action))
	})
}

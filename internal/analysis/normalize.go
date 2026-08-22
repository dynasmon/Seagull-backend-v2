package analysis

import (
	"net/netip"
	"strings"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

// Canonical form is about representation and never about meaning. Two records
// describing the same thing in different ways have to compare equal before a
// rule can be written against either of them, and that is all this does: it
// removes a difference the source system does not consider a difference. A
// distinction the source *does* consider real is left alone, because a stage
// that merges two things cannot un-merge them later.

// A vocabulary that is case insensitive by definition.
func fold(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

// A DNS name, without the trailing dot that makes it absolute: `WEB-01.` and
// `web-01` are one host.
func hostname(value string) string { return strings.TrimSuffix(fold(value), ".") }

// One text form per address: `::ffff:10.0.0.5` is `10.0.0.5` and
// `2001:0DB8::0001` is `2001:db8::1`. A zone survives, because it is part of
// the address. Text that is not an address at all is left as it arrived —
// something that cannot be parsed is evidence, and rewriting it destroys it.
func address(value string) string {
	trimmed := strings.TrimSpace(value)
	parsed, err := netip.ParseAddr(trimmed)
	if err != nil {
		return trimmed
	}
	return parsed.Unmap().String()
}

// Reports whether the field had to be rewritten, so a caller can say how much
// of what arrives is already canonical without comparing whole messages.
func set(field *string, canonical string) bool {
	if *field == canonical {
		return false
	}
	*field = canonical
	return true
}

// What every event carries, whatever its class. The identity the platform
// assigned — tenant, agent, gateway, batch — is not touched: it was not written
// by a producer and it is canonical by construction. Neither is
// `collection.source`, which may be a path, and a path is case sensitive.
func normalizeEnvelope(record *eventv1.Event) bool {
	rewritten := false
	if host := record.GetOrigin().GetHost(); host != nil {
		rewritten = set(&host.Hostname, hostname(host.Hostname)) || rewritten
		rewritten = set(&host.Ip, address(host.Ip)) || rewritten
		rewritten = set(&host.Os, fold(host.Os)) || rewritten
		rewritten = set(&host.Architecture, fold(host.Architecture)) || rewritten
	}
	if collection := record.GetCollection(); collection != nil {
		rewritten = set(&collection.Collector, fold(collection.Collector)) || rewritten
	}
	return rewritten
}

// The canonical form of an authentication event.
//
// `user.name` is trimmed and not folded, and the asymmetry is deliberate: a
// Windows account name is case insensitive and a Unix one is not, so folding it
// would merge two accounts on every Linux host the platform watches. Case there
// is meaning, and a rule that wants to ignore it can ask.
//
// `outcome_reason` is a message written for a human and `raw_record` is the line
// as it was collected — the evidence the rest of the event was derived from.
// Neither is a field to match on, and neither is rewritten.
func normalizeAuthentication(record *eventv1.Event) bool {
	rewritten := normalizeEnvelope(record)

	body := record.GetAuthentication()
	if body == nil {
		return rewritten
	}
	rewritten = set(&body.Method, fold(body.Method)) || rewritten

	if user := body.User; user != nil {
		rewritten = set(&user.Name, strings.TrimSpace(user.Name)) || rewritten
		rewritten = set(&user.Domain, fold(user.Domain)) || rewritten
		rewritten = set(&user.Uid, strings.TrimSpace(user.Uid)) || rewritten
	}
	if service := body.Service; service != nil {
		rewritten = set(&service.Name, fold(service.Name)) || rewritten
		rewritten = set(&service.Protocol, fold(service.Protocol)) || rewritten
	}
	if network := body.Network; network != nil {
		if source := network.Source; source != nil {
			rewritten = set(&source.Ip, address(source.Ip)) || rewritten
		}
		if destination := network.Destination; destination != nil {
			rewritten = set(&destination.Ip, address(destination.Ip)) || rewritten
		}
	}
	return rewritten
}

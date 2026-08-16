package event

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

func ValidIdentifier(value string) bool { return identifierPattern.MatchString(value) }

type Violation struct {
	Field  string
	Reason string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("%s %s", v.Field, v.Reason)
}

type Policy struct {
	MaxClockSkew time.Duration
	MaxAge       time.Duration
}

func Validate(record *eventv1.Event, now time.Time, policy Policy) error {
	if record == nil {
		return &Violation{Field: "event", Reason: "is missing"}
	}

	if err := identifier("event_id", record.GetEventId()); err != nil {
		return err
	}
	if version := record.GetSchemaVersion(); version < MinSchemaVersion || version > MaxSchemaVersion {
		return &Violation{
			Field:  "schema_version",
			Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion),
		}
	}
	if err := validateTime(record.GetTime(), now, policy); err != nil {
		return err
	}
	if err := validateOrigin(record.GetOrigin()); err != nil {
		return err
	}
	if err := validateCollection(record.GetCollection()); err != nil {
		return err
	}
	return validateBody(record)
}

func validateTime(times *eventv1.Timestamps, now time.Time, policy Policy) error {
	if times == nil {
		return &Violation{Field: "time", Reason: "is missing"}
	}
	if err := instant("time.event_time", times.GetEventTime(), now, policy); err != nil {
		return err
	}
	return instant("time.observed_time", times.GetObservedTime(), now, policy)
}

func instant(field string, value *timestamppb.Timestamp, now time.Time, policy Policy) error {
	if value == nil {
		return &Violation{Field: field, Reason: "is missing"}
	}
	if !value.IsValid() {
		return &Violation{Field: field, Reason: "is not a representable instant"}
	}
	at := value.AsTime()
	if at.After(now.Add(policy.MaxClockSkew)) {
		return &Violation{
			Field:  field,
			Reason: fmt.Sprintf("is more than %s ahead of the platform clock", policy.MaxClockSkew),
		}
	}
	if at.Before(now.Add(-policy.MaxAge)) {
		return &Violation{
			Field:  field,
			Reason: fmt.Sprintf("is older than the %s admission window", policy.MaxAge),
		}
	}
	return nil
}

func validateOrigin(origin *eventv1.Origin) error {
	if origin == nil {
		return &Violation{Field: "origin", Reason: "is missing"}
	}
	if !agentidentity.Valid(origin.GetAgentId()) {
		return &Violation{Field: "origin.agent_id", Reason: "is missing or malformed"}
	}
	if err := text("origin.tenant_id", origin.GetTenantId(), MaxTenantIDLength, true); err != nil {
		return err
	}
	host := origin.GetHost()
	if host == nil {
		return nil
	}
	if err := text("origin.host.hostname", host.GetHostname(), MaxHostnameLength, false); err != nil {
		return err
	}
	if err := address("origin.host.ip", host.GetIp()); err != nil {
		return err
	}
	if err := text("origin.host.os", host.GetOs(), MaxOperatingSystem, false); err != nil {
		return err
	}
	return text("origin.host.architecture", host.GetArchitecture(), MaxArchitectureLen, false)
}

func validateCollection(collection *eventv1.Collection) error {
	if collection == nil {
		return &Violation{Field: "collection", Reason: "is missing"}
	}
	if err := text("collection.collector", collection.GetCollector(), MaxCollectorLength, true); err != nil {
		return err
	}
	return text("collection.source", collection.GetSource(), MaxSourceLength, false)
}

func validateBody(record *eventv1.Event) error {
	switch record.GetEventClass() {
	case eventv1.EventClass_EVENT_CLASS_AUTHENTICATION:
		authentication := record.GetAuthentication()
		if authentication == nil {
			return &Violation{Field: "authentication", Reason: "is required for this event class"}
		}
		return validateAuthentication(authentication)
	default:
		return &Violation{Field: "event_class", Reason: "is unspecified or unknown"}
	}
}

func validateAuthentication(authentication *eventv1.Authentication) error {
	if authentication.GetActivity() == eventv1.Authentication_ACTIVITY_UNSPECIFIED {
		return &Violation{Field: "authentication.activity", Reason: "is unspecified"}
	}
	if authentication.GetOutcome() == eventv1.Outcome_OUTCOME_UNSPECIFIED {
		return &Violation{Field: "authentication.outcome", Reason: "is unspecified"}
	}
	if err := text("authentication.outcome_reason", authentication.GetOutcomeReason(), MaxOutcomeReasonLen, false); err != nil {
		return err
	}
	if err := text("authentication.method", authentication.GetMethod(), MaxAuthMethodLength, false); err != nil {
		return err
	}
	if err := validateUser(authentication.GetUser()); err != nil {
		return err
	}
	if err := validateService(authentication.GetService()); err != nil {
		return err
	}
	if err := validateNetwork(authentication.GetNetwork()); err != nil {
		return err
	}
	return text("authentication.raw_record", authentication.GetRawRecord(), MaxRawRecordLength, false)
}

func validateUser(user *eventv1.User) error {
	if user == nil {
		return nil
	}
	if err := text("authentication.user.name", user.GetName(), MaxUserNameLength, false); err != nil {
		return err
	}
	if err := text("authentication.user.domain", user.GetDomain(), MaxUserDomainLength, false); err != nil {
		return err
	}
	return text("authentication.user.uid", user.GetUid(), MaxUserIDLength, false)
}

func validateService(service *eventv1.Service) error {
	if service == nil {
		return nil
	}
	if err := text("authentication.service.name", service.GetName(), MaxServiceNameLength, false); err != nil {
		return err
	}
	return text("authentication.service.protocol", service.GetProtocol(), MaxProtocolLength, false)
}

func validateNetwork(network *eventv1.Network) error {
	if network == nil {
		return nil
	}
	if err := endpoint("authentication.network.source", network.GetSource()); err != nil {
		return err
	}
	return endpoint("authentication.network.destination", network.GetDestination())
}

func endpoint(field string, value *eventv1.Endpoint) error {
	if value == nil {
		return nil
	}
	if err := address(field+".ip", value.GetIp()); err != nil {
		return err
	}
	if value.GetPort() > 65535 {
		return &Violation{Field: field + ".port", Reason: "is outside 0..65535"}
	}
	return nil
}

func identifier(field, value string) error {
	if len(value) < MinEventIDLength {
		return &Violation{Field: field, Reason: fmt.Sprintf("is shorter than %d characters", MinEventIDLength)}
	}
	if !identifierPattern.MatchString(value) {
		return &Violation{Field: field, Reason: "is malformed"}
	}
	return nil
}

func text(field, value string, maximum int, required bool) error {
	if value == "" {
		if required {
			return &Violation{Field: field, Reason: "is required"}
		}
		return nil
	}
	if len(value) > maximum {
		return &Violation{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", maximum)}
	}
	return nil
}

func address(field, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > MaxAddressLength {
		return &Violation{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", MaxAddressLength)}
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return &Violation{Field: field, Reason: "is not an IP address"}
	}
	return nil
}

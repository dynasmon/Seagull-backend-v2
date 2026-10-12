package agentstatus

import (
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func Validate(report *agentv1.Status, now time.Time, policy event.Policy) error {
	if err := ValidateContract(report); err != nil {
		return err
	}
	return admissible(report.GetReportedAt().AsTime(), now, policy)
}

// Every rule that does not depend on when the report is examined, so the
// projector reads back what the gateway admitted without refusing it for age.
func ValidateContract(report *agentv1.Status) error {
	if report == nil {
		return &event.Violation{Field: "report", Reason: "is missing"}
	}
	if version := report.GetSchemaVersion(); version < MinSchemaVersion || version > MaxSchemaVersion {
		return &event.Violation{
			Field:  "schema_version",
			Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion),
		}
	}
	if !event.ValidIdentifier(report.GetInstallationId()) {
		return &event.Violation{Field: "installation_id", Reason: "is missing or malformed"}
	}
	if report.GetSequence() == 0 {
		return &event.Violation{Field: "sequence", Reason: "is missing: an installation counts its reports from 1"}
	}
	if err := required("reported_at", report.GetReportedAt()); err != nil {
		return err
	}
	if err := interval(report.GetInterval()); err != nil {
		return err
	}
	if err := event.ValidateOrigin(report.GetOrigin()); err != nil {
		return err
	}
	if err := validateRun(report.GetRun()); err != nil {
		return err
	}
	if err := validateBuild(report.GetBuild()); err != nil {
		return err
	}
	if err := declared("condition", int32(report.GetCondition()), agentv1.Status_Condition_name); err != nil {
		return err
	}
	if err := validateComponents(report.GetComponents()); err != nil {
		return err
	}
	if err := validateModules(report.GetModules()); err != nil {
		return err
	}
	if err := validateSpool(report.GetSpool()); err != nil {
		return err
	}
	if err := validateCredential(report.GetCredential()); err != nil {
		return err
	}
	if err := validateConfiguration(report.GetConfiguration()); err != nil {
		return err
	}
	if err := validatePrivileges(report.GetPrivileges()); err != nil {
		return err
	}
	return validateUpdate(report.GetUpdate())
}

func admissible(reported, now time.Time, policy event.Policy) error {
	if reported.After(now.Add(policy.MaxClockSkew)) {
		return &event.Violation{
			Field:  "reported_at",
			Reason: fmt.Sprintf("is more than %s ahead of the platform clock", policy.MaxClockSkew),
		}
	}
	if reported.Before(now.Add(-policy.MaxAge)) {
		return &event.Violation{
			Field:  "reported_at",
			Reason: fmt.Sprintf("is older than the %s admission window", policy.MaxAge),
		}
	}
	return nil
}

func interval(announced *durationpb.Duration) error {
	if announced == nil {
		return &event.Violation{Field: "interval", Reason: "is missing"}
	}
	if !announced.IsValid() {
		return &event.Violation{Field: "interval", Reason: "is not a representable duration"}
	}
	if every := announced.AsDuration(); every < MinInterval || every > MaxInterval {
		return &event.Violation{
			Field:  "interval",
			Reason: fmt.Sprintf("must be between %s and %s", MinInterval, MaxInterval),
		}
	}
	return nil
}

func validateRun(run *agentv1.Status_Run) error {
	if run == nil {
		return &event.Violation{Field: "run", Reason: "is missing"}
	}
	if err := text("run.boot_id", run.GetBootId(), MaxBootIDLength, false); err != nil {
		return err
	}
	if err := required("run.started_at", run.GetStartedAt()); err != nil {
		return err
	}
	if err := named("run.previous_ending", int32(run.GetPreviousEnding()), agentv1.Status_Ending_name); err != nil {
		return err
	}
	if err := optional("run.previous_seen_at", run.GetPreviousSeenAt()); err != nil {
		return err
	}
	return text("run.previous_reason", run.GetPreviousReason(), MaxReasonLength, false)
}

func validateBuild(build *agentv1.Status_Build) error {
	if build == nil {
		return &event.Violation{Field: "build", Reason: "is missing"}
	}
	for _, field := range []struct {
		name, value string
		maximum     int
		required    bool
	}{
		{"build.version", build.GetVersion(), MaxVersionLength, true},
		{"build.revision", build.GetRevision(), MaxRevisionLength, false},
		{"build.toolchain", build.GetToolchain(), MaxToolchainLength, false},
		{"build.os", build.GetOs(), MaxPlatformLength, false},
		{"build.architecture", build.GetArchitecture(), MaxPlatformLength, false},
	} {
		if err := text(field.name, field.value, field.maximum, field.required); err != nil {
			return err
		}
	}
	return nil
}

func validateComponents(components []*agentv1.Status_Component) error {
	if len(components) > MaxComponents {
		return &event.Violation{
			Field:  "components",
			Reason: fmt.Sprintf("carries %d components and the ceiling is %d", len(components), MaxComponents),
		}
	}
	for index, component := range components {
		field := fmt.Sprintf("components[%d]", index)
		if err := part(field, component.GetName(), int32(component.GetCondition()), component.GetSince(), component.GetReason()); err != nil {
			return err
		}
	}
	return nil
}

func validateModules(modules []*agentv1.Status_Module) error {
	if len(modules) > MaxModules {
		return &event.Violation{
			Field:  "modules",
			Reason: fmt.Sprintf("carries %d modules and the ceiling is %d", len(modules), MaxModules),
		}
	}
	for index, module := range modules {
		field := fmt.Sprintf("modules[%d]", index)
		if err := part(field, module.GetName(), int32(module.GetCondition()), module.GetSince(), module.GetReason()); err != nil {
			return err
		}
	}
	return nil
}

func part(field, name string, condition int32, since *timestamppb.Timestamp, reason string) error {
	if err := text(field+".name", name, MaxNameLength, true); err != nil {
		return err
	}
	if err := declared(field+".condition", condition, agentv1.Status_Condition_name); err != nil {
		return err
	}
	if err := optional(field+".since", since); err != nil {
		return err
	}
	return text(field+".reason", reason, MaxReasonLength, false)
}

func validateSpool(spool *agentv1.Status_Spool) error {
	if spool == nil {
		return &event.Violation{Field: "spool", Reason: "is missing"}
	}
	streams := spool.GetStreams()
	if len(streams) > MaxStreams {
		return &event.Violation{
			Field:  "spool.streams",
			Reason: fmt.Sprintf("carries %d streams and the ceiling is %d", len(streams), MaxStreams),
		}
	}
	for index, stream := range streams {
		field := fmt.Sprintf("spool.streams[%d]", index)
		if err := text(field+".name", stream.GetName(), MaxNameLength, true); err != nil {
			return err
		}
		for _, instant := range []struct {
			name  string
			value *timestamppb.Timestamp
		}{
			{"oldest_admitted", stream.GetOldestAdmitted()},
			{"last_delivered", stream.GetLastDelivered()},
			{"paused_since", stream.GetPausedSince()},
			{"failing_since", stream.GetFailingSince()},
		} {
			if err := optional(field+"."+instant.name, instant.value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCredential(credential *agentv1.Status_Credential) error {
	if credential == nil {
		return nil
	}
	if err := required("credential.not_after", credential.GetNotAfter()); err != nil {
		return err
	}
	if err := optional("credential.renews_at", credential.GetRenewsAt()); err != nil {
		return err
	}
	return optional("credential.renewal_failing_since", credential.GetRenewalFailingSince())
}

func validateConfiguration(configuration *agentv1.Status_Configuration) error {
	if configuration == nil {
		return &event.Violation{Field: "configuration", Reason: "is missing"}
	}
	if digest := configuration.GetDigestSha256(); !lowercaseDigest(digest) {
		return &event.Violation{Field: "configuration.digest_sha256", Reason: "is not a lowercase hex SHA-256"}
	}
	if err := text("configuration.policy_id", configuration.GetPolicyId(), MaxPolicyIDLength, false); err != nil {
		return err
	}
	return optional("configuration.policy_expires_at", configuration.GetPolicyExpiresAt())
}

func validatePrivileges(privileges *agentv1.Status_Privileges) error {
	if privileges == nil {
		return &event.Violation{Field: "privileges", Reason: "is missing"}
	}
	if err := text("privileges.user", privileges.GetUser(), MaxAccountLength, true); err != nil {
		return err
	}
	if err := listed("privileges.groups", privileges.GetGroups(), MaxGroups, MaxAccountLength); err != nil {
		return err
	}
	if err := listed("privileges.capabilities", privileges.GetCapabilities(), MaxCapabilities, MaxCapabilityLength); err != nil {
		return err
	}
	return text("privileges.seccomp", privileges.GetSeccomp(), MaxSeccompLength, false)
}

// Absent while no update was asked of the agent.
func validateUpdate(update *agentv1.Status_Update) error {
	if update == nil {
		return nil
	}
	if err := declared("update.stage", int32(update.GetStage()), agentv1.Status_Update_Stage_name); err != nil {
		return err
	}
	if err := text("update.version", update.GetVersion(), MaxVersionLength, true); err != nil {
		return err
	}
	if err := required("update.since", update.GetSince()); err != nil {
		return err
	}
	if err := named("update.failure", int32(update.GetFailure()), agentv1.Status_Update_Failure_name); err != nil {
		return err
	}
	return text("update.reason", update.GetReason(), MaxReasonLength, false)
}

func listed(field string, values []string, most, longest int) error {
	if len(values) > most {
		return &event.Violation{Field: field, Reason: fmt.Sprintf("carries %d entries and the ceiling is %d", len(values), most)}
	}
	for index, value := range values {
		if err := text(fmt.Sprintf("%s[%d]", field, index), value, longest, true); err != nil {
			return err
		}
	}
	return nil
}

func lowercaseDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func required(field string, instant *timestamppb.Timestamp) error {
	if instant == nil {
		return &event.Violation{Field: field, Reason: "is missing"}
	}
	return optional(field, instant)
}

func optional(field string, instant *timestamppb.Timestamp) error {
	if instant != nil && !instant.IsValid() {
		return &event.Violation{Field: field, Reason: "is not a representable instant"}
	}
	return nil
}

func declared(field string, value int32, names map[int32]string) error {
	if value == 0 {
		return &event.Violation{Field: field, Reason: "is unspecified"}
	}
	return named(field, value, names)
}

// A number no build declares is refused even where unspecified is admitted,
// because the store keeps the name of a value and would read that one back as
// unspecified.
func named(field string, value int32, names map[int32]string) error {
	if _, known := names[value]; !known {
		return &event.Violation{Field: field, Reason: "is not a value the contract declares"}
	}
	return nil
}

func text(field, value string, maximum int, needed bool) error {
	if value == "" {
		if needed {
			return &event.Violation{Field: field, Reason: "is required"}
		}
		return nil
	}
	if len(value) > maximum {
		return &event.Violation{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", maximum)}
	}
	return nil
}

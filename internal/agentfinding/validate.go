package agentfinding

import (
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

var (
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

type shape struct {
	minReports int
	closures   []agentv1.Finding_Closure
	used       bool
}

// What each kind rests on and how it may end. A kind this table does not name is
// one this build cannot judge, and a decision about it is refused rather than
// stored as something nobody can read.
var shapes = map[agentv1.Finding_Kind]shape{
	agentv1.Finding_KIND_SILENCE: {
		minReports: 1,
		closures:   []agentv1.Finding_Closure{agentv1.Finding_CLOSURE_HEARD, agentv1.Finding_CLOSURE_NOT_ADMITTED},
	},
	agentv1.Finding_KIND_COPIED_INSTALLATION: {
		minReports: 2,
		closures:   []agentv1.Finding_Closure{agentv1.Finding_CLOSURE_ONE_SOURCE, agentv1.Finding_CLOSURE_NOT_ADMITTED},
	},
	agentv1.Finding_KIND_SHARED_IDENTITY: {
		minReports: 2,
		closures:   []agentv1.Finding_Closure{agentv1.Finding_CLOSURE_ONE_SOURCE, agentv1.Finding_CLOSURE_NOT_ADMITTED},
	},
	agentv1.Finding_KIND_REPLACED_CERTIFICATE: {
		closures: []agentv1.Finding_Closure{agentv1.Finding_CLOSURE_REBOUND, agentv1.Finding_CLOSURE_NOT_ADMITTED},
		used:     true,
	},
}

// A decision is ordered by when it was made and names its finding by a digest,
// so neither may be missing; an open finding carries no closure and a closed one
// says what closed it and when.
func Validate(decided *agentv1.Finding) error {
	if decided == nil {
		return &event.Violation{Field: "finding", Reason: "is missing"}
	}
	if version := decided.GetSchemaVersion(); version < MinSchemaVersion || version > MaxSchemaVersion {
		return &event.Violation{Field: "schema_version", Reason: fmt.Sprintf("must be between %d and %d", MinSchemaVersion, MaxSchemaVersion)}
	}
	if id := decided.GetFindingId(); len(id) != IDLength || !lowercaseHex(id) {
		return &event.Violation{Field: "finding_id", Reason: "is not a finding identifier"}
	}
	if err := text("tenant_id", decided.GetTenantId(), event.MaxTenantIDLength, true); err != nil {
		return err
	}
	if !agentidentity.Valid(decided.GetAgentId()) {
		return &event.Violation{Field: "agent_id", Reason: "is missing or malformed"}
	}

	kind, ok := shapes[decided.GetKind()]
	if !ok {
		return &event.Violation{Field: "kind", Reason: "is not a kind this build judges"}
	}
	if err := states(decided, kind); err != nil {
		return err
	}
	if err := instants(decided); err != nil {
		return err
	}
	if decided.GetObservations() == 0 {
		return &event.Violation{Field: "observations", Reason: "is zero, and a finding was observed at least once"}
	}
	if err := reports(decided.GetReports(), kind.minReports); err != nil {
		return err
	}
	if err := use(decided.GetUse(), kind.used); err != nil {
		return err
	}
	if size := proto.Size(decided); size > MaxFindingBytes {
		return &event.Violation{Field: "finding", Reason: fmt.Sprintf("encodes to %d bytes and the ceiling is %d", size, MaxFindingBytes)}
	}
	return nil
}

func states(decided *agentv1.Finding, kind shape) error {
	switch decided.GetState() {
	case agentv1.Finding_STATE_OPEN:
		if decided.GetClosure() != agentv1.Finding_CLOSURE_UNSPECIFIED || decided.GetClosedAt() != nil {
			return &event.Violation{Field: "closure", Reason: "is set on a finding that is open"}
		}
	case agentv1.Finding_STATE_CLOSED:
		for _, closure := range kind.closures {
			if decided.GetClosure() == closure {
				return nil
			}
		}
		return &event.Violation{Field: "closure", Reason: "is not one that ends a finding of this kind"}
	default:
		return &event.Violation{Field: "state", Reason: "is neither open nor closed"}
	}
	return nil
}

func instants(decided *agentv1.Finding) error {
	closed := decided.GetState() == agentv1.Finding_STATE_CLOSED
	for _, held := range []struct {
		field    string
		value    *timestamppb.Timestamp
		required bool
	}{
		{"opened_at", decided.GetOpenedAt(), true},
		{"last_observed_at", decided.GetLastObservedAt(), true},
		{"closed_at", decided.GetClosedAt(), closed},
		{"decided_at", decided.GetDecidedAt(), true},
	} {
		if err := instant(held.field, held.value, held.required); err != nil {
			return err
		}
	}
	opened := decided.GetOpenedAt().AsTime()
	if decided.GetLastObservedAt().AsTime().Before(opened) {
		return &event.Violation{Field: "last_observed_at", Reason: "is before the finding opened"}
	}
	if closed && decided.GetClosedAt().AsTime().Before(opened) {
		return &event.Violation{Field: "closed_at", Reason: "is before the finding opened"}
	}
	return nil
}

func reports(heard []*agentv1.Heard, minimum int) error {
	if len(heard) < minimum || len(heard) > MaxReports {
		return &event.Violation{Field: "reports", Reason: fmt.Sprintf("names %d reports, and a finding of this kind names %d to %d", len(heard), minimum, MaxReports)}
	}
	for index, one := range heard {
		field := func(name string) string { return fmt.Sprintf("reports[%d].%s", index, name) }
		if one == nil {
			return &event.Violation{Field: field("report"), Reason: "is missing"}
		}
		for _, held := range []struct {
			name     string
			value    string
			required bool
		}{
			{"installation_id", one.GetInstallationId(), true},
			{"boot_id", one.GetBootId(), false},
			{"gateway", one.GetGateway(), true},
		} {
			if err := text(field(held.name), held.value, MaxTextLength, held.required); err != nil {
				return err
			}
		}
		if one.GetSequence() == 0 {
			return &event.Violation{Field: field("sequence"), Reason: "is zero, and an installation counts its reports from 1"}
		}
		for _, held := range []struct {
			name     string
			value    *timestamppb.Timestamp
			required bool
		}{
			{"run_started_at", one.GetRunStartedAt(), false},
			{"reported_at", one.GetReportedAt(), true},
			{"ingest_time", one.GetIngestTime(), true},
		} {
			if err := instant(field(held.name), held.value, held.required); err != nil {
				return err
			}
		}
		if every := one.GetInterval(); !every.IsValid() || every.AsDuration() < agentstatus.MinInterval || every.AsDuration() > agentstatus.MaxInterval {
			return &event.Violation{Field: field("interval"), Reason: fmt.Sprintf("must be between %s and %s", agentstatus.MinInterval, agentstatus.MaxInterval)}
		}
	}
	return nil
}

func use(used *agentv1.Finding_Use, required bool) error {
	if !required {
		if used != nil {
			return &event.Violation{Field: "use", Reason: "is set on a finding about no certificate"}
		}
		return nil
	}
	if _, declared := agentv1.Finding_Use_Listener_name[int32(used.GetListener())]; !declared || used.GetListener() == agentv1.Finding_Use_LISTENER_UNSPECIFIED {
		return &event.Violation{Field: "use.listener", Reason: "is not a listener the contract declares"}
	}
	return text("use.route", used.GetRoute(), MaxRouteLength, true)
}

func instant(field string, value *timestamppb.Timestamp, required bool) error {
	if value == nil {
		if required {
			return &event.Violation{Field: field, Reason: "is missing"}
		}
		return nil
	}
	if !value.IsValid() {
		return &event.Violation{Field: field, Reason: "is not a representable instant"}
	}
	if at := value.AsTime(); at.Before(earliest) || at.After(latest) {
		return &event.Violation{Field: field, Reason: "is outside the instants the platform can hold"}
	}
	return nil
}

func text(field, value string, maximum int, required bool) error {
	if value == "" {
		if required {
			return &event.Violation{Field: field, Reason: "is required"}
		}
		return nil
	}
	if len(value) > maximum {
		return &event.Violation{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", maximum)}
	}
	return nil
}

func lowercaseHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

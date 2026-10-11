package statusstore

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// What the store can hold of an instant, which is narrower than what the
// contract can say: outside these bounds UnixNano wraps silently.
var (
	earliest = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(2262, time.April, 11, 23, 47, 16, 0, time.UTC)
)

// One report, as the newest the store holds of its agent: the columns a reader
// asks about, and the report itself, byte for byte as the gateway published it,
// which is what a reader of one agent is handed back.
type Row struct {
	TenantID   string
	AgentID    string
	IngestTime time.Time

	ReportedAt     time.Time
	InstallationID string
	Sequence       uint64
	BootID         string
	IntervalMillis uint32
	Condition      string
	BuildVersion   string

	Report []byte
}

func Project(report *agentv1.Status, published []byte) Row {
	return Row{
		TenantID:   report.GetOrigin().GetTenantId(),
		AgentID:    report.GetOrigin().GetAgentId(),
		IngestTime: instant(report.GetReception().GetIngestTime()),

		ReportedAt:     instant(report.GetReportedAt()),
		InstallationID: report.GetInstallationId(),
		Sequence:       report.GetSequence(),
		BootID:         report.GetRun().GetBootId(),
		IntervalMillis: uint32(report.GetInterval().AsDuration().Milliseconds()),
		Condition:      agentstatus.ConditionName(report.GetCondition()),
		BuildVersion:   report.GetBuild().GetVersion(),

		Report: published,
	}
}

func instant(stamp *timestamppb.Timestamp) time.Time {
	if stamp == nil {
		return time.Time{}
	}
	return stamp.AsTime().UTC()
}

func storable(row Row) error {
	if row.IngestTime.IsZero() {
		return errors.New("reception.ingest_time is missing, so nothing says when the platform heard the agent")
	}
	for _, held := range []struct {
		field string
		at    time.Time
	}{
		{"reception.ingest_time", row.IngestTime},
		{"reported_at", row.ReportedAt},
	} {
		if held.at.Before(earliest) || held.at.After(latest) {
			return fmt.Errorf("%s is outside the %s..%s the store can hold",
				held.field, earliest.Format(time.DateOnly), latest.Format(time.DateOnly))
		}
	}
	return nil
}

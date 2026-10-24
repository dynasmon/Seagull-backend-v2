package ingest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type recordingStatus struct {
	published [][]*agentv1.Status
	failure   error
}

func (r *recordingStatus) PublishStatus(_ context.Context, reports []*agentv1.Status) error {
	if r.failure != nil {
		return r.failure
	}
	r.published = append(r.published, reports)
	return nil
}

func (r *recordingStatus) last() []*agentv1.Status {
	if len(r.published) == 0 {
		return nil
	}
	return r.published[len(r.published)-1]
}

func newStatusAdmitter(t *testing.T, backbone ingest.StatusBackbone) *ingest.StatusAdmitter {
	t.Helper()
	admitter, err := ingest.NewStatusAdmitter(
		backbone,
		ingest.StatusPolicy{
			Gateway:            "gateway-a",
			MaxReportsPerBatch: 2,
			Report:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
		},
		ingest.NewStatusMetrics(metrics.New("test")),
		ingest.WithStatusClock(func() time.Time { return admissionClock }),
	)
	if err != nil {
		t.Fatalf("build status admitter: %v", err)
	}
	return admitter
}

func reported() *agentv1.Status {
	return fixtures.Report{At: admissionClock.Add(-time.Second)}.Status()
}

func TestAnAdmittedStatusBatchIsAcknowledgedAsDurable(t *testing.T) {
	backbone := &recordingStatus{}
	admitter := newStatusAdmitter(t, backbone)

	acknowledgement, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.StatusBatch("status-1", reported()))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() || acknowledgement.GetReceived() != 1 {
		t.Fatalf("an admitted report must be acknowledged as durable and counted: %+v", acknowledgement)
	}
	if len(backbone.last()) != 1 {
		t.Fatalf("expected 1 published report, got %d", len(backbone.last()))
	}
}

// A copied key could otherwise speak for a host it was never on, or for an
// estate it was never placed in.
func TestAReportIsStampedWithTheVerifiedAgentTheRegistryTenantAndThePlatformClock(t *testing.T) {
	backbone := &recordingStatus{}
	admitter := newStatusAdmitter(t, backbone)

	impersonating := reported()
	impersonating.Origin.AgentId = "domain-controller"
	impersonating.Origin.TenantId = "someone-else"
	impersonating.Reception = &eventv1.Reception{Gateway: "not-a-gateway", BatchId: "not-this-batch"}
	claimingNothing := reported()
	claimingNothing.Origin = nil

	if _, err := admitter.Admit(context.Background(), identity(), "globex", fixtures.StatusBatch("status-7", impersonating, claimingNothing)); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	for index, published := range backbone.last() {
		if published.GetOrigin().GetAgentId() != "web-01" || published.GetOrigin().GetTenantId() != "globex" {
			t.Errorf("report %d speaks for %q in %q", index, published.GetOrigin().GetAgentId(), published.GetOrigin().GetTenantId())
		}
		reception := published.GetReception()
		if reception.GetGateway() != "gateway-a" || reception.GetBatchId() != "status-7" || !reception.GetIngestTime().AsTime().Equal(admissionClock) {
			t.Errorf("report %d kept a reception the platform did not write: %+v", index, reception)
		}
	}
}

func TestAStatusBatchIsBoundedAndNamesTheReportItRefuses(t *testing.T) {
	broken := reported()
	broken.Components[0].Reason = strings.Repeat("r", agentstatus.MaxReasonLength+1)
	unsupported := fixtures.StatusBatch("status-1", reported())
	unsupported.ProtocolVersion = 99

	for name, one := range map[string]struct {
		batch *agentv1.StatusBatch
		code  ingest.RejectionCode
		index int
		field string
	}{
		"empty":           {fixtures.StatusBatch("status-1"), ingest.CodeEmptyBatch, -1, ""},
		"too many":        {fixtures.StatusBatch("status-1", reported(), reported(), reported()), ingest.CodeBatchTooLarge, -1, ""},
		"no batch id":     {fixtures.StatusBatch("", reported()), ingest.CodeMalformedBatchID, -1, "batch_id"},
		"protocol":        {unsupported, ingest.CodeUnsupportedProtocol, -1, ""},
		"invalid report":  {fixtures.StatusBatch("status-1", reported(), broken), ingest.CodeInvalidReport, 1, "components[0].reason"},
		"from the future": {fixtures.StatusBatch("status-1", fixtures.Report{At: admissionClock.Add(time.Hour)}.Status()), ingest.CodeInvalidReport, 0, "reported_at"},
		"silly interval":  {fixtures.StatusBatch("status-1", fixtures.Report{At: admissionClock, Interval: time.Second}.Status()), ingest.CodeInvalidReport, 0, "interval"},
		"no installation": {fixtures.StatusBatch("status-1", fixtures.Report{At: admissionClock, InstallationID: "not one"}.Status()), ingest.CodeInvalidReport, 0, "installation_id"},
	} {
		t.Run(name, func(t *testing.T) {
			backbone := &recordingStatus{}
			_, err := newStatusAdmitter(t, backbone).Admit(context.Background(), identity(), "acme", one.batch)
			rejection := rejectionOf(t, err)
			if rejection.Code != one.code || rejection.EventIndex != one.index || rejection.Field != one.field {
				t.Fatalf("refused with %q at %d naming %q", rejection.Code, rejection.EventIndex, rejection.Field)
			}
			if len(backbone.published) != 0 {
				t.Fatal("a refused batch reached the backbone")
			}
		})
	}
}

func TestAStatusBatchTheBackboneRefusedIsNeverAcknowledged(t *testing.T) {
	admitter := newStatusAdmitter(t, &recordingStatus{failure: errors.New("no leader for partition")})

	acknowledgement, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.StatusBatch("status-1", reported()))
	if acknowledgement != nil || !errors.Is(err, ingest.ErrBackboneUnavailable) {
		t.Fatalf("a report the backbone did not take was answered %+v, %v", acknowledgement, err)
	}
}

func TestTheStatusAdmitterRefusesAnIncompletePolicy(t *testing.T) {
	instruments := ingest.NewStatusMetrics(metrics.New("test"))
	for name, policy := range map[string]ingest.StatusPolicy{
		"no gateway":         {MaxReportsPerBatch: 1},
		"no ceiling":         {Gateway: "gateway-a"},
		"above the contract": {Gateway: "gateway-a", MaxReportsPerBatch: agentstatus.MaxReportsPerBatch + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ingest.NewStatusAdmitter(&recordingStatus{}, policy, instruments); err == nil {
				t.Fatal("expected the admitter to refuse the policy")
			}
		})
	}
}

func TestAReportHeavierThanTheBackboneCarriesIsRefusedForGood(t *testing.T) {
	backbone := &recordingStatus{}
	admitter := newStatusAdmitter(t, backbone)

	heavy := reported()
	if !fixtures.Bloat(heavy, agentstatus.MaxReportBytes+4<<10) {
		t.Fatal("no report weighs that much")
	}
	_, err := admitter.Admit(context.Background(), identity(), "acme", fixtures.StatusBatch("status-1", reported(), heavy))

	rejection := rejectionOf(t, err)
	if rejection.Code != ingest.CodeInvalidReport || rejection.EventIndex != 1 || rejection.Field != "report" {
		t.Fatalf("a report above the ceiling was refused as %+v, and an agent sends again whatever is not refused by its index", rejection)
	}
	if len(backbone.published) != 0 {
		t.Fatal("a batch holding a report the backbone cannot carry reached the backbone")
	}
}

package ingest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type recordingBackbone struct {
	published [][]*eventv1.Event
	failure   error
}

func (r *recordingBackbone) PublishEvents(_ context.Context, events []*eventv1.Event) error {
	if r.failure != nil {
		return r.failure
	}
	r.published = append(r.published, events)
	return nil
}

func (r *recordingBackbone) last() []*eventv1.Event {
	if len(r.published) == 0 {
		return nil
	}
	return r.published[len(r.published)-1]
}

var admissionClock = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func newAdmitter(t *testing.T, backbone ingest.Backbone) *ingest.Admitter {
	t.Helper()
	admitter, err := ingest.NewAdmitter(
		backbone,
		ingest.Policy{
			Gateway:           "gateway-a",
			TenantID:          "acme",
			MaxEventsPerBatch: 10,
			Event:             event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour},
		},
		ingest.NewMetrics(metrics.New("test")),
		ingest.WithClock(func() time.Time { return admissionClock }),
	)
	if err != nil {
		t.Fatalf("build admitter: %v", err)
	}
	return admitter
}

func identity() agentidentity.Identity {
	return agentidentity.Identity{AgentID: "web-01"}
}

func sample() *eventv1.Event {
	return fixtures.SSHAuthentication{At: admissionClock.Add(-time.Second)}.Event()
}

func rejectionOf(t *testing.T, err error) *ingest.Rejection {
	t.Helper()
	var rejection *ingest.Rejection
	if !errors.As(err, &rejection) {
		t.Fatalf("expected a rejection, got %v", err)
	}
	return rejection
}

func TestAdmittedBatchIsAcknowledgedAsDurable(t *testing.T) {
	backbone := &recordingBackbone{}
	admitter := newAdmitter(t, backbone)

	acknowledgement, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", sample(), sample()))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	if !acknowledgement.GetAccepted() || !acknowledgement.GetDurable() {
		t.Fatalf("an admitted batch must be acknowledged as durable: %+v", acknowledgement)
	}
	if acknowledgement.GetReceived() != 2 {
		t.Fatalf("expected 2 received events, got %d", acknowledgement.GetReceived())
	}
	if len(backbone.last()) != 2 {
		t.Fatalf("expected 2 published events, got %d", len(backbone.last()))
	}
}

func TestClaimedAgentIdentityIsReplacedByTheVerifiedOne(t *testing.T) {
	backbone := &recordingBackbone{}
	admitter := newAdmitter(t, backbone)

	impersonating := sample()
	impersonating.Origin.AgentId = "domain-controller"
	impersonating.Origin.TenantId = "someone-else"

	if _, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", impersonating)); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	published := backbone.last()[0]
	if published.GetOrigin().GetAgentId() != "web-01" {
		t.Fatalf("the claimed agent identity survived: %q", published.GetOrigin().GetAgentId())
	}
	if published.GetOrigin().GetTenantId() != "acme" {
		t.Fatalf("the claimed tenant survived: %q", published.GetOrigin().GetTenantId())
	}
}

func TestReceptionIsWrittenByThePlatform(t *testing.T) {
	backbone := &recordingBackbone{}
	admitter := newAdmitter(t, backbone)

	forged := sample()
	forged.Reception = &eventv1.Reception{
		IngestTime: timestamppb.New(admissionClock.Add(-72 * time.Hour)),
		Gateway:    "not-a-gateway",
		BatchId:    "not-this-batch",
	}

	if _, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-7", forged)); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	reception := backbone.last()[0].GetReception()
	if !reception.GetIngestTime().AsTime().Equal(admissionClock) {
		t.Fatalf("ingest time was not stamped by the platform: %s", reception.GetIngestTime().AsTime())
	}
	if reception.GetGateway() != "gateway-a" || reception.GetBatchId() != "batch-7" {
		t.Fatalf("reception was not replaced: %+v", reception)
	}
}

func TestProducerTimestampsSurviveAdmission(t *testing.T) {
	backbone := &recordingBackbone{}
	admitter := newAdmitter(t, backbone)

	delayed := fixtures.SSHAuthentication{At: admissionClock.Add(-36 * time.Hour)}.Event()
	if _, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", delayed)); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	published := backbone.last()[0]
	if !published.GetTime().GetEventTime().AsTime().Equal(admissionClock.Add(-36 * time.Hour)) {
		t.Fatal("the producer event time was rewritten by the gateway")
	}
}

func TestBatchThatTheBackboneRefusedIsNeverAcknowledged(t *testing.T) {
	backbone := &recordingBackbone{failure: errors.New("no leader for partition")}
	admitter := newAdmitter(t, backbone)

	acknowledgement, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", sample()))

	if acknowledgement != nil {
		t.Fatalf("a batch that was not made durable must not be acknowledged: %+v", acknowledgement)
	}
	if !errors.Is(err, ingest.ErrBackboneUnavailable) {
		t.Fatalf("expected an unavailable backbone, got %v", err)
	}
	if !strings.Contains(err.Error(), "no leader for partition") {
		t.Fatalf("the underlying cause was lost: %v", err)
	}
}

func TestEmptyBatchIsRefused(t *testing.T) {
	admitter := newAdmitter(t, &recordingBackbone{})

	_, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1"))

	if code := rejectionOf(t, err).Code; code != ingest.CodeEmptyBatch {
		t.Fatalf("unexpected code %q", code)
	}
}

func TestBatchAboveTheCeilingIsRefusedBeforePublishing(t *testing.T) {
	backbone := &recordingBackbone{}
	admitter := newAdmitter(t, backbone)

	events := make([]*eventv1.Event, 11)
	for index := range events {
		events[index] = sample()
	}

	_, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", events...))

	if code := rejectionOf(t, err).Code; code != ingest.CodeBatchTooLarge {
		t.Fatalf("unexpected code %q", code)
	}
	if len(backbone.published) != 0 {
		t.Fatal("an oversized batch reached the backbone")
	}
}

func TestUnsupportedProtocolVersionIsRefused(t *testing.T) {
	admitter := newAdmitter(t, &recordingBackbone{})

	batch := fixtures.Batch("batch-1", sample())
	batch.ProtocolVersion = 99

	_, err := admitter.Admit(context.Background(), identity(), batch)

	if code := rejectionOf(t, err).Code; code != ingest.CodeUnsupportedProtocol {
		t.Fatalf("unexpected code %q", code)
	}
}

func TestBatchIdentifierIsRequiredAndBounded(t *testing.T) {
	admitter := newAdmitter(t, &recordingBackbone{})

	for name, id := range map[string]string{
		"missing": "",
		"unsafe":  "batch id; drop table",
		"long":    strings.Repeat("b", event.MaxBatchIDLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			batch := fixtures.Batch(id, sample())
			_, err := admitter.Admit(context.Background(), identity(), batch)
			if code := rejectionOf(t, err).Code; code != ingest.CodeMalformedBatchID {
				t.Fatalf("unexpected code %q", code)
			}
		})
	}
}

func TestInvalidEventNamesItsPositionAndField(t *testing.T) {
	backbone := &recordingBackbone{}
	admitter := newAdmitter(t, backbone)

	broken := sample()
	broken.GetAuthentication().Network.Source.Ip = "definitely-not-an-ip"

	_, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", sample(), broken))

	rejection := rejectionOf(t, err)
	if rejection.Code != ingest.CodeInvalidEvent {
		t.Fatalf("unexpected code %q", rejection.Code)
	}
	if rejection.EventIndex != 1 {
		t.Fatalf("expected the offending index, got %d", rejection.EventIndex)
	}
	if rejection.Field != "authentication.network.source.ip" {
		t.Fatalf("expected the offending field, got %q", rejection.Field)
	}
	if len(backbone.published) != 0 {
		t.Fatal("a batch holding an invalid event reached the backbone")
	}
}

func TestAdmitterRefusesAnIncompletePolicy(t *testing.T) {
	instruments := ingest.NewMetrics(metrics.New("test"))

	cases := map[string]ingest.Policy{
		"no gateway": {TenantID: "acme", MaxEventsPerBatch: 1},
		"no tenant":  {Gateway: "gateway-a", MaxEventsPerBatch: 1},
		"no ceiling": {Gateway: "gateway-a", TenantID: "acme"},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ingest.NewAdmitter(&recordingBackbone{}, policy, instruments); err == nil {
				t.Fatal("expected the admitter to refuse the policy")
			}
		})
	}
}

func TestAcknowledgementCarriesTheCountTheAgentSent(t *testing.T) {
	admitter := newAdmitter(t, &recordingBackbone{})

	events := []*eventv1.Event{sample(), sample(), sample()}
	acknowledgement, err := admitter.Admit(context.Background(), identity(), fixtures.Batch("batch-1", events...))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	var _ *ingestv1.BatchAck = acknowledgement
	if acknowledgement.GetReceived() != uint32(len(events)) {
		t.Fatalf("expected %d, got %d", len(events), acknowledgement.GetReceived())
	}
}

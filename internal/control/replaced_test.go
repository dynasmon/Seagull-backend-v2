package control_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func replacedBy(t *testing.T, held *stubAgents, id string) {
	t.Helper()
	signing, _ := testAuthority(t)
	at := time.Now().UTC()
	issued, err := signing.Sign(id, signingRequest(t, id), time.Hour, at)
	if err != nil {
		t.Fatalf("sign another certificate: %v", err)
	}
	if _, err := held.Move(t.Context(), id, []string{"default"}, agent.Move{Identity: issued.Identity, Actor: "dev-admin", At: at}); err != nil {
		t.Fatalf("bind another certificate: %v", err)
	}
}

func unsigning(t *testing.T, held *stubAgents, exported *metrics.Registry) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	handler, err := control.NewRenewalHandler(control.ServerOptions{
		Agents: held, Policies: newStubPolicies(held), Authority: signing, TrustBundle: bundle,
		CertificateLife: 30 * time.Minute,
		Metrics:         control.NewMetrics(exported),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-unsigning-routes")),
	})
	if err != nil {
		t.Fatalf("build the renewal listener: %v", err)
	}
	return handler
}

func TestARenewalWithAReplacedCertificateIsRefusedBeforeAnythingIsSigned(t *testing.T) {
	held := newStubAgents()
	active(t, held, "web-01")
	replacedBy(t, held, "web-01")
	exported := metrics.New("control-api-replaced")
	handler := unsigning(t, held, exported)

	refused := call(t, handler, http.MethodPost, control.RenewalPath, "web-01", "", &agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
	if refusal := refusalOf(t, refused); refused.Code != http.StatusUnprocessableEntity || refusal.GetCode() != control.CodeIllegalMove {
		t.Fatalf("a replaced certificate was answered %d %q, want the registry's refusal before the authority's", refused.Code, refusal.GetCode())
	}
	if held.replaced["web-01"] != 1 {
		t.Fatalf("the registry recorded %d uses of the replaced certificate", held.replaced["web-01"])
	}
	if counted := gauged(t, exported, `seagull_control_agent_certificates_renewed_total{outcome="replaced"}`); counted != 1 {
		t.Errorf("%v renewals are counted refused as replaced", counted)
	}

	other := newStubAgents()
	active(t, other, "web-01")
	granted := call(t, unsigning(t, other, metrics.New("control-api-granted")), http.MethodPost, control.RenewalPath, "web-01", "",
		&agentv1.RenewalRequest{CsrPem: signingRequest(t, "web-01")})
	if granted.Code != http.StatusServiceUnavailable || other.replaced["web-01"] != 0 {
		t.Fatalf("a renewal the registry grants was answered %d with %d uses recorded, want it to reach the authority", granted.Code, other.replaced["web-01"])
	}
}

type stubReplacements struct {
	waiting   []agentfinding.Replaced
	published []agentfinding.Replaced
	again     []time.Time
	unread    error
}

func (s *stubReplacements) Unpublished(_ context.Context, limit int) ([]agentfinding.Replaced, error) {
	if s.unread != nil {
		return nil, s.unread
	}
	return s.waiting[:min(limit, len(s.waiting))], nil
}

func (s *stubReplacements) Published(_ context.Context, used agentfinding.Replaced) error {
	s.published = append(s.published, used)
	for index, one := range s.waiting {
		if one.AgentID == used.AgentID && one.InForce == used.InForce && one.Revision == used.Revision {
			s.waiting = append(s.waiting[:index], s.waiting[index+1:]...)
			break
		}
	}
	return nil
}

func (s *stubReplacements) DecideAgain(_ context.Context, before, _ time.Time) error {
	s.again = append(s.again, before)
	return nil
}

type stubFindingDecisions struct {
	published []*agentv1.Finding
	unreached error
}

func (s *stubFindingDecisions) Publish(_ context.Context, decided []*agentv1.Finding) error {
	if s.unreached != nil {
		return s.unreached
	}
	s.published = append(s.published, decided...)
	return nil
}

func TestAReplacedCertificateIsPublishedAsAFindingOfTheRenewalRouteThatNeverNamesIt(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	inForce := strings.Repeat("ab", 32)
	kept := &stubReplacements{waiting: []agentfinding.Replaced{{
		TenantID: "default", AgentID: "web-01", InForce: inForce, OpenedAt: now.Add(-time.Hour),
		LastObservedAt: now.Add(-time.Minute), Observations: 4, DecidedAt: now.Add(-time.Minute), Revision: 4,
	}}}
	told := &stubFindingDecisions{unreached: errors.New("the backbone is unreachable")}
	exported := metrics.New("control-api-finding-announcer")
	announcer, err := control.NewFindingAnnouncer(control.FindingAnnouncerOptions{
		Replacements: kept, Decisions: told, Metrics: control.NewMetrics(exported),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Every: time.Second, Batch: 10, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	announcer.Sweep(context.Background())
	if len(kept.published) != 0 || gauged(t, exported, "seagull_control_agent_findings_outstanding") != 1 {
		t.Fatalf("a decision the backbone refused was recorded published: %v", kept.published)
	}
	told.unreached = nil
	announcer.Sweep(context.Background())
	if len(told.published) != 1 || len(kept.published) != 1 || gauged(t, exported, "seagull_control_agent_findings_outstanding") != 0 {
		t.Fatalf("published %v and recorded %v", told.published, kept.published)
	}
	decided := told.published[0]
	if err := agentfinding.Validate(decided); err != nil || decided.GetKind() != agentv1.Finding_KIND_REPLACED_CERTIFICATE ||
		decided.GetUse().GetListener() != agentv1.Finding_Use_LISTENER_CONTROL || decided.GetUse().GetRoute() != "POST "+control.RenewalPath ||
		decided.GetObservations() != 4 || decided.GetFindingId() != agentfinding.ID("default", "web-01", agentv1.Finding_KIND_REPLACED_CERTIFICATE, inForce) {
		t.Fatalf("the replaced certificate was published as %v (%v)", decided, err)
	}
	if encoded, _ := proto.Marshal(decided); bytes.Contains(encoded, []byte(inForce)) {
		t.Error("the published finding names the certificate in force")
	}
	if len(kept.again) != 2 || !kept.again[1].Equal(now.Add(-24*time.Hour)) {
		t.Errorf("the open decisions were decided again up to %v, want a day before each sweep", kept.again)
	}
	if counted := gauged(t, exported, `seagull_control_agent_findings_published_total{outcome="published"}`); counted != 1 {
		t.Errorf("%v decisions are counted published", counted)
	}
}

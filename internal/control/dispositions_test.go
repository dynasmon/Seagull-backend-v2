package control_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/disposition"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type stubWithdrawal struct {
	id      string
	tenants []string
	act     disposition.Withdrawal
}

type stubSearch struct {
	asked   *vulnerabilityv1.DispositionQuery
	tenants []string
	at      time.Time
}

// What the listener asked of the store and nothing more: what a disposition is
// and how it is kept is decided by the domain and the adapter, and held there.
type stubDispositions struct {
	err         error
	recorded    []*vulnerabilityv1.Disposition
	withdrawals []stubWithdrawal
	searches    []stubSearch
	answer      *vulnerabilityv1.Disposition
	page        *vulnerabilityv1.DispositionPage
}

func newStubDispositions() *stubDispositions {
	return &stubDispositions{page: &vulnerabilityv1.DispositionPage{}}
}

func (s *stubDispositions) Record(_ context.Context, recorded *vulnerabilityv1.Disposition) error {
	if s.err != nil {
		return s.err
	}
	s.recorded = append(s.recorded, recorded)
	return nil
}

func (s *stubDispositions) Withdraw(_ context.Context, id string, tenants []string, act disposition.Withdrawal) (*vulnerabilityv1.Disposition, error) {
	s.withdrawals = append(s.withdrawals, stubWithdrawal{id: id, tenants: tenants, act: act})
	if s.err != nil {
		return nil, s.err
	}
	return s.answer, nil
}

func (s *stubDispositions) Page(_ context.Context, asked *vulnerabilityv1.DispositionQuery, tenants []string, at time.Time) (*vulnerabilityv1.DispositionPage, error) {
	s.searches = append(s.searches, stubSearch{asked: asked, tenants: tenants, at: at})
	if s.err != nil {
		return nil, s.err
	}
	return s.page, nil
}

func dispositionListener(t *testing.T, h *harness, kept *stubDispositions) http.Handler {
	t.Helper()
	signing, bundle := testAuthority(t)
	handler, err := control.NewHandler(control.ServerOptions{
		Guard: h.guard, Sessions: h.sessions, Registry: h.registry,
		Rulesets: newStubRulesets(), Alerts: newStubAlerts(), Incidents: newStubIncidents(),
		Agents: newStubAgents(), Admissions: &stubAdmissions{}, Policies: newStubPolicies(nil),
		Dispositions: kept,
		Authority:    signing, TrustBundle: bundle, CertificateLife: time.Hour,
		Metrics: h.metrics, Logger: slog.New(slog.DiscardHandler),
		Instrumentation: httpx.NewInstrumentation(metrics.New("control-api-dispositions")),
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("build the routes: %v", err)
	}
	return handler
}

func acceptedRisk() *vulnerabilityv1.DispositionRequest {
	return &vulnerabilityv1.DispositionRequest{
		TenantId:        "default",
		VulnerabilityId: "CVE-2026-0001",
		Kind:            vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK,
		Reason:          "the appliance is retired next quarter",
		ExpiresAt:       timestamppb.New(now.Add(30 * 24 * time.Hour)),
	}
}

func withdrawalPath(id string) string {
	return strings.Replace(control.DispositionWithdrawal, "{id}", id, 1)
}

func wrapped(err error) error { return fmt.Errorf("%w: as the store words it", err) }

func disposed(t *testing.T, h *harness, outcome string) float64 {
	t.Helper()
	return gauged(t, h.scraped, `seagull_control_vulnerability_dispositions_total{outcome="`+outcome+`"}`)
}

func TestAResponderRecordsADispositionInItsTenantUnderItsOwnName(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	handler := dispositionListener(t, h, kept)

	recorder := call(t, handler, http.MethodPost, control.DispositionsPath, "dev-responder", open(t, h, "dev-responder"), acceptedRisk())
	if recorder.Code != http.StatusCreated {
		t.Fatalf("recording answered %d: %s", recorder.Code, recorder.Body)
	}
	var answered vulnerabilityv1.Disposition
	decode(t, recorder, &answered)

	if answered.GetActor() != "dev-responder" || !answered.GetDecidedAt().AsTime().Equal(now) || answered.GetTenantId() != "default" {
		t.Errorf("recorded by %q at %s in %q", answered.GetActor(), answered.GetDecidedAt().AsTime(), answered.GetTenantId())
	}
	if len(kept.recorded) != 1 || !proto.Equal(kept.recorded[0], &answered) {
		t.Errorf("the store kept %v and the caller was answered %v", kept.recorded, &answered)
	}
	if counted := disposed(t, h, "accepted_risk"); counted != 1 {
		t.Errorf("an accepted risk was counted %v times", counted)
	}
}

func TestADispositionIntoATenantTheCallerDoesNotHoldNeverReachesTheStore(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	handler := dispositionListener(t, h, kept)

	refusedWith(t, call(t, handler, http.MethodPost, control.DispositionsPath, "globex-admin", open(t, h, "globex-admin"), acceptedRisk()),
		http.StatusForbidden, control.CodeForbidden)

	if len(kept.recorded) != 0 {
		t.Errorf("the store kept %v", kept.recorded)
	}
	if counted := gauged(t, h.scraped,
		`seagull_control_authorizations_total{action="write",reason="out_of_tenant",resource="vulnerabilities"}`); counted != 1 {
		t.Errorf("the refusal was counted %v times", counted)
	}
}

func TestAnAnalystReadsDispositionsAndDisposesOfNone(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	handler := dispositionListener(t, h, kept)
	analyst := open(t, h, "dev-analyst")

	refusedWith(t, call(t, handler, http.MethodPost, control.DispositionsPath, "dev-analyst", analyst, acceptedRisk()),
		http.StatusForbidden, control.CodeForbidden)
	refusedWith(t, call(t, handler, http.MethodPost, withdrawalPath("0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6"), "dev-analyst", analyst,
		&vulnerabilityv1.WithdrawalRequest{Reason: "not mine to end"}), http.StatusForbidden, control.CodeForbidden)
	if listed := call(t, handler, http.MethodPost, control.DispositionSearch, "dev-analyst", analyst, &vulnerabilityv1.DispositionQuery{}); listed.Code != http.StatusOK {
		t.Errorf("an analyst reading dispositions was answered %d: %s", listed.Code, listed.Body)
	}

	if len(kept.recorded) != 0 || len(kept.withdrawals) != 0 || len(kept.searches) != 1 {
		t.Errorf("the store recorded %d, withdrew %d and listed %d times", len(kept.recorded), len(kept.withdrawals), len(kept.searches))
	}
}

func TestADispositionNobodyCanExplainIsRefusedBeforeTheStore(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	handler := dispositionListener(t, h, kept)
	unexplained := acceptedRisk()
	unexplained.Reason = ""

	refusedWith(t, call(t, handler, http.MethodPost, control.DispositionsPath, "dev-responder", open(t, h, "dev-responder"), unexplained),
		http.StatusUnprocessableEntity, control.CodeMalformedDisposition)
	if len(kept.recorded) != 0 {
		t.Errorf("the store kept %v", kept.recorded)
	}
	if counted := disposed(t, h, "refused"); counted != 1 {
		t.Errorf("the refusal was counted %v times", counted)
	}
}

func TestAWithdrawalIsAskedWithinTheCallersTenantsAsTheCallerAtThePlatformsClock(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	kept.answer = &vulnerabilityv1.Disposition{DispositionId: "0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6", WithdrawnBy: "dev-responder"}
	handler := dispositionListener(t, h, kept)

	recorder := call(t, handler, http.MethodPost, withdrawalPath("0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6"), "dev-responder",
		open(t, h, "dev-responder"), &vulnerabilityv1.WithdrawalRequest{Reason: "3.0.15 is installed"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("withdrawing answered %d: %s", recorder.Code, recorder.Body)
	}
	var answered vulnerabilityv1.Disposition
	decode(t, recorder, &answered)
	if !proto.Equal(&answered, kept.answer) {
		t.Errorf("answered %v, and the store withdrew %v", &answered, kept.answer)
	}

	want := stubWithdrawal{
		id:      "0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6",
		tenants: []string{"default"},
		act:     disposition.Withdrawal{Reason: "3.0.15 is installed", Actor: "dev-responder", At: now},
	}
	if len(kept.withdrawals) != 1 || kept.withdrawals[0].id != want.id || !slices.Equal(kept.withdrawals[0].tenants, want.tenants) ||
		kept.withdrawals[0].act != want.act {
		t.Errorf("the store was asked %+v, want %+v", kept.withdrawals, want)
	}
	if counted := disposed(t, h, "withdrawn"); counted != 1 {
		t.Errorf("the withdrawal was counted %v times", counted)
	}
}

func TestASearchIsAnsweredWithinTheCallersTenantsByThePlatformsClock(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	kept.page = &vulnerabilityv1.DispositionPage{
		Dispositions: []*vulnerabilityv1.Disposition{{DispositionId: "0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6"}},
		NextCursor:   "next",
	}
	handler := dispositionListener(t, h, kept)
	asked := &vulnerabilityv1.DispositionQuery{
		VulnerabilityIds: []string{"CVE-2026-0001"},
		AgentIds:         []string{"web-01"},
		Kinds:            []vulnerabilityv1.DispositionKind{vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED},
		Lapsed:           true,
		Limit:            10,
		Cursor:           "previous",
	}

	recorder := call(t, handler, http.MethodPost, control.DispositionSearch, "dev-analyst", open(t, h, "dev-analyst"), asked)
	if recorder.Code != http.StatusOK {
		t.Fatalf("searching answered %d: %s", recorder.Code, recorder.Body)
	}
	var page vulnerabilityv1.DispositionPage
	decode(t, recorder, &page)
	if !proto.Equal(&page, kept.page) {
		t.Errorf("answered %v, and the store listed %v", &page, kept.page)
	}
	if len(kept.searches) != 1 || !proto.Equal(kept.searches[0].asked, asked) ||
		!slices.Equal(kept.searches[0].tenants, []string{"default"}) || !kept.searches[0].at.Equal(now) {
		t.Errorf("the store was asked %+v", kept.searches)
	}
}

func TestASearchForAKindTheContractDoesNotDeclareIsRefused(t *testing.T) {
	h, kept := newHarness(t, nil), newStubDispositions()
	handler := dispositionListener(t, h, kept)
	analyst := open(t, h, "dev-analyst")

	for _, kind := range []vulnerabilityv1.DispositionKind{vulnerabilityv1.DispositionKind_DISPOSITION_KIND_UNSPECIFIED, 9} {
		refusedWith(t, call(t, handler, http.MethodPost, control.DispositionSearch, "dev-analyst", analyst,
			&vulnerabilityv1.DispositionQuery{Kinds: []vulnerabilityv1.DispositionKind{kind}}), http.StatusUnprocessableEntity, control.CodeUnknownFilter)
	}
	if len(kept.searches) != 0 {
		t.Errorf("the store was asked %+v", kept.searches)
	}
}

func TestEveryRefusalOfTheDispositionStoreIsAnsweredForWhatItIs(t *testing.T) {
	driver := errors.New(`ERROR: relation "vulnerability_dispositions" does not exist (SQLSTATE 42P01) at 10.0.0.7:5432`)
	withdraw := func(t *testing.T, h *harness, handler http.Handler) *httptest.ResponseRecorder {
		return call(t, handler, http.MethodPost, withdrawalPath("0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6"), "dev-responder",
			open(t, h, "dev-responder"), &vulnerabilityv1.WithdrawalRequest{Reason: "fixed"})
	}
	record := func(t *testing.T, h *harness, handler http.Handler) *httptest.ResponseRecorder {
		return call(t, handler, http.MethodPost, control.DispositionsPath, "dev-responder", open(t, h, "dev-responder"), acceptedRisk())
	}
	search := func(t *testing.T, h *harness, handler http.Handler) *httptest.ResponseRecorder {
		return call(t, handler, http.MethodPost, control.DispositionSearch, "dev-responder", open(t, h, "dev-responder"), &vulnerabilityv1.DispositionQuery{})
	}

	for name, refusal := range map[string]struct {
		err    error
		ask    func(*testing.T, *harness, http.Handler) *httptest.ResponseRecorder
		status int
		code   string
	}{
		"an agent its tenant never registered": {wrapped(disposition.ErrUnregistered), record, http.StatusUnprocessableEntity, control.CodeDispositionUnregistered},
		"a store that would not record":        {driver, record, http.StatusServiceUnavailable, control.CodeDispositionsUnavailable},
		"a disposition outside the tenants":    {wrapped(disposition.ErrUnknown), withdraw, http.StatusNotFound, control.CodeUnknownDisposition},
		"a disposition that lapsed":            {wrapped(disposition.ErrLapsed), withdraw, http.StatusConflict, control.CodeDispositionLapsed},
		"a withdrawal nobody explained":        {wrapped(disposition.ErrMalformed), withdraw, http.StatusUnprocessableEntity, control.CodeMalformedDisposition},
		"a store that would not withdraw":      {driver, withdraw, http.StatusServiceUnavailable, control.CodeDispositionsUnavailable},
		"a cursor nobody issued":               {wrapped(disposition.ErrCursor), search, http.StatusBadRequest, control.CodeBadCursor},
		"a store that would not list":          {driver, search, http.StatusServiceUnavailable, control.CodeDispositionsUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			h, kept := newHarness(t, nil), newStubDispositions()
			kept.err = refusal.err
			recorder := refusal.ask(t, h, dispositionListener(t, h, kept))
			refusedWith(t, recorder, refusal.status, refusal.code)
			if strings.Contains(recorder.Body.String(), "10.0.0.7") || strings.Contains(recorder.Body.String(), "SQLSTATE") {
				t.Errorf("the caller was told the driver's words: %s", recorder.Body)
			}
		})
	}
}

func TestACallerIsShownWhatTheyMayDoAboutVulnerabilities(t *testing.T) {
	h := newHarness(t, nil)
	handler := dispositionListener(t, h, newStubDispositions())

	for subject, want := range map[string][]controlv1.Action{
		"dev-analyst":   {controlv1.Action_ACTION_READ},
		"dev-responder": {controlv1.Action_ACTION_READ, controlv1.Action_ACTION_WRITE},
	} {
		recorder := call(t, handler, http.MethodPost, control.SessionPath, subject, "", &controlv1.SessionRequest{})
		var opened controlv1.SessionResponse
		decode(t, recorder, &opened)
		var held []controlv1.Action
		for _, permission := range opened.GetSession().GetGrant().GetPermissions() {
			if permission.GetResource() == controlv1.Resource_RESOURCE_VULNERABILITIES {
				held = append(held, permission.GetAction())
			}
		}
		if !slices.Equal(held, want) {
			t.Errorf("%s is shown %v over vulnerabilities, want %v", subject, held, want)
		}
	}
}

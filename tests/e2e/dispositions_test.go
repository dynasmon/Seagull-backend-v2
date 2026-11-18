package e2e_test

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/disposition"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// Kept in memory with the domain's own rules, so what this suite proves is the
// listener over the wire; how PostgreSQL keeps a disposition is proved against
// PostgreSQL.
type keptDispositions struct {
	mutex sync.Mutex
	held  map[string]*vulnerabilityv1.Disposition
}

func newKeptDispositions() *keptDispositions {
	return &keptDispositions{held: map[string]*vulnerabilityv1.Disposition{}}
}

func (k *keptDispositions) Record(_ context.Context, recorded *vulnerabilityv1.Disposition) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	k.held[recorded.GetDispositionId()] = recorded
	return nil
}

func (k *keptDispositions) Withdraw(_ context.Context, id string, tenants []string, withdrawal disposition.Withdrawal) (*vulnerabilityv1.Disposition, error) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	held, found := k.held[id]
	if !found || !slices.Contains(tenants, held.GetTenantId()) {
		return nil, disposition.ErrUnknown
	}
	withdrawn, err := disposition.Withdraw(held, withdrawal)
	if err != nil {
		return nil, err
	}
	k.held[id] = withdrawn
	return withdrawn, nil
}

func (k *keptDispositions) Page(_ context.Context, asked *vulnerabilityv1.DispositionQuery, tenants []string, at time.Time) (*vulnerabilityv1.DispositionPage, error) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	page := &vulnerabilityv1.DispositionPage{}
	for _, one := range k.held {
		if slices.Contains(tenants, one.GetTenantId()) && (asked.GetLapsed() || disposition.InForce(one, at)) {
			page.Dispositions = append(page.Dispositions, one)
		}
	}
	slices.SortFunc(page.Dispositions, func(one, other *vulnerabilityv1.Disposition) int {
		return cmp.Compare(other.GetDecidedAt().AsTime().UnixNano(), one.GetDecidedAt().AsTime().UnixNano())
	})
	return page, nil
}

func (c *controlPlane) dispositions(t *testing.T, client *http.Client, token string, lapsed bool) []*vulnerabilityv1.Disposition {
	t.Helper()
	response, body := c.send(t, client, http.MethodPost, control.DispositionSearch, token, &vulnerabilityv1.DispositionQuery{Lapsed: lapsed})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("listing dispositions answered %d: %s", response.StatusCode, body)
	}
	var page vulnerabilityv1.DispositionPage
	if err := proto.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode the page: %v", err)
	}
	return page.GetDispositions()
}

func TestAnAcceptedRiskIsRecordedReadAndWithdrawnOverRealMutualTLS(t *testing.T) {
	plane := startControlAPI(t, nil)
	responder, analyst, outsider := plane.caller(t, "e2e-responder"), plane.caller(t, "e2e-analyst"), plane.caller(t, "e2e-outsider")
	responding, reading, elsewhere := plane.open(t, responder).GetToken(), plane.open(t, analyst).GetToken(), plane.open(t, outsider).GetToken()

	asked := &vulnerabilityv1.DispositionRequest{
		TenantId:        "default",
		VulnerabilityId: "CVE-2026-0001",
		PackageName:     "openssl",
		Kind:            vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK,
		Reason:          "the WAF blocks the vulnerable path until 3.0.15 ships",
		ExpiresAt:       timestamppb.New(time.Now().Add(30 * 24 * time.Hour)),
	}
	if response, body := plane.send(t, analyst, http.MethodPost, control.DispositionsPath, reading, asked); response.StatusCode != http.StatusForbidden {
		t.Fatalf("an analyst recording a disposition was answered %d: %s", response.StatusCode, body)
	}
	response, body := plane.send(t, responder, http.MethodPost, control.DispositionsPath, responding, asked)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("recording answered %d: %s", response.StatusCode, body)
	}
	var recorded vulnerabilityv1.Disposition
	if err := proto.Unmarshal(body, &recorded); err != nil {
		t.Fatalf("decode the disposition: %v", err)
	}
	if recorded.GetActor() != "e2e-responder" {
		t.Errorf("the disposition was recorded as %q", recorded.GetActor())
	}

	if listed := plane.dispositions(t, analyst, reading, false); len(listed) != 1 || !proto.Equal(listed[0], &recorded) {
		t.Fatalf("the analyst reads %v", listed)
	}
	if listed := plane.dispositions(t, outsider, elsewhere, true); len(listed) != 0 {
		t.Errorf("a responder of another tenant reads %v", listed)
	}

	withdrawal := strings.Replace(control.DispositionWithdrawal, "{id}", recorded.GetDispositionId(), 1)
	ending := &vulnerabilityv1.WithdrawalRequest{Reason: "3.0.15 is installed everywhere"}
	if response, body := plane.send(t, outsider, http.MethodPost, withdrawal, elsewhere, ending); response.StatusCode != http.StatusNotFound {
		t.Fatalf("a responder of another tenant withdrawing it was answered %d: %s", response.StatusCode, body)
	}
	if response, body := plane.send(t, responder, http.MethodPost, withdrawal, responding, ending); response.StatusCode != http.StatusOK {
		t.Fatalf("withdrawing answered %d: %s", response.StatusCode, body)
	}
	if response, body := plane.send(t, responder, http.MethodPost, withdrawal, responding, ending); response.StatusCode != http.StatusConflict ||
		refusalCode(t, body) != control.CodeDispositionLapsed {
		t.Fatalf("withdrawing it again answered %d: %s", response.StatusCode, body)
	}

	if listed := plane.dispositions(t, analyst, reading, false); len(listed) != 0 {
		t.Errorf("a withdrawn disposition is still read as in force: %v", listed)
	}
	listed := plane.dispositions(t, analyst, reading, true)
	if len(listed) != 1 || listed[0].GetWithdrawnBy() != "e2e-responder" || listed[0].GetWithdrawalReason() != ending.GetReason() ||
		listed[0].GetActor() != "e2e-responder" || listed[0].GetReason() != asked.GetReason() {
		t.Errorf("asked with lapsed ones, the analyst reads %v", listed)
	}
}

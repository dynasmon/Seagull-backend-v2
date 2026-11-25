package e2e_test

import (
	"context"
	"slices"
	"sync"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the read plane's stores were asked, by any of its listings.
type holding struct {
	mu     sync.Mutex
	scopes []hunt.Scope
}

func (h *holding) record(scope hunt.Scope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scopes = append(h.scopes, scope)
}

func (h *holding) asked() []hunt.Scope {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.scopes)
}

func (h *holding) Assets(_ context.Context, asked hunt.AssetQuestion) (*inventoryv1.AssetPage, []string, error) {
	h.record(asked.Scope())
	return &inventoryv1.AssetPage{Assets: []*inventoryv1.Asset{{TenantId: "acme", AgentId: "web-01"}}}, []string{"acme", "web-01"}, nil
}

func (h *holding) Items(_ context.Context, asked hunt.ItemQuestion) (*inventoryv1.ItemPage, []string, error) {
	h.record(asked.Scope())
	return &inventoryv1.ItemPage{}, nil, nil
}

func (h *holding) Findings(_ context.Context, asked hunt.FindingQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.FindingPage{}, nil, nil
}

func (h *holding) History(_ context.Context, asked hunt.HistoryQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.FindingPage{}, nil, nil
}

func (h *holding) Assessments(_ context.Context, asked hunt.AssessmentQuestion) (*vulnerabilityv1.AssessmentPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.AssessmentPage{}, nil, nil
}

func (h *holding) Advisories(_ context.Context, asked hunt.AdvisoryQuestion) (*vulnerabilityv1.AdvisoryPage, []string, error) {
	h.record(asked.Scope())
	return &vulnerabilityv1.AdvisoryPage{}, nil, nil
}

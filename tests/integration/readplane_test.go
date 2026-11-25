//go:build integration

package integration_test

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func readPlane(t *testing.T, address string) *hunt.Lister {
	t.Helper()

	reader := migratedHunter(t, address)
	built, err := hunt.NewLister(hunt.ListerOptions{
		Inventory:       reader,
		Vulnerabilities: reader,
		Compiler:        huntCompiler(t),
		Metrics:         hunt.NewMetrics(metrics.New("readplane")),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build the read plane: %v", err)
	}
	return built
}

func granted(t *testing.T, tenants ...string) hunt.Scope {
	t.Helper()
	scope, err := hunt.NewScope(tenants)
	if err != nil {
		t.Fatalf("scope %v: %v", tenants, err)
	}
	return scope
}

func listContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// Every item of a kind an asset holds, page after page, as the read plane
// lists them: what an asset currently has, asked of the production reader.
func listedItems(t *testing.T, address, owner, agent string, kind inventoryv1.Kind) ([]*inventoryv1.HeldItem, *inventoryv1.Scan) {
	t.Helper()

	plane := readPlane(t, address)
	asked := &inventoryv1.ItemQuery{AgentId: agent, Kind: kind, Limit: 2}
	var (
		items []*inventoryv1.HeldItem
		scan  *inventoryv1.Scan
	)
	for range 1000 {
		page, err := plane.Items(listContext(t), granted(t, owner), asked)
		if err != nil {
			t.Fatalf("list the %s of %s: %v", kind, agent, err)
		}
		items, scan = append(items, page.GetItems()...), page.GetScan()
		if page.GetNextCursor() == "" {
			return items, scan
		}
		asked.Cursor = page.GetNextCursor()
	}
	t.Fatal("the listing never ended")
	return nil, nil
}

func current(t *testing.T, address, owner, agent string) map[string]string {
	t.Helper()
	items, _ := listedItems(t, address, owner, agent, inventoryv1.Kind_KIND_PACKAGE)
	versions := map[string]string{}
	for _, item := range items {
		versions[item.GetItem().GetPackage().GetName()] = item.GetItem().GetPackage().GetVersion()
	}
	return versions
}

func instances(t *testing.T, address, owner, agent string, kind inventoryv1.Kind) []string {
	t.Helper()
	items, _ := listedItems(t, address, owner, agent, kind)
	var listed []string
	for _, item := range items {
		if account := item.GetItem().GetUser(); account != nil {
			listed = append(listed, account.GetName()+" "+account.GetUid())
			continue
		}
		listed = append(listed, item.GetItem().GetPackage().GetName()+" "+item.GetItem().GetPackage().GetVersion())
	}
	slices.Sort(listed)
	return listed
}

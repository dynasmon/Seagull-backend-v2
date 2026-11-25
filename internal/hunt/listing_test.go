package hunt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type shelf struct {
	assets      []*inventoryv1.Asset
	items       []*inventoryv1.HeldItem
	scan        *inventoryv1.Scan
	findings    []*vulnerabilityv1.Finding
	assessments []*vulnerabilityv1.Assessment
	advisories  []*vulnerabilityv1.Advisory
	last        []string
	err         error
	linger      time.Duration

	askedAssets      *hunt.AssetQuestion
	askedItems       *hunt.ItemQuestion
	askedFindings    *hunt.FindingQuestion
	askedHistory     *hunt.HistoryQuestion
	askedAssessments *hunt.AssessmentQuestion
	askedAdvisories  *hunt.AdvisoryQuestion
}

func (s *shelf) Assets(_ context.Context, asked hunt.AssetQuestion) (*inventoryv1.AssetPage, []string, error) {
	s.askedAssets = &asked
	return &inventoryv1.AssetPage{Assets: s.assets}, s.last, s.err
}

func (s *shelf) Items(ctx context.Context, asked hunt.ItemQuestion) (*inventoryv1.ItemPage, []string, error) {
	s.askedItems = &asked
	if s.linger > 0 {
		select {
		case <-time.After(s.linger):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return &inventoryv1.ItemPage{Items: s.items, Scan: s.scan}, s.last, s.err
}

func (s *shelf) Findings(_ context.Context, asked hunt.FindingQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	s.askedFindings = &asked
	return &vulnerabilityv1.FindingPage{Findings: s.findings}, s.last, s.err
}

func (s *shelf) History(_ context.Context, asked hunt.HistoryQuestion) (*vulnerabilityv1.FindingPage, []string, error) {
	s.askedHistory = &asked
	return &vulnerabilityv1.FindingPage{Findings: s.findings}, s.last, s.err
}

func (s *shelf) Assessments(_ context.Context, asked hunt.AssessmentQuestion) (*vulnerabilityv1.AssessmentPage, []string, error) {
	s.askedAssessments = &asked
	return &vulnerabilityv1.AssessmentPage{Assessments: s.assessments}, s.last, s.err
}

func (s *shelf) Advisories(_ context.Context, asked hunt.AdvisoryQuestion) (*vulnerabilityv1.AdvisoryPage, []string, error) {
	s.askedAdvisories = &asked
	return &vulnerabilityv1.AdvisoryPage{Advisories: s.advisories}, s.last, s.err
}

// keeper-01 reads inventories and vulnerabilities in acme and globex,
// patcher-01 vulnerabilities alone in acme, analyst-01 telemetry alone in acme,
// and root-01 reaches the platform with every reading permission and no tenant.
func keepers(t *testing.T) *authz.Policy {
	t.Helper()
	read := func(resource authz.Resource) authz.Permission {
		return authz.Permission{Resource: resource, Action: authz.Read}
	}
	roles := []struct {
		name        string
		permissions []authz.Permission
	}{
		{"keeper", []authz.Permission{read(authz.Inventory), read(authz.Vulnerabilities)}},
		{"patcher", []authz.Permission{read(authz.Vulnerabilities)}},
		{"analyst", []authz.Permission{read(authz.Events), read(authz.Detections)}},
	}
	var declared []authz.Role
	for _, one := range roles {
		role, err := authz.NewRole(one.name, "reads what it is named for", one.permissions)
		if err != nil {
			t.Fatal(err)
		}
		declared = append(declared, role)
	}
	var bindings []authz.Binding
	for _, bound := range []struct {
		subject string
		scope   authz.Scope
		roles   []string
		tenants []string
	}{
		{"keeper-01", authz.Tenant, []string{"keeper"}, []string{"globex", "acme"}},
		{"keeper-02", authz.Tenant, []string{"keeper"}, []string{"acme"}},
		{"patcher-01", authz.Tenant, []string{"patcher"}, []string{"acme"}},
		{"analyst-01", authz.Tenant, []string{"analyst"}, []string{"acme"}},
		{"root-01", authz.Platform, []string{"keeper", "analyst"}, nil},
	} {
		binding, err := authz.NewBinding(bound.subject, bound.scope, bound.roles, bound.tenants)
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, binding)
	}
	compiled, err := authz.Compile(declared, bindings)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func lister(t *testing.T, source *shelf) *hunt.Lister {
	t.Helper()

	built, err := hunt.NewLister(hunt.ListerOptions{
		Inventory:       source,
		Vulnerabilities: source,
		Compiler:        compiler(t),
		Metrics:         hunt.NewMetrics(metrics.New("listing")),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build the lister: %v", err)
	}
	return built
}

func listing(t *testing.T, dataset hunt.Dataset, source *shelf) *hunt.Handler {
	t.Helper()

	built, err := hunt.NewHandler(dataset, hunt.HandlerOptions{
		Grants:       keepers(t),
		Lister:       lister(t, source),
		Capacity:     capacity(t, 8),
		Metrics:      hunt.NewMetrics(metrics.New("listing")),
		MaxBodyBytes: 4 << 10,
	})
	if err != nil {
		t.Fatalf("build the %s handler: %v", dataset, err)
	}
	return built
}

func ask(t *testing.T, path, caller string, body proto.Message) *http.Request {
	t.Helper()

	encoded, err := proto.Marshal(body)
	if err != nil {
		t.Fatalf("encode the question: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", hunt.ContentType)
	if caller != "" {
		request.TLS = verified(certificate(caller, nil))
	}
	return request
}

func served(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func listingRefusedAs(t *testing.T, recorder *httptest.ResponseRecorder, status int, code, field string) {
	t.Helper()

	if recorder.Code != status {
		t.Fatalf("answered %d, want %d: %s", recorder.Code, status, recorder.Body)
	}
	var refusal huntv1.Refusal
	answered(t, recorder, &refusal)
	if refusal.GetCode() != code || refusal.GetField() != field {
		t.Fatalf("refused as %q on %q, want %q on %q (%s)", refusal.GetCode(), refusal.GetField(), code, field, refusal.GetDetail())
	}
}

// What an asset has is the inventory's, so a caller the policy lets read
// telemetry and nothing else is refused before the question is read, and
// never reaches the store.
func TestAnInventoryIsReadOnlyByACallerThePolicyLetsReadIt(t *testing.T) {
	for _, dataset := range []hunt.Dataset{hunt.Assets, hunt.Items} {
		source := &shelf{}
		recorder := served(t, listing(t, dataset, source), ask(t, hunt.AssetsPath, "analyst-01", &inventoryv1.AssetQuery{}))

		listingRefusedAs(t, recorder, http.StatusForbidden, hunt.CodeForbidden, "")
		if source.askedAssets != nil || source.askedItems != nil {
			t.Errorf("a caller without inventory:read reached the store for %s", dataset)
		}
	}
}

func TestAnInventoryIsReadWithinTheTenantsTheCallerHolds(t *testing.T) {
	source := &shelf{}
	recorder := served(t, listing(t, hunt.Assets, source), ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{}))

	if recorder.Code != http.StatusOK {
		t.Fatalf("a caller holding inventory:read was answered %d: %s", recorder.Code, recorder.Body)
	}
	if tenants := source.askedAssets.Scope().Tenants(); !slices.Equal(tenants, []string{"acme", "globex"}) {
		t.Errorf("the store was asked about %v", tenants)
	}
}

func TestAGrantOfThePlatformNamingNoTenantReadsNoInventory(t *testing.T) {
	source := &shelf{}
	recorder := served(t, listing(t, hunt.Assets, source), ask(t, hunt.AssetsPath, "root-01", &inventoryv1.AssetQuery{}))

	listingRefusedAs(t, recorder, http.StatusForbidden, hunt.CodeUnscoped, "")
	if source.askedAssets != nil {
		t.Error("a caller with no tenant reached the store")
	}
}

func TestTheAssetsAskedAboutAndTheLineOfStalenessReachTheStore(t *testing.T) {
	source := &shelf{}
	before := day.Add(-48 * time.Hour)
	recorder := served(t, listing(t, hunt.Assets, source), ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{
		AgentIds: []string{"web-02", "web-01", "web-02"}, ScannedBefore: timestamppb.New(before),
	}))

	if recorder.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", recorder.Code, recorder.Body)
	}
	if agents := source.askedAssets.Agents(); !slices.Equal(agents, []string{"web-01", "web-02"}) {
		t.Errorf("the store was asked about %v", agents)
	}
	if at, asked := source.askedAssets.ScannedBefore(); !asked || !at.Equal(before) {
		t.Errorf("the store was asked for assets scanned before %v (%v)", at, asked)
	}
	if limit := source.askedAssets.Limit(); limit != limits().Page {
		t.Errorf("a question naming no limit was given %d, want the plane's page %d", limit, limits().Page)
	}
}

func TestAnAssetListingIsRefusedWhatItCannotAsk(t *testing.T) {
	many := make([]string, 257)
	for index := range many {
		many[index] = fmt.Sprintf("web-%03d", index)
	}
	for name, refused := range map[string]struct {
		asked *inventoryv1.AssetQuery
		code  string
		field string
	}{
		"more agents than a question may name":  {&inventoryv1.AssetQuery{AgentIds: many}, hunt.CodeQueryTooLarge, "agent_ids"},
		"an agent no registry could have named": {&inventoryv1.AssetQuery{AgentIds: []string{"web 01"}}, hunt.CodeUnreadableValue, "agent_ids"},
		"a page beyond the ceiling":             {&inventoryv1.AssetQuery{Limit: 501}, hunt.CodeLimitTooLarge, "limit"},
		"a cursor nobody issued":                {&inventoryv1.AssetQuery{Cursor: "AAAA.BBBB"}, hunt.CodeInvalidCursor, "cursor"},
	} {
		t.Run(name, func(t *testing.T) {
			source := &shelf{}
			listingRefusedAs(t, served(t, listing(t, hunt.Assets, source), ask(t, hunt.AssetsPath, "keeper-01", refused.asked)),
				http.StatusUnprocessableEntity, refused.code, refused.field)
			if source.askedAssets != nil {
				t.Error("a question the plane refused reached the store")
			}
		})
	}
}

func TestAnItemListingNamesTheAssetAndAKindOfIt(t *testing.T) {
	for name, refused := range map[string]struct {
		asked *inventoryv1.ItemQuery
		code  string
		field string
	}{
		"no asset":                     {&inventoryv1.ItemQuery{Kind: inventoryv1.Kind_KIND_PACKAGE}, hunt.CodeMissingField, "agent_id"},
		"an asset no registry named":   {&inventoryv1.ItemQuery{AgentId: "web/01", Kind: inventoryv1.Kind_KIND_PACKAGE}, hunt.CodeUnreadableValue, "agent_id"},
		"no kind":                      {&inventoryv1.ItemQuery{AgentId: "web-01"}, hunt.CodeUnknownKind, "kind"},
		"a kind the contract lacks":    {&inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind(99)}, hunt.CodeUnknownKind, "kind"},
		"a name a kind does not carry": {&inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_HARDWARE, Name: "R640"}, hunt.CodeUnknownField, "name"},
		"a name beyond what is stored": {&inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_PACKAGE, Name: strings.Repeat("x", 513)}, hunt.CodeUnreadableValue, "name"},
	} {
		t.Run(name, func(t *testing.T) {
			source := &shelf{}
			listingRefusedAs(t, served(t, listing(t, hunt.Items, source), ask(t, hunt.ItemsPath, "keeper-01", refused.asked)),
				http.StatusUnprocessableEntity, refused.code, refused.field)
			if source.askedItems != nil {
				t.Error("a question the plane refused reached the store")
			}
		})
	}
}

func TestAnItemListingAsksTheStoreAboutOneKindOfOneAsset(t *testing.T) {
	source := &shelf{
		items: []*inventoryv1.HeldItem{{ItemId: "a", Kind: inventoryv1.Kind_KIND_PACKAGE, Current: true}},
		scan:  &inventoryv1.Scan{Kind: inventoryv1.Kind_KIND_PACKAGE, RecordId: "inv-1", Items: 1},
		last:  []string{"curl", "8.5.0", "amd64", "dpkg"},
	}
	recorder := served(t, listing(t, hunt.Items, source), ask(t, hunt.ItemsPath, "keeper-01", &inventoryv1.ItemQuery{
		AgentId: "web-01", Kind: inventoryv1.Kind_KIND_PACKAGE, Name: "curl",
	}))

	if recorder.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", recorder.Code, recorder.Body)
	}
	var page inventoryv1.ItemPage
	answered(t, recorder, &page)
	if len(page.GetItems()) != 1 || page.GetScan().GetRecordId() != "inv-1" {
		t.Errorf("the page carried %d items and the scan %v", len(page.GetItems()), page.GetScan())
	}
	asked := source.askedItems
	if asked.Agent() != "web-01" || asked.Kind() != inventoryv1.Kind_KIND_PACKAGE {
		t.Errorf("the store was asked about %s of %s", asked.Kind(), asked.Agent())
	}
	if name, named := asked.Name(); !named || name != "curl" {
		t.Errorf("the store was asked for the history of %q (%v)", name, named)
	}
}

// The position a page ended at is the store's, and the plane signs it with the
// question: the next page resumes exactly there, and a cursor carried into
// another question, or past another caller's grant, is refused rather than read
// as a position in it.
func TestAPageOfAnInventoryResumesWhereTheStoreSaidItEnded(t *testing.T) {
	source := &shelf{
		assets: []*inventoryv1.Asset{{TenantId: "acme", AgentId: "web-01"}},
		last:   []string{"acme", "web-01"},
	}
	handler := listing(t, hunt.Assets, source)
	first := served(t, handler, ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{Limit: 1}))
	var page inventoryv1.AssetPage
	answered(t, first, &page)
	if page.GetNextCursor() == "" {
		t.Fatal("a page that carried an asset was not followed by a cursor")
	}

	served(t, handler, ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{Limit: 1, Cursor: page.GetNextCursor()}))
	if after := source.askedAssets.After(); !slices.Equal(after, []string{"acme", "web-01"}) {
		t.Errorf("the second page was asked to start after %q", after)
	}

	listingRefusedAs(t, served(t, handler, ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{Limit: 2, Cursor: page.GetNextCursor()})),
		http.StatusUnprocessableEntity, hunt.CodeInvalidCursor, "cursor")
	listingRefusedAs(t, served(t, handler, ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{Limit: 1, AgentIds: []string{"web-01"}, Cursor: page.GetNextCursor()})),
		http.StatusUnprocessableEntity, hunt.CodeInvalidCursor, "cursor")

	refusedAs := func(caller string) {
		t.Helper()
		listingRefusedAs(t, served(t, handler, ask(t, hunt.AssetsPath, caller, &inventoryv1.AssetQuery{Limit: 1, Cursor: page.GetNextCursor()})),
			http.StatusUnprocessableEntity, hunt.CodeInvalidCursor, "cursor")
	}
	refusedAs("keeper-02")

	items := listing(t, hunt.Items, &shelf{})
	listingRefusedAs(t, served(t, items, ask(t, hunt.ItemsPath, "keeper-01", &inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_PACKAGE, Cursor: page.GetNextCursor()})),
		http.StatusUnprocessableEntity, hunt.CodeInvalidCursor, "cursor")
}

func TestAnEmptyPageSaysTheListingIsExhausted(t *testing.T) {
	source := &shelf{}
	recorder := served(t, listing(t, hunt.Assets, source), ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{}))

	var page inventoryv1.AssetPage
	answered(t, recorder, &page)
	if page.GetNextCursor() != "" {
		t.Errorf("an empty page was followed by %q", page.GetNextCursor())
	}
}

// A page the store cannot say where it ended cannot be resumed, so it is the
// platform's failure rather than an answer that silently has no next page.
func TestAPageWhoseEndTheStoreCannotNameIsNotAnswered(t *testing.T) {
	source := &shelf{assets: []*inventoryv1.Asset{{TenantId: "acme", AgentId: "web-01"}}}
	recorder := served(t, listing(t, hunt.Assets, source), ask(t, hunt.AssetsPath, "keeper-01", &inventoryv1.AssetQuery{}))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a page with no position was answered %d", recorder.Code)
	}
}

func TestAStoreThatCouldNotListIsNotTheCallersFault(t *testing.T) {
	for name, failure := range map[string]struct {
		err    error
		status int
	}{
		"unreachable":     {errors.New("connection refused"), http.StatusServiceUnavailable},
		"out of its time": {context.DeadlineExceeded, http.StatusGatewayTimeout},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := served(t, listing(t, hunt.Items, &shelf{err: failure.err}),
				ask(t, hunt.ItemsPath, "keeper-01", &inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_SERVICE}))
			if recorder.Code != failure.status || recorder.Header().Get("Retry-After") == "" {
				t.Errorf("answered %d with Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
			}
		})
	}
}

func TestAListerNeedsBothStoresACompilerAndMetrics(t *testing.T) {
	source := &shelf{}
	for name, options := range map[string]hunt.ListerOptions{
		"no inventory":       {Vulnerabilities: source, Compiler: compiler(t), Metrics: hunt.NewMetrics(metrics.New("a"))},
		"no vulnerabilities": {Inventory: source, Compiler: compiler(t), Metrics: hunt.NewMetrics(metrics.New("b"))},
		"no compiler":        {Inventory: source, Vulnerabilities: source, Metrics: hunt.NewMetrics(metrics.New("c"))},
		"no metrics":         {Inventory: source, Vulnerabilities: source, Compiler: compiler(t)},
	} {
		if _, err := hunt.NewLister(options); err == nil {
			t.Errorf("a lister with %s was built", name)
		}
	}
	if _, err := hunt.NewHandler(hunt.Assets, hunt.HandlerOptions{Grants: keepers(t), Hunter: hunter(t, &store{}),
		Capacity: capacity(t, 1), Metrics: hunt.NewMetrics(metrics.New("d")), MaxBodyBytes: 1024}); err == nil {
		t.Error("a listing handler was built with no lister")
	}
}

func TestAListingIsHeldToTheReadBudget(t *testing.T) {
	started := time.Now()
	_, err := lister(t, &shelf{linger: time.Minute}).Items(context.Background(), scoped(t, "acme"),
		&inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_PACKAGE})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a store that never answered produced %v", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("the caller waited %s for a store given %s", elapsed, limits().Timeout)
	}
}

func TestEachListingIsReadUnderThePermissionOfWhatItLists(t *testing.T) {
	for dataset, question := range map[hunt.Dataset]struct {
		path   string
		asked  proto.Message
		status int
	}{
		hunt.Assets:         {hunt.AssetsPath, &inventoryv1.AssetQuery{}, http.StatusForbidden},
		hunt.Items:          {hunt.ItemsPath, &inventoryv1.ItemQuery{AgentId: "web-01", Kind: inventoryv1.Kind_KIND_PACKAGE}, http.StatusForbidden},
		hunt.Findings:       {hunt.FindingsPath, &vulnerabilityv1.FindingQuery{}, http.StatusOK},
		hunt.FindingHistory: {hunt.FindingHistoryPath, &vulnerabilityv1.FindingHistoryQuery{AgentId: "web-01", ItemId: "a232cc002c99c96b", VulnerabilityId: "CVE-2024-6387"}, http.StatusOK},
		hunt.Assessments:    {hunt.AssessmentsPath, &vulnerabilityv1.AssessmentQuery{}, http.StatusOK},
		hunt.Advisories: {hunt.AdvisoriesPath, &vulnerabilityv1.AdvisoryQuery{Question: &vulnerabilityv1.AdvisoryQuery_Advisory{
			Advisory: &vulnerabilityv1.AdvisoryName{Source: "osv", Id: "DSA-5764-1"}}}, http.StatusOK},
	} {
		if recorder := served(t, listing(t, dataset, &shelf{}), ask(t, question.path, "patcher-01", question.asked)); recorder.Code != question.status {
			t.Errorf("a caller holding vulnerabilities:read alone asked %s and was answered %d, want %d: %s", dataset, recorder.Code, question.status, recorder.Body)
		}
	}
}

func TestAQuestionAboutWhatIsWrongWithAnAssetIsRefusedWhatItCannotAsk(t *testing.T) {
	many := make([]string, 257)
	for index := range many {
		many[index] = fmt.Sprintf("V%03d", index)
	}
	for name, refused := range map[string]struct {
		dataset hunt.Dataset
		path    string
		asked   proto.Message
		code    string
		field   string
	}{
		"a state nobody is in": {hunt.Findings, hunt.FindingsPath,
			&vulnerabilityv1.FindingQuery{States: []vulnerabilityv1.FindingState{vulnerabilityv1.FindingState_FINDING_STATE_UNSPECIFIED}}, hunt.CodeUnknownState, "states"},
		"a state the contract lacks": {hunt.Findings, hunt.FindingsPath,
			&vulnerabilityv1.FindingQuery{States: []vulnerabilityv1.FindingState{99}}, hunt.CodeUnknownState, "states"},
		"more vulnerabilities than a question may name": {hunt.Findings, hunt.FindingsPath,
			&vulnerabilityv1.FindingQuery{VulnerabilityIds: many}, hunt.CodeQueryTooLarge, "vulnerability_ids"},
		"a package named with a control character": {hunt.Findings, hunt.FindingsPath,
			&vulnerabilityv1.FindingQuery{PackageNames: []string{"open\nssl"}}, hunt.CodeUnreadableValue, "package_names"},
		"a history of no item": {hunt.FindingHistory, hunt.FindingHistoryPath,
			&vulnerabilityv1.FindingHistoryQuery{AgentId: "web-01", VulnerabilityId: "CVE-2024-6387"}, hunt.CodeMissingField, "item_id"},
		"a history of no vulnerability": {hunt.FindingHistory, hunt.FindingHistoryPath,
			&vulnerabilityv1.FindingHistoryQuery{AgentId: "web-01", ItemId: "a232cc002c99c96b"}, hunt.CodeMissingField, "vulnerability_id"},
		"an advisory asked for by nothing": {hunt.Advisories, hunt.AdvisoriesPath,
			&vulnerabilityv1.AdvisoryQuery{}, hunt.CodeMissingField, "question"},
		"an advisory named by its source alone": {hunt.Advisories, hunt.AdvisoriesPath,
			&vulnerabilityv1.AdvisoryQuery{Question: &vulnerabilityv1.AdvisoryQuery_Advisory{Advisory: &vulnerabilityv1.AdvisoryName{Source: "osv"}}}, hunt.CodeMissingField, "advisory.id"},
		"a package of no ecosystem": {hunt.Advisories, hunt.AdvisoriesPath,
			&vulnerabilityv1.AdvisoryQuery{Question: &vulnerabilityv1.AdvisoryQuery_Package{Package: &vulnerabilityv1.AdvisedPackage{Name: "openssl"}}}, hunt.CodeMissingField, "package.ecosystem"},
		"assessments of an agent no registry named": {hunt.Assessments, hunt.AssessmentsPath,
			&vulnerabilityv1.AssessmentQuery{AgentIds: []string{"web/01"}}, hunt.CodeUnreadableValue, "agent_ids"},
	} {
		t.Run(name, func(t *testing.T) {
			source := &shelf{}
			listingRefusedAs(t, served(t, listing(t, refused.dataset, source), ask(t, refused.path, "keeper-01", refused.asked)),
				http.StatusUnprocessableEntity, refused.code, refused.field)
			if source.askedFindings != nil || source.askedHistory != nil || source.askedAdvisories != nil || source.askedAssessments != nil {
				t.Error("a question the plane refused reached the store")
			}
		})
	}
}

func TestTheStatesAFindingListingAsksForReachTheStoreOnceEach(t *testing.T) {
	source := &shelf{}
	affected, fixed := vulnerabilityv1.FindingState_FINDING_STATE_AFFECTED, vulnerabilityv1.FindingState_FINDING_STATE_FIXED
	recorder := served(t, listing(t, hunt.Findings, source), ask(t, hunt.FindingsPath, "keeper-01",
		&vulnerabilityv1.FindingQuery{States: []vulnerabilityv1.FindingState{fixed, affected, fixed}, VulnerabilityIds: []string{"CVE-2024-6387"}}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", recorder.Code, recorder.Body)
	}
	if states := source.askedFindings.States(); !slices.Equal(states, []vulnerabilityv1.FindingState{affected, fixed}) {
		t.Errorf("the store was asked for %v", states)
	}
	if asked := source.askedFindings.Vulnerabilities(); !slices.Equal(asked, []string{"CVE-2024-6387"}) {
		t.Errorf("the store was asked about %v", asked)
	}
}

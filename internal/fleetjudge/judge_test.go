package fleetjudge_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/fleetjudge"
	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

var start = time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)

type batch struct {
	records []fleetjudge.Record
	done    chan struct{}
}

type memLog struct {
	replay    []fleetjudge.Record
	live      chan batch
	following chan struct{}
	once      sync.Once
}

func newLog(replay ...fleetjudge.Record) *memLog {
	return &memLog{replay: replay, live: make(chan batch), following: make(chan struct{})}
}

func (m *memLog) Replay(ctx context.Context, deliver fleetjudge.Deliver) error {
	if len(m.replay) == 0 {
		return nil
	}
	return deliver(ctx, m.replay)
}

func (m *memLog) Follow(ctx context.Context, deliver fleetjudge.Deliver) error {
	m.once.Do(func() { close(m.following) })
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case next := <-m.live:
			err := deliver(ctx, next.records)
			close(next.done)
			if err != nil {
				return err
			}
		}
	}
}

type statusLog struct {
	*memLog
	mu     sync.Mutex
	behind int64
	err    error
}

func (s *statusLog) Behind(context.Context) (int64, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.behind, time.Time{}, s.err
}

func (s *statusLog) lag(behind int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.behind = behind
}

type published struct {
	mu      sync.Mutex
	decided []*agentv1.Finding
	fail    int
}

func (p *published) Publish(_ context.Context, decided []*agentv1.Finding) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail > 0 {
		p.fail--
		return errors.New("the backbone is unreachable")
	}
	for _, one := range decided {
		p.decided = append(p.decided, proto.Clone(one).(*agentv1.Finding))
	}
	return nil
}

func (p *published) all() []*agentv1.Finding {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*agentv1.Finding(nil), p.decided...)
}

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

type harness struct {
	t          *testing.T
	clock      *clock
	status     *statusLog
	admissions *memLog
	beacons    *memLog
	findings   *memLog
	published  *published
	exported   *metrics.Registry
	judge      *fleetjudge.Judge
	stop       context.CancelFunc
	done       chan error
	maxAgents  int
}

func encoded(t *testing.T, key string, message proto.Message) fleetjudge.Record {
	t.Helper()
	value, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return fleetjudge.Record{Key: []byte(key), Value: value}
}

func admitted(t *testing.T, agentID string, state agentv1.State, changed time.Time) fleetjudge.Record {
	return encoded(t, agentID, &agentv1.Admission{AgentId: agentID, TenantId: "default", State: state, Revision: 2, ChangedAt: timestamppb.New(changed)})
}

func reported(t *testing.T, agentID string, sequence uint64, arrived time.Time, condition agentv1.Status_Condition) fleetjudge.Record {
	report := fixtures.Report{AgentID: agentID, Sequence: sequence, At: arrived.Add(-time.Second), Interval: time.Minute, Condition: condition}.Status()
	report.Origin.TenantId = "default"
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-1", BatchId: "status-" + strconv.FormatUint(sequence, 10)}
	return encoded(t, agentID, report)
}

func remembered(t *testing.T, decided *agentv1.Finding) fleetjudge.Record {
	return encoded(t, decided.GetAgentId(), decided)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{
		t: t, clock: &clock{at: start},
		status: &statusLog{memLog: newLog()}, admissions: newLog(), beacons: newLog(), findings: newLog(),
		published: &published{}, exported: metrics.New("fleet-judge-test"), maxAgents: 100,
	}
}

func (h *harness) run() {
	h.t.Helper()
	judge, err := fleetjudge.New(fleetjudge.Options{
		Status: h.status, Admissions: h.admissions, Beacons: h.beacons, Findings: h.findings, Decisions: h.published,
		Metrics: fleetjudge.NewMetrics(h.exported), Logger: slog.New(slog.DiscardHandler),
		Every: time.Minute, StaleAfter: 2 * time.Minute, MaxAgents: h.maxAgents, Again: 24 * time.Hour, Now: h.clock.now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	h.judge, h.stop, h.done = judge, stop, make(chan error, 1)
	go func() { h.done <- judge.Run(ctx) }()
	for _, followed := range []*memLog{h.status.memLog, h.admissions, h.beacons} {
		select {
		case <-followed.following:
		case err := <-h.done:
			h.t.Fatalf("the judge stopped before following: %v", err)
		case <-time.After(10 * time.Second):
			h.t.Fatal("the judge never followed its logs")
		}
	}
	h.t.Cleanup(func() {
		h.stop()
		if err := <-h.done; err != nil {
			h.t.Errorf("the judge stopped with %v", err)
		}
	})
}

func (h *harness) send(log *memLog, records ...fleetjudge.Record) {
	h.t.Helper()
	delivered := batch{records: records, done: make(chan struct{})}
	select {
	case log.live <- delivered:
	case <-time.After(10 * time.Second):
		h.t.Fatal("the judge did not take a record")
	}
	<-delivered.done
}

// At names a moment of the test: the clock moves there, the gateway says it
// admits, as it would every few seconds, and the judge sweeps.
func (h *harness) at(after time.Duration) {
	h.t.Helper()
	h.clock.set(start.Add(after))
	h.send(h.beacons, encoded(h.t, "gateway-1", listening.Beacon("gateway-1", start.Add(after), 5*time.Second, true)))
	h.judge.Sweep(context.Background())
}

func (h *harness) quietly(after time.Duration) {
	h.t.Helper()
	h.clock.set(start.Add(after))
	h.judge.Sweep(context.Background())
}

func counted(t *testing.T, registry *metrics.Registry, series string) float64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if value, found := strings.CutPrefix(line, series+" "); found {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return parsed
		}
	}
	t.Fatalf("%s is not exported", series)
	return 0
}

func silentAgent(t *testing.T) *harness {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{reported(t, "web-01", 41, start, agentv1.Status_CONDITION_RUNNING)}
	return h
}

func TestASilentAgentIsFoundOnceAfterFiveIntervalsOfAPlatformListeningThroughout(t *testing.T) {
	h := silentAgent(t)
	h.run()

	h.at(time.Minute)
	h.at(5*time.Minute + 30*time.Second)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a silence was decided after %s of listening: %v", 4*time.Minute+30*time.Second, got)
	}

	h.at(6*time.Minute + time.Second)
	h.at(7 * time.Minute)
	got := h.published.all()
	if len(got) != 1 {
		t.Fatalf("the silence was decided %d times", len(got))
	}
	silence := got[0]
	if err := agentfinding.Validate(silence); err != nil || silence.GetKind() != agentv1.Finding_KIND_SILENCE ||
		silence.GetState() != agentv1.Finding_STATE_OPEN || !silence.GetOpenedAt().AsTime().Equal(start.Add(5*time.Minute)) ||
		silence.GetTenantId() != "default" || silence.GetReports()[0].GetSequence() != 41 || silence.GetReports()[0].GetStopping() {
		t.Errorf("the silence was decided as %v (%v)", silence, err)
	}
	if open := counted(t, h.exported, `seagull_fleetjudge_open_findings{kind="silence"}`); open != 1 {
		t.Errorf("%v silences are counted open", open)
	}
}

func TestNoSilenceIsFoundWhileNoGatewaySaysItAdmits(t *testing.T) {
	h := silentAgent(t)
	h.beacons.replay = []fleetjudge.Record{encoded(t, "gateway-1", listening.Beacon("gateway-1", start, 5*time.Second, true))}
	h.run()
	h.quietly(0)
	if serving := counted(t, h.exported, "seagull_fleetjudge_serving_gateways"); serving != 0 {
		t.Fatalf("a beacon read back from before the judge started counts %v gateways as serving", serving)
	}

	for minutes := 1; minutes <= 20; minutes++ {
		h.quietly(time.Duration(minutes) * time.Minute)
	}
	h.clock.set(start.Add(21 * time.Minute))
	h.send(h.beacons, encoded(t, "gateway-1", listening.Beacon("gateway-1", start.Add(21*time.Minute), 5*time.Second, false)))
	h.judge.Sweep(context.Background())
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a silence was decided while no gateway admitted: %v", got)
	}
	if listens := counted(t, h.exported, "seagull_fleetjudge_listening"); listens != 0 {
		t.Errorf("the judge says it listens: %v", listens)
	}
}

func TestNoSilenceIsFoundWhileTheJudgeCannotConfirmItReadsTheEndOfTheStatusLog(t *testing.T) {
	h := silentAgent(t)
	h.status.lag(3)
	h.run()

	for minutes := 1; minutes <= 20; minutes++ {
		h.at(time.Duration(minutes) * time.Minute)
	}
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a silence was decided while reports were left unread: %v", got)
	}
}

func TestAfterAStretchItCouldNotConfirmTheJudgeListensAWholeThresholdBeforeItJudges(t *testing.T) {
	h := silentAgent(t)
	h.run()

	h.at(time.Minute)
	h.at(3 * time.Minute)
	h.status.lag(1)
	h.at(4 * time.Minute)
	h.at(5*time.Minute + time.Second)
	h.status.lag(0)
	h.at(6 * time.Minute)
	h.at(10*time.Minute + 59*time.Second)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a silence was decided before a whole threshold of listening followed the break: %v", got)
	}
	h.at(11 * time.Minute)
	if got := h.published.all(); len(got) != 1 {
		t.Fatalf("the silence was decided %d times once the platform had listened a whole threshold again", len(got))
	}
}

func TestASilenceClosesWhenTheAgentReportsAgain(t *testing.T) {
	h := silentAgent(t)
	h.run()
	h.at(time.Minute)
	h.at(6*time.Minute + time.Second)

	h.clock.set(start.Add(8 * time.Minute))
	h.send(h.status.memLog, reported(t, "web-01", 41, start, agentv1.Status_CONDITION_RUNNING))
	h.send(h.status.memLog, reported(t, "web-01", 42, start.Add(8*time.Minute), agentv1.Status_CONDITION_RUNNING))
	h.at(8 * time.Minute)

	got := h.published.all()
	if len(got) != 2 {
		t.Fatalf("the silence was decided %d times, want an opening and a closing", len(got))
	}
	closed := got[1]
	if err := agentfinding.Validate(closed); err != nil || closed.GetFindingId() != got[0].GetFindingId() ||
		closed.GetClosure() != agentv1.Finding_CLOSURE_HEARD || !closed.GetClosedAt().AsTime().Equal(start.Add(8*time.Minute)) ||
		len(closed.GetReports()) != 2 || closed.GetReports()[1].GetSequence() != 42 {
		t.Errorf("the silence closed as %v (%v)", closed, err)
	}
}

func TestASilenceClosesWhenTheRegistryStopsAdmittingTheAgentAndAnAgentItDoesNotAdmitIsNeverSilent(t *testing.T) {
	h := silentAgent(t)
	h.admissions.replay = append(h.admissions.replay, admitted(t, "web-02", agentv1.State_STATE_DISABLED, start.Add(-time.Hour)))
	h.status.replay = append(h.status.replay, reported(t, "web-02", 7, start, agentv1.Status_CONDITION_RUNNING))
	h.run()
	h.at(time.Minute)
	h.at(6*time.Minute + time.Second)

	h.send(h.admissions, admitted(t, "web-01", agentv1.State_STATE_REVOKED, start.Add(9*time.Minute)))
	h.at(10 * time.Minute)

	got := h.published.all()
	if len(got) != 2 || got[0].GetAgentId() != "web-01" || got[1].GetClosure() != agentv1.Finding_CLOSURE_NOT_ADMITTED ||
		!got[1].GetClosedAt().AsTime().Equal(start.Add(9*time.Minute)) {
		t.Fatalf("the decisions were %v, want web-01 silent and then closed when it was revoked", got)
	}
}

func TestARestartClosesWhatItLeftOpenIfTheAgentReportedMeanwhileAndKeepsTheRestOpen(t *testing.T) {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{
		admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour)),
		admitted(t, "web-02", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour)),
	}
	first := fixtures.Report{AgentID: "web-01", Sequence: 41, At: start.Add(-time.Second), Interval: time.Minute}.Status()
	first.Origin.TenantId, first.Reception = "default", &eventv1.Reception{IngestTime: timestamppb.New(start), Gateway: "gateway-1", BatchId: "status-41"}
	other := fixtures.Report{AgentID: "web-02", Sequence: 7, At: start.Add(-time.Second), Interval: time.Minute}.Status()
	other.Origin.TenantId, other.Reception = "default", &eventv1.Reception{IngestTime: timestamppb.New(start), Gateway: "gateway-1", BatchId: "status-7"}
	left := agentfinding.Silence("default", "web-01", agentfinding.HeardOf(first), start.Add(6*time.Minute))
	stillSilent := agentfinding.Silence("default", "web-02", agentfinding.HeardOf(other), start.Add(6*time.Minute))
	h.findings.replay = []fleetjudge.Record{remembered(t, left), remembered(t, stillSilent)}
	h.status.replay = []fleetjudge.Record{
		encoded(t, "web-01", first), reported(t, "web-01", 42, start.Add(20*time.Minute), agentv1.Status_CONDITION_RUNNING),
		encoded(t, "web-02", other),
	}
	h.clock.set(start.Add(30 * time.Minute))
	h.run()
	h.quietly(30 * time.Minute)

	got := h.published.all()
	if len(got) != 1 || got[0].GetFindingId() != left.GetFindingId() || got[0].GetClosure() != agentv1.Finding_CLOSURE_HEARD ||
		!got[0].GetClosedAt().AsTime().Equal(start.Add(20*time.Minute)) {
		t.Fatalf("after a restart the judge decided %v, want only web-01's silence closed by its report at 12:20", got)
	}
	h.at(31 * time.Minute)
	h.at(35 * time.Minute)
	if again := h.published.all(); len(again) != 1 {
		t.Errorf("the silence still open was decided again before a day passed: %v", again[1:])
	}
}

func TestAnOpenSilenceIsDecidedAgainEveryDayItStaysOpen(t *testing.T) {
	h := silentAgent(t)
	h.run()
	h.at(time.Minute)
	h.at(6*time.Minute + time.Second)
	h.at(24*time.Hour + 6*time.Minute)
	if got := h.published.all(); len(got) != 1 {
		t.Fatalf("the silence was decided again before a whole day passed: %v", got)
	}
	h.at(24*time.Hour + 6*time.Minute + time.Second)

	got := h.published.all()
	if len(got) != 2 || got[1].GetFindingId() != got[0].GetFindingId() || got[1].GetState() != agentv1.Finding_STATE_OPEN ||
		!got[1].GetDecidedAt().AsTime().Equal(start.Add(24*time.Hour+6*time.Minute+time.Second)) || !proto.Equal(got[1].GetOpenedAt(), got[0].GetOpenedAt()) {
		t.Fatalf("a day later the decisions were %v", got)
	}
}

func TestADecisionTheBackboneDidNotTakeIsPublishedAgainAtTheNextSweep(t *testing.T) {
	h := silentAgent(t)
	h.published.fail = 1
	h.run()
	h.at(time.Minute)
	h.at(6*time.Minute + time.Second)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a refused publication was recorded: %v", got)
	}
	if left := counted(t, h.exported, "seagull_fleetjudge_unpublished_decisions"); left != 1 {
		t.Errorf("%v decisions are counted unpublished", left)
	}
	h.at(6*time.Minute + 30*time.Second)
	if got := h.published.all(); len(got) != 1 || got[0].GetState() != agentv1.Finding_STATE_OPEN {
		t.Fatalf("the refused decision was published as %v", got)
	}
}

func TestAnAgentThatSaidItWasStoppingIsSilentTooAndTheFindingSaysSo(t *testing.T) {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{reported(t, "web-01", 41, start, agentv1.Status_CONDITION_STOPPED)}
	h.run()
	h.at(time.Minute)
	h.at(6*time.Minute + time.Second)
	if got := h.published.all(); len(got) != 1 || !got[0].GetReports()[0].GetStopping() {
		t.Fatalf("a stopped agent was decided as %v", got)
	}
}

func TestAJudgeHoldingMoreAgentsThanItsCeilingJudgesNoSilence(t *testing.T) {
	h := silentAgent(t)
	h.maxAgents = 1
	h.admissions.replay = append(h.admissions.replay, admitted(t, "web-02", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour)))
	h.status.replay = append(h.status.replay, reported(t, "web-02", 7, start, agentv1.Status_CONDITION_RUNNING))
	h.run()
	for minutes := 1; minutes <= 20; minutes++ {
		h.at(time.Duration(minutes) * time.Minute)
	}
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a judge that could not hold every agent decided %v", got)
	}
	if refused := counted(t, h.exported, "seagull_fleetjudge_agents_refused_total"); refused < 1 {
		t.Errorf("%v agents are counted refused", refused)
	}
}

func TestAJudgeNeedsWhatItReadsAndSaneBounds(t *testing.T) {
	base := fleetjudge.Options{
		Status: &statusLog{memLog: newLog()}, Admissions: newLog(), Beacons: newLog(), Findings: newLog(), Decisions: &published{},
		Metrics: fleetjudge.NewMetrics(metrics.New("fleet-judge-options")), Logger: slog.New(slog.DiscardHandler),
		Every: time.Second, StaleAfter: 2 * time.Second, MaxAgents: 1, Again: time.Hour,
	}
	for name, change := range map[string]func(*fleetjudge.Options){
		"no status log":         func(o *fleetjudge.Options) { o.Status = nil },
		"nowhere to publish":    func(o *fleetjudge.Options) { o.Decisions = nil },
		"a stale bound too low": func(o *fleetjudge.Options) { o.StaleAfter = time.Second },
		"no agent held":         func(o *fleetjudge.Options) { o.MaxAgents = 0 },
		"deciding too often":    func(o *fleetjudge.Options) { o.Again = time.Millisecond },
	} {
		options := base
		change(&options)
		if _, err := fleetjudge.New(options); err == nil {
			t.Errorf("a judge with %s was built", name)
		}
	}
}

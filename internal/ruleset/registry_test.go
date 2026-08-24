package ruleset_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
)

func TestARegistryNeedsWhatItIsPinnedBy(t *testing.T) {
	complete := options(t, held(compiled(t, rule("a.rule"))))

	cases := map[string]func(*ruleset.Options){
		"no source":  func(o *ruleset.Options) { o.Source = nil },
		"no metrics": func(o *ruleset.Options) { o.Metrics = nil },
		"no logger":  func(o *ruleset.Options) { o.Logger = nil },
	}
	for name, without := range cases {
		t.Run(name, func(t *testing.T) {
			incomplete := complete
			without(&incomplete)

			if _, err := ruleset.New(incomplete); err == nil {
				t.Errorf("a registry with %s was built", name)
			}
		})
	}
}

// A process running against a ruleset nobody chose is worse than one that
// refuses to run, so neither an unreadable source nor an inconsistent one
// starts a registry.
func TestAProcessThatCannotReadItsRulesDoesNotStart(t *testing.T) {
	refused := errors.New("rules/core/ssh.yml:3:5: rule \"a.rule\": severity is missing")

	if _, err := ruleset.New(options(t, failing(refused))); !errors.Is(err, refused) {
		t.Errorf("a registry started on a source that refused its rules: %v", err)
	}
	twice := held(compiled(t, rule("a.rule")), compiled(t, draft("a.rule")))
	if _, err := ruleset.New(options(t, twice)); err == nil {
		t.Error("a registry started on a source holding one id twice")
	}
}

func TestARegistryIsPinnedToWhatItLoaded(t *testing.T) {
	source := held(compiled(t, rule("a.rule")), compiled(t, draft("b.rule")))
	registry := pinned(t, source)

	current := registry.Current()
	if current == nil {
		t.Fatal("a registry that started is pinned to nothing")
	}
	if current.Rules() != 2 || current.Running() != 1 {
		t.Errorf("the registry is pinned to %d rules of which %d run", current.Rules(), current.Running())
	}
}

func TestAReloadPinsTheRegistryToWhatChanged(t *testing.T) {
	source := held(compiled(t, rule("a.rule")))
	registry := pinned(t, source)
	before := registry.Current()

	source.hold(compiled(t, rule("a.rule")), compiled(t, rule("b.rule")))
	after, err := registry.Reload()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if after.ID() == before.ID() {
		t.Errorf("a ruleset that grew a rule is still named %s", after.ID())
	}
	if registry.Current() != after {
		t.Error("the registry is not pinned to what the reload produced")
	}
	if after.Running() != 2 {
		t.Errorf("the new ruleset runs %d rules", after.Running())
	}
}

// Nothing is replaced unless the whole ruleset read and compiled, so a source
// that breaks between deployments leaves the process running what it had.
func TestAReloadThatFailsLeavesTheRulesetAlone(t *testing.T) {
	source := held(compiled(t, rule("a.rule")))
	registry := pinned(t, source)
	before := registry.Current()

	source.fail(errors.New("packs/core/auth.yml:12:7: rule \"a.rule\": match.all is not a list of terms"))
	if _, err := registry.Reload(); err == nil {
		t.Fatal("a reload of a source that refused its rules was applied")
	}
	if registry.Current() != before {
		t.Error("a reload that failed still moved the registry")
	}
}

func TestAReloadOfTheSameRulesChangesNothing(t *testing.T) {
	source := held(compiled(t, rule("a.rule")))
	registry := pinned(t, source)
	before := registry.Current()

	after, err := registry.Reload()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after != before {
		t.Error("reading the same rules again produced a different ruleset")
	}
}

// Putting a ruleset back is a swap and not another load, which is what a
// rollback will be built out of.
func TestReplacingGivesBackWhatItReplaced(t *testing.T) {
	registry := pinned(t, held(compiled(t, rule("a.rule"))))
	first := registry.Current()

	second := compose(t, compiled(t, rule("b.rule")))
	if replaced := registry.Replace(second); replaced != first {
		t.Errorf("replacing gave back %v", replaced)
	}
	if registry.Current() != second {
		t.Error("the registry is not pinned to what replaced the first ruleset")
	}
	if replaced := registry.Replace(first); replaced != second {
		t.Errorf("putting the first ruleset back gave back %v", replaced)
	}
	if registry.Current() != first {
		t.Error("the registry did not go back to the ruleset it started on")
	}
}

func TestTheRulesetIsIdentifiableInMetrics(t *testing.T) {
	registry := metrics.New("analysis-engine")
	source := held(compiled(t, rule("a.rule")))

	pinnedTo, err := ruleset.New(ruleset.Options{
		Source:  source,
		Metrics: ruleset.NewMetrics(registry),
		Logger:  quiet(),
	})
	if err != nil {
		t.Fatalf("build a registry: %v", err)
	}
	first := pinnedTo.Current().ID()

	exposition := scrape(t, registry)
	for _, expected := range []string{
		`seagull_ruleset_info{ruleset="` + string(first) + `"} 1`,
		`seagull_ruleset_rules{state="held"} 1`,
		`seagull_ruleset_rules{state="running"} 1`,
		"seagull_ruleset_loaded_timestamp_seconds ",
	} {
		if !strings.Contains(exposition, expected) {
			t.Errorf("the exposition does not carry %q:\n%s", expected, exposition)
		}
	}

	source.hold(compiled(t, rule("a.rule")), compiled(t, rule("b.rule")))
	if _, err := pinnedTo.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	source.fail(errors.New("unreadable"))
	if _, err := pinnedTo.Reload(); err == nil {
		t.Fatal("a reload of an unreadable source was applied")
	}

	exposition = scrape(t, registry)
	if strings.Contains(exposition, string(first)) {
		t.Errorf("the ruleset the process left behind is still exposed:\n%s", exposition)
	}
	if count := strings.Count(exposition, "seagull_ruleset_info{"); count != 1 {
		t.Errorf("the exposition carries %d ruleset identities and a process is pinned to one", count)
	}
	for _, expected := range []string{
		`seagull_ruleset_reloads_total{outcome="applied"} 1`,
		`seagull_ruleset_reloads_total{outcome="refused"} 1`,
	} {
		if !strings.Contains(exposition, expected) {
			t.Errorf("the exposition does not carry %q:\n%s", expected, exposition)
		}
	}
}

// An event is decided against one ruleset from beginning to end. A reader
// holding a snapshot while the registry is replaced under it must never see a
// ruleset that is half of one and half of the other.
func TestAnEventIsDecidedAgainstAConsistentRuleset(t *testing.T) {
	small := compose(t, compiled(t, rule("a.rule")))
	large := compose(t, compiled(t, rule("a.rule")), compiled(t, rule("b.rule")), compiled(t, draft("c.rule")))

	var turn atomic.Int64
	registry := pinned(t, ruleset.SourceFunc(func() ([]*detection.Program, error) {
		if turn.Add(1)%2 == 0 {
			return []*detection.Program{compiled(t, rule("a.rule"))}, nil
		}
		return []*detection.Program{
			compiled(t, rule("a.rule")), compiled(t, rule("b.rule")), compiled(t, draft("c.rule")),
		}, nil
	}))

	consistent := map[ruleset.ID]int{small.ID(): small.Running(), large.ID(): large.Running()}

	var waiting sync.WaitGroup
	for range 8 {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			for range 300 {
				snapshot := registry.Current()
				running := len(ids(snapshot, authentication))
				expected, known := consistent[snapshot.ID()]
				if !known {
					t.Errorf("a reader saw the ruleset %s, which nothing composed", snapshot.ID())
					return
				}
				if running != expected || running != snapshot.Running() {
					t.Errorf("the ruleset %s says it runs %d rules and gave %d",
						snapshot.ID(), snapshot.Running(), running)
					return
				}
			}
		}()
	}
	for range 4 {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			for range 100 {
				if _, err := registry.Reload(); err != nil {
					t.Errorf("reload: %v", err)
					return
				}
			}
		}()
	}
	waiting.Wait()
}

type source struct {
	mutex    sync.Mutex
	programs []*detection.Program
	err      error
}

func (s *source) Programs() ([]*detection.Program, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.programs, s.err
}

func (s *source) hold(programs ...*detection.Program) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.programs, s.err = programs, nil
}

func (s *source) fail(err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.programs, s.err = nil, err
}

func held(programs ...*detection.Program) *source { return &source{programs: programs} }

func failing(err error) *source { return &source{err: err} }

func options(t *testing.T, from ruleset.Source) ruleset.Options {
	t.Helper()
	return ruleset.Options{Source: from, Metrics: ruleset.NewMetrics(metrics.New("analysis-engine")), Logger: quiet()}
}

func pinned(t *testing.T, from ruleset.Source) *ruleset.Registry {
	t.Helper()

	registry, err := ruleset.New(options(t, from))
	if err != nil {
		t.Fatalf("build a registry: %v", err)
	}
	return registry
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func scrape(t *testing.T, registry *metrics.Registry) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("scrape returned %d", recorder.Code)
	}
	return recorder.Body.String()
}

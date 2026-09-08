package ruleset_test

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

func TestACatalogueHoldsEveryVersionInThePublicationOrder(t *testing.T) {
	catalogue := ruleset.NewCatalogue()

	first := version(t, nil, compiled(t, rule("ssh.session_opened")))
	second := version(t, nil, compiled(t, rule("ssh.session_opened")), compiled(t, rule("ssh.invalid_user")))
	apply(t, catalogue, first.Record())
	apply(t, catalogue, second.Record())

	held := catalogue.Versions()
	if len(held) != 2 {
		t.Fatalf("the catalogue holds %d versions", len(held))
	}
	if held[0].ID() != first.ID() || held[1].ID() != second.ID() {
		t.Errorf("the catalogue holds %s then %s", held[0].ID(), held[1].ID())
	}
	if _, running := catalogue.Active(); running {
		t.Error("a catalogue that was never told what to run named something")
	}
}

// The same rules published twice are one version, so a republish neither
// doubles the list nor rewrites who published it first.
func TestPublishingTheSameRulesTwiceIsOneVersion(t *testing.T) {
	catalogue := ruleset.NewCatalogue()
	first := version(t, nil, compiled(t, rule("ssh.session_opened")))

	apply(t, catalogue, first.Record())
	again := first.Encode()
	again.PublishedBy = "somebody-else"
	apply(t, catalogue, &rulesetv1.Record{Record: &rulesetv1.Record_Version{Version: again}})

	if catalogue.Count() != 1 {
		t.Fatalf("the catalogue holds %d versions of one ruleset", catalogue.Count())
	}
	if held, _ := catalogue.Version(first.ID()); held.PublishedBy() != "dev-engineer" {
		t.Errorf("a republish rewrote the provenance to %q", held.PublishedBy())
	}
}

// Nothing is lost from a log that is replayed: a pointer read before the
// version it names is kept, and resolves the moment that version arrives.
func TestAnActivationAheadOfItsVersionResolvesWhenTheVersionArrives(t *testing.T) {
	catalogue := ruleset.NewCatalogue()
	held := version(t, nil, compiled(t, rule("ssh.session_opened")))

	apply(t, catalogue, activation(string(held.ID()), "dev-engineer"))
	if _, running := catalogue.Active(); running {
		t.Fatal("a catalogue named a ruleset it has never seen as the one to run")
	}
	if catalogue.Activation().GetRulesetId() != string(held.ID()) {
		t.Fatal("the pointer was dropped rather than kept")
	}

	apply(t, catalogue, held.Record())
	active, running := catalogue.Active()
	if !running || active.ID() != held.ID() {
		t.Fatalf("the pointer did not resolve: %v", running)
	}
}

// Rolling back is a pointer at something that cannot have changed, so the
// ruleset that comes back is the one that ran before and not a rebuild of it.
func TestRollingBackNamesTheRulesetThatRanBefore(t *testing.T) {
	catalogue := ruleset.NewCatalogue()
	first := version(t, nil, compiled(t, rule("ssh.session_opened")))
	second := version(t, nil, compiled(t, rule("ssh.invalid_user")))

	apply(t, catalogue, first.Record())
	apply(t, catalogue, second.Record())
	apply(t, catalogue, activation(string(second.ID()), "dev-engineer"))
	apply(t, catalogue, activation(string(first.ID()), "dev-admin"))

	active, running := catalogue.Active()
	if !running || active.ID() != first.ID() {
		t.Fatalf("the rollback landed on %v", active)
	}
	if catalogue.Activation().GetActivatedBy() != "dev-admin" {
		t.Errorf("the rollback was attributed to %q", catalogue.Activation().GetActivatedBy())
	}
	if catalogue.Count() != 2 {
		t.Errorf("rolling back changed what has been published: %d versions", catalogue.Count())
	}
}

func TestARecordACatalogueCannotReadLeavesItAsItWas(t *testing.T) {
	catalogue := ruleset.NewCatalogue()
	held := version(t, nil, compiled(t, rule("ssh.session_opened")))
	apply(t, catalogue, held.Record())

	if err := catalogue.Read([]byte{0xff, 0xfe, 0xfd}); err == nil {
		t.Error("bytes that are not a record were applied")
	}
	if err := catalogue.Apply(&rulesetv1.Record{}); err == nil {
		t.Error("a record carrying nothing was applied")
	}
	if err := catalogue.Apply(activation("", "dev-engineer")); err == nil {
		t.Error("an activation naming no ruleset was applied")
	}
	if catalogue.Count() != 1 {
		t.Errorf("the catalogue holds %d versions after three refusals", catalogue.Count())
	}
}

func TestACatalogueReadsWhatWasWrittenToTheLog(t *testing.T) {
	catalogue := ruleset.NewCatalogue()
	held := version(t, nil, compiled(t, rule("ssh.session_opened")))

	encoded, err := proto.Marshal(held.Record())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := catalogue.Read(encoded); err != nil {
		t.Fatalf("read a record off the log: %v", err)
	}
	if !catalogue.Published(held.ID()) {
		t.Error("the version did not arrive")
	}
}

func apply(t *testing.T, catalogue *ruleset.Catalogue, record *rulesetv1.Record) {
	t.Helper()

	if err := catalogue.Apply(record); err != nil {
		t.Fatalf("apply a record: %v", err)
	}
}

func activation(id, by string) *rulesetv1.Record {
	return &rulesetv1.Record{Record: &rulesetv1.Record_Active{
		Active: &rulesetv1.Active{RulesetId: id, ActivatedBy: by},
	}}
}

// A detection is named by the rule and the revision that decided it, so the pair
// has to keep meaning one thing: a second version reusing it for another
// question is refused whole, and the catalogue stays as it was.
func TestARevisionThatChangesWhatARuleAsksIsRefused(t *testing.T) {
	catalogue := ruleset.NewCatalogue()

	first := rule("ssh.session_opened")
	first.Revision = 4
	published := version(t, nil, compiled(t, first))
	apply(t, catalogue, published.Record())

	changed := first
	changed.Severity = detection.Critical
	rewritten := version(t, nil, compiled(t, changed))

	if err := catalogue.Admits(rewritten); err == nil {
		t.Error("a rewritten revision was admitted before it was written")
	}
	if err := catalogue.Apply(rewritten.Record()); err == nil {
		t.Error("a rewritten revision was applied")
	}
	if catalogue.Count() != 1 {
		t.Errorf("the catalogue holds %d versions after refusing one", catalogue.Count())
	}

	var conflict *ruleset.Conflict
	if err := catalogue.Admits(rewritten); !errors.As(err, &conflict) {
		t.Fatalf("the refusal does not name the rule: %v", err)
	}
	if conflict.Rule != first.ID || conflict.Revision != first.Revision {
		t.Errorf("the refusal names %s revision %d", conflict.Rule, conflict.Revision)
	}
}

// The next revision is how a rule changes, so raising it is admitted and the
// version that carried the previous one is still published.
func TestTheNextRevisionCarriesAChangedRule(t *testing.T) {
	catalogue := ruleset.NewCatalogue()

	first := rule("ssh.session_opened")
	first.Revision = 4
	apply(t, catalogue, version(t, nil, compiled(t, first)).Record())

	changed := first
	changed.Revision = 5
	changed.Severity = detection.Critical
	revised := version(t, nil, compiled(t, changed))

	if err := catalogue.Admits(revised); err != nil {
		t.Fatalf("a raised revision was refused: %v", err)
	}
	apply(t, catalogue, revised.Record())
	if catalogue.Count() != 2 {
		t.Errorf("the catalogue holds %d versions", catalogue.Count())
	}
}

// A ruleset carries the rule beside others that changed, so refusing the version
// whole is what stops half of it becoming what an engine runs.
func TestARewrittenRuleRefusesTheWholeVersion(t *testing.T) {
	catalogue := ruleset.NewCatalogue()

	held := rule("ssh.session_opened")
	held.Revision = 2
	apply(t, catalogue, version(t, nil, compiled(t, held)).Record())

	rewritten := held
	rewritten.Description = "Something else entirely."
	beside := version(t, nil, compiled(t, rewritten), compiled(t, rule("ssh.invalid_user")))

	if err := catalogue.Apply(beside.Record()); err == nil {
		t.Fatal("a version carrying a rewritten revision was applied")
	}
	if catalogue.Count() != 1 {
		t.Errorf("the catalogue holds %d versions", catalogue.Count())
	}
}

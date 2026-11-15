package ruleset_test

import (
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// An upgrade brings the rules of a release and must not undo what a person
// chose, so the pointer is the installation's to move only while nobody else
// has written it.
func TestThePointerYieldsToTheStartingRulesUntilAPersonActivatesSomething(t *testing.T) {
	starting := version(t, nil, compiled(t, rule("ssh.session_opened")))
	before := version(t, nil, compiled(t, rule("ssh.invalid_user")))

	for name, held := range map[string]struct {
		pointer *rulesetv1.Record
		yields  bool
	}{
		"nothing was ever activated":                            {nil, true},
		"the installation activated the rules of a release ago": {activation(string(before.ID()), ruleset.Installation), true},
		"the installation already activated these rules":        {activation(string(starting.ID()), ruleset.Installation), false},
		"a person activated another ruleset":                    {activation(string(before.ID()), "dev-engineer"), false},
		"a person activated these very rules":                   {activation(string(starting.ID()), "dev-engineer"), false},
	} {
		t.Run(name, func(t *testing.T) {
			catalogue := ruleset.NewCatalogue()
			apply(t, catalogue, before.Record())
			apply(t, catalogue, starting.Record())
			if held.pointer != nil {
				apply(t, catalogue, held.pointer)
			}

			if yields := catalogue.Yields(starting.ID()); yields != held.yields {
				t.Errorf("the pointer yields to the starting rules: %v, and it should be %v", yields, held.yields)
			}
		})
	}
}

// What a person activated last is what counts: an installation that pointed at
// its rules first has nothing left to say once somebody rolled out their own.
func TestAPointerAPersonMovedAfterTheInstallationIsNoLongerTheInstallations(t *testing.T) {
	starting := version(t, nil, compiled(t, rule("ssh.session_opened")))
	before := version(t, nil, compiled(t, rule("ssh.invalid_user")))
	chosen := version(t, nil, compiled(t, rule("ssh.failed_password")))

	catalogue := ruleset.NewCatalogue()
	for _, published := range []*ruleset.Version{before, chosen, starting} {
		apply(t, catalogue, published.Record())
	}
	apply(t, catalogue, activation(string(before.ID()), ruleset.Installation))
	apply(t, catalogue, activation(string(chosen.ID()), "dev-engineer"))

	if catalogue.Yields(starting.ID()) {
		t.Error("a ruleset a person activated would be replaced by the rules of an upgrade")
	}
}

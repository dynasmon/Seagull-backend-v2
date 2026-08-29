package ruleset

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// A ruleset that has been published: the compiled rules, the cases they were
// written for, and who published it when. Named by its rules and by nothing
// about the act of publishing, so the same rules published twice are one
// version rather than two, and a rollback names something that cannot have
// changed underneath it.
type Version struct {
	snapshot *Snapshot
	cases    map[detection.ID][]detection.Case
	by       string
	at       time.Time
	note     string
}

func NewVersion(programs []*detection.Program, cases map[detection.ID][]detection.Case, by string, at time.Time, note string) (*Version, error) {
	if by == "" {
		return nil, errors.New("a published ruleset names who published it")
	}
	if at.IsZero() {
		return nil, errors.New("a published ruleset says when it was published")
	}

	snapshot, err := Compose(programs)
	if err != nil {
		return nil, err
	}
	return &Version{snapshot: snapshot, cases: cases, by: by, at: at.UTC(), note: note}, nil
}

func (v *Version) ID() ID { return v.snapshot.ID() }

func (v *Version) Snapshot() *Snapshot { return v.snapshot }

func (v *Version) Cases(rule detection.ID) []detection.Case { return v.cases[rule] }

func (v *Version) PublishedBy() string { return v.by }

func (v *Version) PublishedAt() time.Time { return v.at }

func (v *Version) Note() string { return v.note }

func (v *Version) Encode() *rulesetv1.Version {
	encoded := &rulesetv1.Version{
		Id:          string(v.ID()),
		PublishedBy: v.by,
		PublishedAt: timestamppb.New(v.at),
		Note:        v.note,
	}
	for program := range v.snapshot.All() {
		rule := program.Rule()
		encoded.Rules = append(encoded.Rules, encodeRule(rule, v.cases[rule.ID]))
	}
	return encoded
}

func (v *Version) Record() *rulesetv1.Record {
	return &rulesetv1.Record{Record: &rulesetv1.Record_Version{Version: v.Encode()}}
}

// Every rule is compiled again here rather than trusted, and the ruleset is
// then held to naming itself: a record whose rules do not hash to the id it
// carries is refused, so nothing that was rewritten in transit or written by a
// build that means something else by a rule can become what an engine runs.
func DecodeVersion(encoded *rulesetv1.Version) (*Version, error) {
	if encoded == nil {
		return nil, errors.New("a published ruleset record carries nothing")
	}
	if encoded.GetId() == "" {
		return nil, errors.New("a published ruleset carries the id it was named by")
	}

	programs := make([]*detection.Program, 0, len(encoded.GetRules()))
	cases := make(map[detection.ID][]detection.Case, len(encoded.GetRules()))
	for _, held := range encoded.GetRules() {
		rule, written, err := decodeRule(held)
		if err != nil {
			return nil, err
		}
		program, err := detection.Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		programs = append(programs, program)
		if len(written) > 0 {
			cases[rule.ID] = written
		}
	}

	version, err := NewVersion(programs, cases, encoded.GetPublishedBy(), encoded.GetPublishedAt().AsTime(), encoded.GetNote())
	if err != nil {
		return nil, err
	}
	if version.ID() != ID(encoded.GetId()) {
		return nil, fmt.Errorf("a ruleset is named by what is in it: this record says %s and holds %s", encoded.GetId(), version.ID())
	}
	return version, nil
}

func (v *Version) Summary(active bool) *rulesetv1.Summary {
	return &rulesetv1.Summary{
		Id:          string(v.ID()),
		Rules:       uint32(v.snapshot.Rules()),
		Running:     uint32(v.snapshot.Running()),
		PublishedBy: v.by,
		PublishedAt: timestamppb.New(v.at),
		Note:        v.note,
		Active:      active,
	}
}

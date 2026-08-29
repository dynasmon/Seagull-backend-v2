package main

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
	"github.com/dynasmon/Seagull-backend-v2/internal/rulefile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
	rulesetv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ruleset/v1"
)

// The bridge between an administrative request and the log a ruleset lives in.
// The listener knows no rule language and the log knows no HTTP; composing them
// is an executable's job, as it is for the ruleset the engine runs.
type rulesets struct {
	catalogue *ruleset.Catalogue
	publisher publisher
}

type publisher interface {
	Publish(ctx context.Context, record *rulesetv1.Record) error
}

func (r rulesets) Validate(documents []*rulesetv1.Document) *rulesetv1.ValidationResponse {
	validation, _ := r.compile(documents)
	return validation
}

func (r rulesets) Check(documents []*rulesetv1.Document) (*rulesetv1.ValidationResponse, *rulesetv1.CheckResponse) {
	validation, written := r.compile(documents)
	if !validation.GetValid() {
		return validation, nil
	}
	return validation, checked(rulefile.Checked(written))
}

// Nothing is published that does not compile, and nothing is published whose
// own cases do not hold: an estate may ship a rule nobody wrote a case for, and
// may not ship one whose case says it is wrong.
func (r rulesets) Publish(ctx context.Context, request *rulesetv1.PublishRequest, by string, at time.Time) (*rulesetv1.PublishResponse, error) {
	validation, written := r.compile(request.GetDocuments())
	answer := &rulesetv1.PublishResponse{RulesetId: validation.GetRulesetId(), Validation: validation}
	if !validation.GetValid() {
		return answer, nil
	}

	answer.Check = checked(rulefile.Checked(written))
	if !answer.Check.GetHeld() {
		return answer, nil
	}

	programs, cases := composed(written)
	version, err := ruleset.NewVersion(programs, cases, by, at, request.GetNote())
	if err != nil {
		return nil, err
	}

	record := version.Record()
	if err := r.publisher.Publish(ctx, record); err != nil {
		return nil, err
	}
	if err := r.catalogue.Apply(record); err != nil {
		return nil, err
	}
	answer.Published = true
	return answer, nil
}

func (r rulesets) List() *rulesetv1.VersionList {
	activation := r.catalogue.Activation()
	active := ruleset.ID(activation.GetRulesetId())

	held := r.catalogue.Versions()
	listed := make([]*rulesetv1.Summary, 0, len(held))
	for _, version := range held {
		listed = append(listed, version.Summary(version.ID() == active))
	}
	return &rulesetv1.VersionList{Versions: listed, Active: activation}
}

func (r rulesets) Version(id string) (*rulesetv1.Version, bool) {
	version, published := r.catalogue.Version(ruleset.ID(id))
	if !published {
		return nil, false
	}
	return version.Encode(), true
}

func (r rulesets) Activate(ctx context.Context, id, note, by string, at time.Time) (*rulesetv1.ActivationResponse, error) {
	if !r.catalogue.Published(ruleset.ID(id)) {
		return nil, control.ErrUnknownRuleset
	}

	replaced := r.catalogue.Activation().GetRulesetId()
	active := &rulesetv1.Active{
		RulesetId:   id,
		ActivatedBy: by,
		ActivatedAt: timestamppb.New(at.UTC()),
		Note:        note,
	}
	record := &rulesetv1.Record{Record: &rulesetv1.Record_Active{Active: active}}

	if err := r.publisher.Publish(ctx, record); err != nil {
		return nil, err
	}
	if err := r.catalogue.Apply(record); err != nil {
		return nil, err
	}
	return &rulesetv1.ActivationResponse{Active: active, Replaced: replaced}, nil
}

func (r rulesets) compile(documents []*rulesetv1.Document) (*rulesetv1.ValidationResponse, []rulefile.Written) {
	var (
		written []rulefile.Written
		faults  []*rulesetv1.Fault
	)
	for _, document := range documents {
		read, err := rulefile.Parse(document.GetName(), document.GetContent())
		if err != nil {
			faults = append(faults, faultsOf(err)...)
			continue
		}
		written = append(written, read...)
	}
	if len(faults) > 0 {
		return &rulesetv1.ValidationResponse{Faults: faults}, nil
	}

	programs, _ := composed(written)
	snapshot, err := ruleset.Compose(programs)
	if err != nil {
		return &rulesetv1.ValidationResponse{Faults: faultsOf(err)}, nil
	}
	return &rulesetv1.ValidationResponse{
		Valid:     true,
		RulesetId: string(snapshot.ID()),
		Rules:     uint32(snapshot.Rules()),
		Running:   uint32(snapshot.Running()),
	}, written
}

func composed(written []rulefile.Written) ([]*detection.Program, map[detection.ID][]detection.Case) {
	programs := make([]*detection.Program, 0, len(written))
	cases := make(map[detection.ID][]detection.Case, len(written))
	for _, rule := range written {
		programs = append(programs, rule.Program)
		if len(rule.Cases) > 0 {
			cases[rule.Program.Rule().ID] = rule.Cases
		}
	}
	return programs, cases
}

func checked(report rulefile.Report) *rulesetv1.CheckResponse {
	answer := &rulesetv1.CheckResponse{
		Held:  report.Held(),
		Rules: uint32(report.Rules),
		Cases: uint32(report.Cases),
	}
	for _, unheld := range report.Unheld {
		answer.Unheld = append(answer.Unheld, &rulesetv1.Unheld{
			Source:   unheld.Source,
			Rule:     string(unheld.Rule),
			CaseName: unheld.Case,
			Reason:   unheld.Reason,
		})
	}
	for _, untested := range report.Untested {
		answer.Untested = append(answer.Untested, string(untested))
	}
	return answer
}

// A refusal keeps the file, the position, the rule and the part it was written
// in, so what an editor would underline is what the caller is answered with.
func faultsOf(err error) []*rulesetv1.Fault {
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		var all []*rulesetv1.Fault
		for _, one := range joined.Unwrap() {
			all = append(all, faultsOf(one)...)
		}
		return all
	}

	var fault *rulefile.Fault
	if errors.As(err, &fault) {
		return []*rulesetv1.Fault{{
			Source: fault.Source,
			Line:   uint32(fault.Line),
			Column: uint32(fault.Column),
			Rule:   string(fault.Rule),
			Part:   fault.Part,
			Reason: fault.Reason,
		}}
	}
	return []*rulesetv1.Fault{{Reason: err.Error()}}
}

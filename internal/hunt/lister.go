package hunt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the query plane needs of the stores it lists from: one page of what a
// question already holds to its scope, its page and its budget, and the
// position its last record sits at in the order the store sorts by. A store
// names the position because only it knows that order; the plane signs it.
type Inventory interface {
	Assets(ctx context.Context, asked AssetQuestion) (*inventoryv1.AssetPage, []string, error)
	Items(ctx context.Context, asked ItemQuestion) (*inventoryv1.ItemPage, []string, error)
}

type Vulnerabilities interface {
	Findings(ctx context.Context, asked FindingQuestion) (*vulnerabilityv1.FindingPage, []string, error)
	History(ctx context.Context, asked HistoryQuestion) (*vulnerabilityv1.FindingPage, []string, error)
	Assessments(ctx context.Context, asked AssessmentQuestion) (*vulnerabilityv1.AssessmentPage, []string, error)
	Advisories(ctx context.Context, asked AdvisoryQuestion) (*vulnerabilityv1.AdvisoryPage, []string, error)
}

type ListerOptions struct {
	Inventory       Inventory
	Vulnerabilities Vulnerabilities
	Compiler        *Compiler
	Metrics         *Metrics
	Logger          *slog.Logger
}

type Lister struct {
	inventory       Inventory
	vulnerabilities Vulnerabilities
	compiler        *Compiler
	metrics         *Metrics
	logger          *slog.Logger
}

func NewLister(options ListerOptions) (*Lister, error) {
	switch {
	case options.Inventory == nil:
		return nil, errors.New("a lister needs the store of what assets have")
	case options.Vulnerabilities == nil:
		return nil, errors.New("a lister needs the store of what is wrong with them")
	case options.Compiler == nil:
		return nil, errors.New("a lister needs a compiler to hold a question to its limits")
	case options.Metrics == nil:
		return nil, errors.New("a lister needs metrics")
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Lister{
		inventory:       options.Inventory,
		vulnerabilities: options.Vulnerabilities,
		compiler:        options.Compiler,
		metrics:         options.Metrics,
		logger:          logger,
	}, nil
}

func (l *Lister) Assets(ctx context.Context, scope Scope, asked *inventoryv1.AssetQuery) (*inventoryv1.AssetPage, error) {
	question, err := l.compiler.Assets(scope, asked)
	if err != nil {
		return nil, l.refused(Assets, err)
	}
	return list(ctx, l, question.listing,
		func(ctx context.Context) (*inventoryv1.AssetPage, []string, error) {
			return l.inventory.Assets(ctx, question)
		},
		func(page *inventoryv1.AssetPage) int { return len(page.GetAssets()) },
		func(page *inventoryv1.AssetPage, cursor string) { page.NextCursor = cursor })
}

func (l *Lister) Items(ctx context.Context, scope Scope, asked *inventoryv1.ItemQuery) (*inventoryv1.ItemPage, error) {
	question, err := l.compiler.Items(scope, asked)
	if err != nil {
		return nil, l.refused(Items, err)
	}
	return list(ctx, l, question.listing,
		func(ctx context.Context) (*inventoryv1.ItemPage, []string, error) {
			return l.inventory.Items(ctx, question)
		},
		func(page *inventoryv1.ItemPage) int { return len(page.GetItems()) },
		func(page *inventoryv1.ItemPage, cursor string) { page.NextCursor = cursor })
}

func (l *Lister) Findings(ctx context.Context, scope Scope, asked *vulnerabilityv1.FindingQuery) (*vulnerabilityv1.FindingPage, error) {
	question, err := l.compiler.Findings(scope, asked)
	if err != nil {
		return nil, l.refused(Findings, err)
	}
	return list(ctx, l, question.listing,
		func(ctx context.Context) (*vulnerabilityv1.FindingPage, []string, error) {
			return l.vulnerabilities.Findings(ctx, question)
		},
		func(page *vulnerabilityv1.FindingPage) int { return len(page.GetFindings()) },
		func(page *vulnerabilityv1.FindingPage, cursor string) { page.NextCursor = cursor })
}

func (l *Lister) History(ctx context.Context, scope Scope, asked *vulnerabilityv1.FindingHistoryQuery) (*vulnerabilityv1.FindingPage, error) {
	question, err := l.compiler.History(scope, asked)
	if err != nil {
		return nil, l.refused(FindingHistory, err)
	}
	return list(ctx, l, question.listing,
		func(ctx context.Context) (*vulnerabilityv1.FindingPage, []string, error) {
			return l.vulnerabilities.History(ctx, question)
		},
		func(page *vulnerabilityv1.FindingPage) int { return len(page.GetFindings()) },
		func(page *vulnerabilityv1.FindingPage, cursor string) { page.NextCursor = cursor })
}

func (l *Lister) Assessments(ctx context.Context, scope Scope, asked *vulnerabilityv1.AssessmentQuery) (*vulnerabilityv1.AssessmentPage, error) {
	question, err := l.compiler.Assessments(scope, asked)
	if err != nil {
		return nil, l.refused(Assessments, err)
	}
	return list(ctx, l, question.listing,
		func(ctx context.Context) (*vulnerabilityv1.AssessmentPage, []string, error) {
			return l.vulnerabilities.Assessments(ctx, question)
		},
		func(page *vulnerabilityv1.AssessmentPage) int { return len(page.GetAssessments()) },
		func(page *vulnerabilityv1.AssessmentPage, cursor string) { page.NextCursor = cursor })
}

func (l *Lister) Advisories(ctx context.Context, scope Scope, asked *vulnerabilityv1.AdvisoryQuery) (*vulnerabilityv1.AdvisoryPage, error) {
	question, err := l.compiler.Advisories(scope, asked)
	if err != nil {
		return nil, l.refused(Advisories, err)
	}
	return list(ctx, l, question.listing,
		func(ctx context.Context) (*vulnerabilityv1.AdvisoryPage, []string, error) {
			return l.vulnerabilities.Advisories(ctx, question)
		},
		func(page *vulnerabilityv1.AdvisoryPage) int { return len(page.GetAdvisories()) },
		func(page *vulnerabilityv1.AdvisoryPage, cursor string) { page.NextCursor = cursor })
}

// The read budget is a deadline here as it is for a hunt, and a page that
// carried anything is followed by a cursor: a store answers within a budget, so
// only the empty page says the listing is exhausted.
func list[P any](ctx context.Context, l *Lister, question listing, read func(context.Context) (P, []string, error),
	carried func(P) int, resume func(P, string)) (P, error) {
	var none P
	bounded, cancel := context.WithTimeout(ctx, question.Timeout())
	defer cancel()

	started := time.Now()
	page, last, err := read(bounded)
	elapsed := time.Since(started)
	if err != nil {
		l.metrics.failed(question.dataset, elapsed)
		return none, fmt.Errorf("answer a %s listing: %w", question.dataset, err)
	}

	records := carried(page)
	if records > 0 {
		cursor, err := l.compiler.resume(question, last)
		if err != nil {
			l.metrics.failed(question.dataset, elapsed)
			return none, fmt.Errorf("the store answered a %s page it cannot say where it ended: %w", question.dataset, err)
		}
		resume(page, cursor)
	}

	l.metrics.answered(question.dataset, records, elapsed)
	l.logger.Info("listing_answered",
		slog.String("dataset", string(question.dataset)),
		slog.Int("records", records),
		slog.Duration("elapsed", elapsed),
	)
	return page, nil
}

func (l *Lister) refused(dataset Dataset, err error) error { return counted(l.metrics, dataset, err) }

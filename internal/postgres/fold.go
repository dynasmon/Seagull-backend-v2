package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
)

const insertOccurrence = `INSERT INTO alert_occurrences (alert_id, detection_id, event_time, folded_at)
VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`

const openWithKey = `SELECT alert_id, last_seen FROM alerts
WHERE tenant_id = $1 AND correlation_key = $2 AND state NOT IN ('resolved','false_positive')
ORDER BY last_seen DESC LIMIT 1
FOR UPDATE`

const closedWithKey = `SELECT closure_at FROM alerts
WHERE tenant_id = $1 AND correlation_key = $2 AND state IN ('resolved','false_positive') AND closure_at IS NOT NULL
ORDER BY closure_at DESC LIMIT 1`

const foldInto = `UPDATE alerts
SET occurrences = occurrences + 1, last_seen = GREATEST(last_seen, $2)
WHERE alert_id = $1`

// One transaction for the batch, so a batch is durable or it is not. Every step
// is idempotent on the detection id, which is what lets the writer retry the
// whole thing until the store takes it.
func (s *Store) Record(ctx context.Context, candidates []alert.Candidate) ([]alert.Outcome, error) {
	outcomes := make([]alert.Outcome, len(candidates))
	if len(candidates) == 0 {
		return outcomes, nil
	}

	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin recording %d detections: %w", len(candidates), err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	for index, candidate := range candidates {
		outcome, err := record(ctx, transaction, candidate)
		if err != nil {
			return nil, err
		}
		outcomes[index] = outcome
	}

	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit %d recorded detections: %w", len(candidates), err)
	}
	return outcomes, nil
}

func record(ctx context.Context, transaction pgx.Tx, candidate alert.Candidate) (alert.Outcome, error) {
	folded, err := alreadyFolded(ctx, transaction, candidate.DetectionID)
	if err != nil {
		return "", err
	}
	if folded {
		return alert.OutcomeRepeated, nil
	}

	open, lastSeen, err := openAlert(ctx, transaction, candidate)
	if err != nil {
		return "", err
	}
	if open != "" && !candidate.At.After(lastSeen.Add(candidate.Window)) {
		if _, err := transaction.Exec(ctx, foldInto, open, candidate.At); err != nil {
			return "", fmt.Errorf("fold detection %s into alert %s: %w", candidate.DetectionID, open, err)
		}
		if err := fold(ctx, transaction, open, candidate); err != nil {
			return "", err
		}
		return alert.OutcomeFolded, nil
	}

	if open == "" && candidate.Cooldown > 0 {
		cooling, err := coolingDown(ctx, transaction, candidate)
		if err != nil {
			return "", err
		}
		if cooling {
			return alert.OutcomeCooledDown, nil
		}
	}

	if err := raise(ctx, transaction, candidate); err != nil {
		return "", err
	}
	return alert.OutcomeRaised, nil
}

func alreadyFolded(ctx context.Context, transaction pgx.Tx, detection string) (bool, error) {
	var into string
	err := transaction.QueryRow(ctx, "SELECT alert_id FROM alert_occurrences WHERE detection_id = $1", detection).Scan(&into)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read whether detection %s was already folded: %w", detection, err)
	}
	return true, nil
}

func openAlert(ctx context.Context, transaction pgx.Tx, candidate alert.Candidate) (string, time.Time, error) {
	var (
		id       string
		lastSeen time.Time
	)
	err := transaction.QueryRow(ctx, openWithKey, candidate.Alert.GetTenantId(), candidate.Key).Scan(&id, &lastSeen)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", time.Time{}, nil
	case err != nil:
		return "", time.Time{}, fmt.Errorf("read the open alert keyed %s: %w", candidate.Key, err)
	}
	return id, lastSeen.UTC(), nil
}

// Measured from the detection's event time against when the alert was closed,
// never against the clock, so replaying a batch decides what it decided the
// first time however long afterwards it runs.
func coolingDown(ctx context.Context, transaction pgx.Tx, candidate alert.Candidate) (bool, error) {
	var closedAt time.Time
	err := transaction.QueryRow(ctx, closedWithKey, candidate.Alert.GetTenantId(), candidate.Key).Scan(&closedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read the last alert closed under %s: %w", candidate.Key, err)
	}
	return candidate.At.Before(closedAt.UTC().Add(candidate.Cooldown)), nil
}

func raise(ctx context.Context, transaction pgx.Tx, candidate alert.Candidate) error {
	// The key the alert is stored under is the one it was looked up by, so the
	// two can never disagree and leave an alert nothing will ever fold into.
	candidate.Alert.CorrelationKey = candidate.Key

	if _, err := transaction.Exec(ctx, insertAlert, stored(candidate.Alert)...); err != nil {
		return fmt.Errorf("raise alert %s: %w", candidate.Alert.GetAlertId(), err)
	}
	if _, err := transaction.Exec(ctx, insertTransition, trail(alert.Raised(candidate.Alert))...); err != nil {
		return fmt.Errorf("record how alert %s was raised: %w", candidate.Alert.GetAlertId(), err)
	}
	return fold(ctx, transaction, candidate.Alert.GetAlertId(), candidate)
}

func fold(ctx context.Context, transaction pgx.Tx, into string, candidate alert.Candidate) error {
	_, err := transaction.Exec(ctx, insertOccurrence, into, candidate.DetectionID, candidate.At, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("record detection %s against alert %s: %w", candidate.DetectionID, into, err)
	}
	return nil
}

func (s *Store) Occurrences(ctx context.Context, id string, tenants []string) (*alertv1.Occurrences, error) {
	if _, err := s.Alert(ctx, id, tenants); err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT detection_id, event_time, folded_at FROM alert_occurrences
		 WHERE alert_id = $1 ORDER BY event_time, detection_id`, id)
	if err != nil {
		return nil, fmt.Errorf("read what alert %s is made of: %w", id, err)
	}
	made, err := pgx.CollectRows(rows, restoreOccurrence)
	if err != nil {
		return nil, fmt.Errorf("read what alert %s is made of: %w", id, err)
	}
	return &alertv1.Occurrences{AlertId: id, Occurrences: made}, nil
}

func restoreOccurrence(row pgx.CollectableRow) (*alertv1.Occurrence, error) {
	var (
		one                 alertv1.Occurrence
		eventTime, foldedAt time.Time
	)
	if err := row.Scan(&one.DetectionId, &eventTime, &foldedAt); err != nil {
		return nil, err
	}
	one.EventTime = instant(&eventTime)
	one.FoldedAt = instant(&foldedAt)
	return &one, nil
}

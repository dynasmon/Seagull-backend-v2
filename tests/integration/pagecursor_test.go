//go:build integration

package integration_test

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/incident"
	alertv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/alert/v1"
	detectionv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/detection/v1"
	incidentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/incident/v1"
)

// alert-writer stamps every alert and incident of a batch with one instant read
// from its clock, which PostgreSQL keeps to the microsecond, so a page boundary
// falls inside one millisecond whenever a batch is longer than a page.
func batchInstant() time.Time {
	return time.Now().UTC().Truncate(time.Millisecond).Add(456789 * time.Nanosecond)
}

func TestEveryAlertRaisedInOneBatchIsListedPageByPageOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()
	tenant, at := isolated(t), batchInstant()

	var batch []alert.Candidate
	var raised []string
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		one := raisedFrom(t, tenant, tenant+"-batch-"+name, detectionv1.Severity_SEVERITY_HIGH, at)
		batch = append(batch, mustConsider(t, one))
		raised = append(raised, one.GetAlertId())
	}
	recorded(t, store, batch...)
	slices.Reverse(raised)

	for _, limit := range []uint32{1, 2, 4} {
		var listed []string
		for cursor, pages := "", 0; pages < 10; pages++ {
			page, err := store.Page(ctx, &alertv1.Query{Limit: limit, Cursor: cursor}, []string{tenant})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			for _, one := range page.GetAlerts() {
				listed = append(listed, one.GetAlertId())
			}
			if cursor = page.GetNextCursor(); cursor == "" {
				break
			}
		}
		if !slices.Equal(listed, raised) {
			t.Errorf("by pages of %d the five alerts of one batch were listed as %v, want %v", limit, listed, raised)
		}
	}
}

func TestEveryIncidentOpenedInOneBatchIsListedPageByPageOnPostgresql(t *testing.T) {
	stories := migratedAlertStore(t, alertStoreAddress(t)).Incidents()
	ctx := context.Background()
	tenant, at := isolated(t), batchInstant()

	var told []*incidentv1.Incident
	var raised []string
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		one := openedFrom(t, tenant, tenant+"-batch-"+name, at.Add(-time.Minute), 0)
		told = append(told, one)
		raised = append(raised, one.GetIncidentId())
	}
	opened(t, stories, told...)
	slices.Reverse(raised)

	for _, limit := range []uint32{1, 2, 4} {
		var listed []string
		for cursor, pages := "", 0; pages < 10; pages++ {
			page, err := stories.Page(ctx, &incidentv1.Query{Limit: limit, Cursor: cursor}, []string{tenant})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			for _, one := range page.GetIncidents() {
				listed = append(listed, one.GetIncidentId())
			}
			if cursor = page.GetNextCursor(); cursor == "" {
				break
			}
		}
		if !slices.Equal(listed, raised) {
			t.Errorf("by pages of %d the five incidents of one batch were listed as %v, want %v", limit, listed, raised)
		}
	}
}

// A cursor written to the millisecond, as one issued before this build was, is
// refused rather than read as a position nothing is behind.
func TestACursorWrittenToTheMillisecondIsRefusedOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx := context.Background()
	tenant := isolated(t)
	before := base64.RawURLEncoding.EncodeToString([]byte("1794916800123.0f8e4a521c3b4d6e9f70a1b2c3d4e5f6"))

	if _, err := store.Page(ctx, &alertv1.Query{Cursor: before}, []string{tenant}); !errors.Is(err, alert.ErrCursor) {
		t.Errorf("an alert cursor written to the millisecond was answered %v", err)
	}
	if _, err := store.Incidents().Page(ctx, &incidentv1.Query{Cursor: before}, []string{tenant}); !errors.Is(err, incident.ErrCursor) {
		t.Errorf("an incident cursor written to the millisecond was answered %v", err)
	}
}

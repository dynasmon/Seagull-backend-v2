//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/eventstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

func migratedHunter(t *testing.T, address string) *clickhouse.Hunter {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	reader, err := clickhouse.NewHunter(storeSettings(address))
	if err != nil {
		t.Fatalf("build the hunter: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	if err := reader.VerifySchema(ctx); err != nil {
		t.Fatalf("a migrated store did not pass verification: %v", err)
	}
	return reader
}

func huntCompiler(t *testing.T) *hunt.Compiler {
	t.Helper()

	built, err := hunt.NewCompiler(hunt.CompilerOptions{
		Limits: hunt.Limits{
			Window: 720 * time.Hour, Page: 50, MaxPage: 500,
			Timeout: 30 * time.Second, MaxRowsRead: 10_000_000,
		},
		CursorKey: []byte(strings.Repeat("k", 32)),
	})
	if err != nil {
		t.Fatalf("build the compiler: %v", err)
	}
	return built
}

func hunted(t *testing.T, compiler *hunt.Compiler, dataset hunt.Dataset, tenant string, asked *huntv1.Query) hunt.Query {
	t.Helper()

	scope, err := hunt.NewScope([]string{tenant})
	if err != nil {
		t.Fatalf("build the scope: %v", err)
	}
	query, err := compiler.Compile(dataset, scope, asked)
	if err != nil {
		t.Fatalf("compile the query: %v", err)
	}
	return query
}

func within(from, to time.Time) *huntv1.TimeRange {
	return &huntv1.TimeRange{Start: timestamppb.New(from), End: timestamppb.New(to)}
}

func term(field string, operator huntv1.Operator, values ...string) *huntv1.Expression {
	return &huntv1.Expression{Form: &huntv1.Expression_Predicate{
		Predicate: &huntv1.Predicate{Field: field, Operator: operator, Values: values},
	}}
}

func admitted(owner, id, user string, at time.Time) *eventv1.Event {
	return &eventv1.Event{
		EventId:       id,
		SchemaVersion: 1,
		EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:          &eventv1.Timestamps{EventTime: timestamppb.New(at), ObservedTime: timestamppb.New(at)},
		Origin: &eventv1.Origin{
			TenantId: owner,
			AgentId:  "web-01",
			Host:     &eventv1.Host{Hostname: "web-01.acme.example", Ip: "198.51.100.7", Os: "linux", Architecture: "amd64"},
		},
		Collection: &eventv1.Collection{Collector: "ssh.authlog", Source: "/var/log/auth.log", Sequence: 42},
		Reception:  &eventv1.Reception{IngestTime: timestamppb.New(at), Gateway: "ingest-gateway", BatchId: "batch-1"},
		Body: &eventv1.Event_Authentication{Authentication: &eventv1.Authentication{
			Activity:      eventv1.Authentication_ACTIVITY_LOGON,
			Outcome:       eventv1.Outcome_OUTCOME_FAILURE,
			OutcomeReason: "failed_password",
			Method:        "password",
			User:          &eventv1.User{Name: user, Domain: "acme", Uid: "0"},
			Service:       &eventv1.Service{Name: "sshd", Protocol: "ssh"},
			Network: &eventv1.Network{
				Source:      &eventv1.Endpoint{Ip: "203.0.113.10", Port: 54321},
				Destination: &eventv1.Endpoint{Ip: "198.51.100.5", Port: 22},
				Transport:   eventv1.Transport_TRANSPORT_TCP,
			},
			RawRecord: "Failed password for " + user + " from 203.0.113.10 port 54321 ssh2",
		}},
	}
}

func keep(t *testing.T, store *clickhouse.Store, events ...*eventv1.Event) {
	t.Helper()

	rows := make([]eventstore.Row, 0, len(events))
	for _, record := range events {
		rows = append(rows, eventstore.Project(record))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Store(ctx, rows); err != nil {
		t.Fatalf("keep %d events: %v", len(rows), err)
	}
}

// The store is a materialisation of what crossed the backbone, and a hunt is
// where that stops being a claim: what an analyst reads back is the record the
// gateway admitted, field for field.
func TestAHuntReadsBackTheRecordThatWasAdmitted(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	owner := fmt.Sprintf("roundtrip%d", time.Now().UnixNano())
	original := admitted(owner, "11111111-2222-4333-8444-555555555555", "root", at)
	keep(t, store, original)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	found, err := reader.Events(ctx, hunted(t, compiler, hunt.Events, owner,
		&huntv1.Query{Range: within(at.Add(-time.Hour), at.Add(time.Hour))}))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("the hunt found %d events", len(found))
	}
	if !proto.Equal(original, found[0]) {
		t.Errorf("the store answered with a different record:\n admitted %v\n     read %v", original, found[0])
	}
}

// The scope is not a filter the caller supplies. A query carrying no predicate
// at all still reads only the tenants the caller was authorised for.
func TestAHuntNeverReadsOutsideItsScope(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	mine := fmt.Sprintf("mine%d", time.Now().UnixNano())
	theirs := fmt.Sprintf("theirs%d", time.Now().UnixNano())
	keep(t, store,
		admitted(mine, "22222222-2222-4333-8444-555555555555", "root", at),
		admitted(theirs, "33333333-2222-4333-8444-555555555555", "root", at),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	found, err := reader.Events(ctx, hunted(t, compiler, hunt.Events, mine,
		&huntv1.Query{Range: within(at.Add(-time.Hour), at.Add(time.Hour))}))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	for _, record := range found {
		if owner := record.GetOrigin().GetTenantId(); owner != mine {
			t.Errorf("a caller scoped to %s was answered with a record belonging to %s", mine, owner)
		}
	}
	if len(found) != 1 {
		t.Errorf("the hunt found %d events for one tenant", len(found))
	}
}

// A page resumes at the last record rather than at a count, so every record is
// read exactly once even though the pages are read one after another.
func TestPagingReadsEveryRecordExactlyOnce(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	owner := fmt.Sprintf("paged%d", time.Now().UnixNano())

	const written = 25
	events := make([]*eventv1.Event, 0, written)
	for index := range written {
		events = append(events, admitted(owner,
			fmt.Sprintf("44444444-2222-4333-8444-%012d", index), "root", base.Add(time.Duration(index)*time.Second)))
	}
	keep(t, store, events...)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	seen := map[string]int{}
	asked := &huntv1.Query{Range: within(base.Add(-time.Hour), base.Add(time.Hour)), Limit: 4}
	for pages := 0; pages < 20; pages++ {
		query := hunted(t, compiler, hunt.Events, owner, asked)
		found, err := reader.Events(ctx, query)
		if err != nil {
			t.Fatalf("read page %d: %v", pages, err)
		}
		if len(found) == 0 {
			break
		}
		for _, record := range found {
			seen[record.GetEventId()]++
		}
		last := found[len(found)-1]
		asked = &huntv1.Query{
			Range:  asked.GetRange(),
			Limit:  asked.GetLimit(),
			Cursor: compiler.Next(query, last.GetTime().GetEventTime().AsTime(), last.GetEventId()),
		}
	}

	if len(seen) != written {
		t.Errorf("paging read %d of %d records", len(seen), written)
	}
	for id, times := range seen {
		if times != 1 {
			t.Errorf("%s was read %d times", id, times)
		}
	}
}

// A replayed record is a second row until the parts holding it are merged, and
// an analyst reading the same event twice cannot tell that from the same thing
// happening twice.
func TestAReplayedEventIsReadOnce(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	owner := fmt.Sprintf("replayed%d", time.Now().UnixNano())
	record := admitted(owner, "55555555-2222-4333-8444-555555555555", "root", at)
	keep(t, store, record)
	keep(t, store, record)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	found, err := reader.Events(ctx, hunted(t, compiler, hunt.Events, owner,
		&huntv1.Query{Range: within(at.Add(-time.Hour), at.Add(time.Hour))}))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("an event delivered twice was read %d times", len(found))
	}
}

// Every operator the language has, against a real store, because a predicate
// that compiles and a predicate ClickHouse accepts are different claims.
func TestEveryOperatorIsAnsweredByTheStore(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	owner := fmt.Sprintf("asked%d", time.Now().UnixNano())
	keep(t, store,
		admitted(owner, "66666666-2222-4333-8444-000000000001", "root", at),
		admitted(owner, "66666666-2222-4333-8444-000000000002", "backup", at.Add(-time.Second)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	window := within(at.Add(-time.Hour), at.Add(time.Hour))

	for name, expected := range map[string]struct {
		where *huntv1.Expression
		found int
	}{
		"equals":       {term("authentication.user.name", huntv1.Operator_OPERATOR_EQUALS, "root"), 1},
		"one of":       {term("authentication.user.name", huntv1.Operator_OPERATOR_ONE_OF, "root", "backup"), 2},
		"contains":     {term("authentication.raw_record", huntv1.Operator_OPERATOR_CONTAINS, "Failed password for backup"), 1},
		"starts with":  {term("origin.host.hostname", huntv1.Operator_OPERATOR_STARTS_WITH, "web-01"), 2},
		"ends with":    {term("origin.host.hostname", huntv1.Operator_OPERATOR_ENDS_WITH, ".example"), 2},
		"above":        {term("collection.sequence", huntv1.Operator_OPERATOR_ABOVE, "41"), 2},
		"at least":     {term("authentication.network.source.port", huntv1.Operator_OPERATOR_AT_LEAST, "54321"), 2},
		"below":        {term("collection.sequence", huntv1.Operator_OPERATOR_BELOW, "42"), 0},
		"at most":      {term("authentication.network.destination.port", huntv1.Operator_OPERATOR_AT_MOST, "22"), 2},
		"present":      {term("authentication.user.name", huntv1.Operator_OPERATOR_PRESENT), 2},
		"a choice":     {term("authentication.outcome", huntv1.Operator_OPERATOR_EQUALS, "failure"), 2},
		"an instant":   {term("time.observed_time", huntv1.Operator_OPERATOR_AT_MOST, at.Format(time.RFC3339Nano)), 2},
		"not a choice": {negated(term("authentication.outcome", huntv1.Operator_OPERATOR_EQUALS, "success")), 2},
	} {
		t.Run(name, func(t *testing.T) {
			found, err := reader.Events(ctx, hunted(t, compiler, hunt.Events, owner,
				&huntv1.Query{Range: window, Where: expected.where}))
			if err != nil {
				t.Fatalf("the store refused the query: %v", err)
			}
			if len(found) != expected.found {
				t.Errorf("the store answered with %d records and %d were expected", len(found), expected.found)
			}
		})
	}
}

func negated(term *huntv1.Expression) *huntv1.Expression {
	return &huntv1.Expression{Form: &huntv1.Expression_Negated{Negated: term}}
}

// The pivot an investigation is built out of: from an event to the detections
// that were made from it, which is what the list column exists for.
func TestADetectionIsFoundByTheEventItWasMadeFrom(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedDetectionStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	owner := fmt.Sprintf("pivot%d", time.Now().UnixNano())
	made := madeDetection(owner, "77777777-2222-4333-8444-555555555555", at)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, []detectionstore.Row{detectionstore.Project(made)}); err != nil {
		t.Fatalf("keep the detection: %v", err)
	}

	window := within(at.Add(-time.Hour), at.Add(time.Hour))
	for name, where := range map[string]*huntv1.Expression{
		"by the event it was made from": term("source_event_ids", huntv1.Operator_OPERATOR_EQUALS,
			made.GetSourceEventIds()[0]),
		"by what the rule read": term("evidence.field", huntv1.Operator_OPERATOR_EQUALS, "authentication.outcome"),
		"by severity":           term("severity", huntv1.Operator_OPERATOR_EQUALS, "high"),
		"by rule":               term("rule.id", huntv1.Operator_OPERATOR_EQUALS, made.GetRule().GetId()),
	} {
		t.Run(name, func(t *testing.T) {
			found, err := reader.Detections(ctx, hunted(t, compiler, hunt.Detections, owner,
				&huntv1.Query{Range: window, Where: where}))
			if err != nil {
				t.Fatalf("the store refused the query: %v", err)
			}
			if len(found) != 1 {
				t.Fatalf("the hunt found %d detections", len(found))
			}
			if !proto.Equal(made, found[0]) {
				t.Errorf("the store answered with a different detection:\n made %v\n read %v", made, found[0])
			}
		})
	}
}

// The window is what makes a query answerable, and a record outside it is not an
// answer however well it matches everything else.
func TestARecordOutsideTheWindowIsNotAnAnswer(t *testing.T) {
	address := storeAddress(t)
	store, reader := migratedStore(t, address), migratedHunter(t, address)
	compiler := huntCompiler(t)

	at := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	owner := fmt.Sprintf("outside%d", time.Now().UnixNano())
	keep(t, store, admitted(owner, "88888888-2222-4333-8444-555555555555", "root", at))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	found, err := reader.Events(ctx, hunted(t, compiler, hunt.Events, owner,
		&huntv1.Query{Range: within(at.Add(time.Minute), at.Add(time.Hour))}))
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("a record from before the window was answered with %d times", len(found))
	}
}

package control_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
)

func store(t *testing.T, lifetime time.Duration, perSubject int) *control.Sessions {
	t.Helper()

	key, err := authz.RandomSessionKey()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	issuer, err := authz.NewIssuer(key, lifetime)
	if err != nil {
		t.Fatalf("build an issuer: %v", err)
	}
	sessions, err := control.NewSessions(control.SessionOptions{Issuer: issuer, PerSubject: perSubject})
	if err != nil {
		t.Fatalf("build a session store: %v", err)
	}
	return sessions
}

func bind(subject string) [32]byte { return authz.Fingerprint(certificate(subject)) }

func TestAnUnknownSessionIsRefusedEvenWithAGoodSignature(t *testing.T) {
	sessions := store(t, time.Hour, 0)

	session, token, err := sessions.Open("alice", bind("alice"), now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := sessions.Verify(token, bind("alice"), now); err != nil {
		t.Fatalf("a live session was refused: %v", err)
	}

	sessions.Revoke(session.ID())
	if _, err := sessions.Verify(token, bind("alice"), now); !errors.Is(err, control.ErrRevoked) {
		t.Errorf("a revoked session produced %v", err)
	}
	if ended := sessions.Revoke(session.ID()); ended != 0 {
		t.Errorf("revoking twice ended %d sessions", ended)
	}
}

func TestASubjectAtItsCeilingLosesItsOldestSession(t *testing.T) {
	sessions := store(t, time.Hour, 2)

	first, firstToken, err := sessions.Open("alice", bind("alice"), now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := sessions.Open("alice", bind("alice"), now); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := sessions.Open("alice", bind("alice"), now); err != nil {
		t.Fatalf("open: %v", err)
	}

	if held := len(sessions.Held("alice")); held != 2 {
		t.Errorf("the subject holds %d sessions", held)
	}
	if _, err := sessions.Verify(firstToken, bind("alice"), now); !errors.Is(err, control.ErrRevoked) {
		t.Errorf("the oldest session %q survived: %v", first.ID(), err)
	}
}

func TestOneSubjectsCeilingDoesNotReachAnother(t *testing.T) {
	sessions := store(t, time.Hour, 1)

	if _, _, err := sessions.Open("alice", bind("alice"), now); err != nil {
		t.Fatalf("open: %v", err)
	}
	_, token, err := sessions.Open("bob", bind("bob"), now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := sessions.Open("alice", bind("alice"), now); err != nil {
		t.Fatalf("open: %v", err)
	}

	if _, err := sessions.Verify(token, bind("bob"), now); err != nil {
		t.Errorf("alice's churn ended bob's session: %v", err)
	}
}

func TestEndingASubjectEndsEverySessionItHolds(t *testing.T) {
	sessions := store(t, time.Hour, 4)

	tokens := make([]string, 0, 3)
	for range 3 {
		_, token, err := sessions.Open("alice", bind("alice"), now)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		tokens = append(tokens, token)
	}
	if _, _, err := sessions.Open("bob", bind("bob"), now); err != nil {
		t.Fatalf("open: %v", err)
	}

	if ended := sessions.RevokeSubject("alice"); ended != 3 {
		t.Errorf("ending the subject ended %d sessions", ended)
	}
	for index, token := range tokens {
		if _, err := sessions.Verify(token, bind("alice"), now); !errors.Is(err, control.ErrRevoked) {
			t.Errorf("session %d survived: %v", index, err)
		}
	}
	if sessions.Live() != 1 {
		t.Errorf("%d sessions are still live", sessions.Live())
	}
	if held := sessions.Subjects(); len(held) != 1 || held[0] != "bob" {
		t.Errorf("the store holds sessions for %v", held)
	}
}

func TestExpiredSessionsAreForgotten(t *testing.T) {
	sessions := store(t, time.Minute, 4)

	if _, _, err := sessions.Open("alice", bind("alice"), now); err != nil {
		t.Fatalf("open: %v", err)
	}
	if sessions.Sweep(now) != 0 {
		t.Error("a live session was swept")
	}
	if ended := sessions.Sweep(now.Add(time.Hour)); ended != 1 {
		t.Errorf("sweeping ended %d sessions", ended)
	}
	if sessions.Live() != 0 {
		t.Errorf("%d sessions survived the sweep", sessions.Live())
	}
}

func TestAStoreRefusesWhatItCannotHold(t *testing.T) {
	key, err := authz.RandomSessionKey()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	issuer, err := authz.NewIssuer(key, time.Hour)
	if err != nil {
		t.Fatalf("build an issuer: %v", err)
	}

	if _, err := control.NewSessions(control.SessionOptions{}); err == nil {
		t.Error("a store with no issuer was built")
	}
	if _, err := control.NewSessions(control.SessionOptions{Issuer: issuer, PerSubject: 8, Capacity: 4}); err == nil {
		t.Error("a capacity too small for one subject was accepted")
	}
}

func TestARecordCarriesNoWayBackToASession(t *testing.T) {
	sessions := store(t, time.Hour, 4)

	session, token, err := sessions.Open("alice", bind("alice"), now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	held := sessions.Held("alice")
	if len(held) != 1 {
		t.Fatalf("the subject holds %d sessions", len(held))
	}
	if held[0].ID != session.ID() || held[0].Subject != "alice" {
		t.Errorf("the record reads %q for %q", held[0].ID, held[0].Subject)
	}
	if held[0].ExpiresAt.Before(held[0].IssuedAt) {
		t.Error("the record expires before it was issued")
	}
	if _, err := sessions.Verify(held[0].ID, bind("alice"), now); err == nil {
		t.Error("a record identifier was spendable as a token")
	}
	if held[0].ID == token {
		t.Error("the record carries the token")
	}
}

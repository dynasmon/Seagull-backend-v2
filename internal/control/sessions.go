package control

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
)

var ErrRevoked = errors.New("the session is no longer live")

const (
	DefaultPerSubject = 8
	DefaultCapacity   = 4096
)

type SessionOptions struct {
	Issuer     *authz.Issuer
	PerSubject int
	Capacity   int
}

// The sessions this process has minted and still honours.
//
// It is an allowlist and not a list of revocations: a token is spendable only
// while its session is in here, so ending one takes effect at the next request
// rather than at its expiry, and nothing survives a restart. The signing key is
// drawn per process anyway, so tokens already die when the process does — this
// only makes that true before it does.
type Sessions struct {
	issuer     *authz.Issuer
	perSubject int
	capacity   int

	mu      sync.Mutex
	live    map[string]live
	holders map[string][]string
}

type live struct {
	subject   string
	issuedAt  time.Time
	expiresAt time.Time
	binding   [sha256.Size]byte
}

func NewSessions(options SessionOptions) (*Sessions, error) {
	if options.Issuer == nil {
		return nil, errors.New("a session store needs an issuer")
	}
	if options.PerSubject <= 0 {
		options.PerSubject = DefaultPerSubject
	}
	if options.Capacity <= 0 {
		options.Capacity = DefaultCapacity
	}
	if options.Capacity < options.PerSubject {
		return nil, fmt.Errorf("a capacity of %d cannot hold one subject's %d sessions", options.Capacity, options.PerSubject)
	}

	return &Sessions{
		issuer:     options.Issuer,
		perSubject: options.PerSubject,
		capacity:   options.Capacity,
		live:       make(map[string]live, options.PerSubject),
		holders:    make(map[string][]string),
	}, nil
}

func (s *Sessions) Lifetime() time.Duration { return s.issuer.Lifetime() }

func (s *Sessions) Open(subject string, binding [sha256.Size]byte, now time.Time) (authz.Session, string, error) {
	session, token, err := s.issuer.Issue(subject, binding, now)
	if err != nil {
		return authz.Session{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(now)

	held := s.holders[subject]
	for len(held) >= s.perSubject {
		delete(s.live, held[0])
		held = held[1:]
	}
	if len(s.live) >= s.capacity {
		return authz.Session{}, "", errors.New("the process is holding as many sessions as it will hold")
	}

	s.live[session.ID()] = live{
		subject:   subject,
		issuedAt:  session.IssuedAt(),
		expiresAt: session.ExpiresAt(),
		binding:   binding,
	}
	s.holders[subject] = append(held, session.ID())
	return session, token, nil
}

// Verify reads a token back and confirms the session behind it is still live.
// The cryptography is checked first, so a caller who cannot forge a token cannot
// learn from the timing which sessions exist.
func (s *Sessions) Verify(token string, presented [sha256.Size]byte, now time.Time) (authz.Session, error) {
	session, err := s.issuer.Verify(token, presented, now)
	if err != nil {
		return authz.Session{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	held, ok := s.live[session.ID()]
	if !ok || held.subject != session.Subject() {
		return authz.Session{}, ErrRevoked
	}
	return session, nil
}

func (s *Sessions) Revoke(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeLocked(id)
}

func (s *Sessions) RevokeSubject(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	ended := 0
	for _, id := range slices.Clone(s.holders[subject]) {
		ended += s.revokeLocked(id)
	}
	return ended
}

func (s *Sessions) revokeLocked(id string) int {
	held, ok := s.live[id]
	if !ok {
		return 0
	}
	delete(s.live, id)

	remaining := slices.DeleteFunc(s.holders[held.subject], func(other string) bool { return other == id })
	if len(remaining) == 0 {
		delete(s.holders, held.subject)
	} else {
		s.holders[held.subject] = remaining
	}
	return 1
}

func (s *Sessions) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

func (s *Sessions) sweepLocked(now time.Time) int {
	ended := 0
	for id, held := range s.live {
		if !now.Before(held.expiresAt) {
			ended += s.revokeLocked(id)
		}
	}
	return ended
}

func (s *Sessions) Live() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

type Record struct {
	ID        string
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func (s *Sessions) Held(subject string) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	held := make([]Record, 0, len(s.holders[subject]))
	for _, id := range s.holders[subject] {
		if one, ok := s.live[id]; ok {
			held = append(held, Record{ID: id, Subject: one.subject, IssuedAt: one.issuedAt, ExpiresAt: one.expiresAt})
		}
	}
	return held
}

func (s *Sessions) Subjects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	held := make([]string, 0, len(s.holders))
	for subject := range s.holders {
		held = append(held, subject)
	}
	slices.Sort(held)
	return held
}

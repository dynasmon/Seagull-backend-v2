package authz

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// One algorithm, not negotiable: a build that changes this layout refuses
// yesterday's tokens rather than reading them as something else.
const tokenVersion byte = 1

const (
	sessionIDBytes = 16
	fixedBytes     = 1 + sessionIDBytes + 8 + 8 + sha256.Size
	maxTokenBytes  = fixedBytes + 128
)

var (
	ErrToken = errors.New("the token was not issued here")

	ErrExpired = errors.New("the session has expired")

	ErrWrongCertificate = errors.New("the token was issued to a different certificate")
)

// Carries identity and no authority. What the subject may do is resolved from
// the current policy per request, so a role taken away takes effect at the next
// request rather than at the next expiry.
type Session struct {
	id        string
	subject   string
	issuedAt  time.Time
	expiresAt time.Time
	binding   [sha256.Size]byte
}

func (s Session) ID() string { return s.id }

func (s Session) Subject() string { return s.subject }

func (s Session) IssuedAt() time.Time { return s.issuedAt }

func (s Session) ExpiresAt() time.Time { return s.expiresAt }

func (s Session) Binding() [sha256.Size]byte { return s.binding }

func (s Session) Empty() bool { return s.id == "" }

func (s Session) Expired(now time.Time) bool { return !now.Before(s.expiresAt) }

// Names a certificate by the whole of what was signed, so re-enrolling under one
// common name does not inherit the sessions of the certificate it replaced.
func Fingerprint(certificate *x509.Certificate) [sha256.Size]byte {
	if certificate == nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(certificate.Raw)
}

type Issuer struct {
	key      []byte
	lifetime time.Duration
}

func NewIssuer(key []byte, lifetime time.Duration) (*Issuer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("a session key is at least 32 bytes and this one is %d", len(key))
	}
	if lifetime <= 0 {
		return nil, errors.New("a session that never expires is not a session")
	}
	return &Issuer{key: append([]byte(nil), key...), lifetime: lifetime}, nil
}

func (i *Issuer) Lifetime() time.Duration { return i.lifetime }

func (i *Issuer) Issue(subject string, binding [sha256.Size]byte, now time.Time) (Session, string, error) {
	if !ValidSubject(subject) {
		return Session{}, "", fmt.Errorf("%q is not a subject", subject)
	}
	if binding == ([sha256.Size]byte{}) {
		return Session{}, "", errors.New("a session is bound to the certificate that asked for it and none was given")
	}

	raw := make([]byte, sessionIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return Session{}, "", fmt.Errorf("draw a session identifier: %w", err)
	}

	session := Session{
		id:        hex.EncodeToString(raw),
		subject:   subject,
		issuedAt:  now.UTC().Truncate(time.Millisecond),
		expiresAt: now.UTC().Add(i.lifetime).Truncate(time.Millisecond),
		binding:   binding,
	}
	return session, i.encode(session, raw), nil
}

// Signature first, so a caller who cannot forge a token learns nothing from the
// order in which the remaining checks fail.
func (i *Issuer) Verify(token string, presented [sha256.Size]byte, now time.Time) (Session, error) {
	written, signature, found := strings.Cut(token, ".")
	if !found {
		return Session{}, ErrToken
	}

	encoding := base64.RawURLEncoding
	payload, err := encoding.DecodeString(written)
	if err != nil {
		return Session{}, ErrToken
	}
	offered, err := encoding.DecodeString(signature)
	if err != nil {
		return Session{}, ErrToken
	}
	if len(payload) < fixedBytes || len(payload) > maxTokenBytes {
		return Session{}, ErrToken
	}
	if !hmac.Equal(offered, i.sign(payload)) {
		return Session{}, ErrToken
	}
	if payload[0] != tokenVersion {
		return Session{}, ErrToken
	}

	session := Session{
		id:        hex.EncodeToString(payload[1 : 1+sessionIDBytes]),
		issuedAt:  time.UnixMilli(int64(binary.BigEndian.Uint64(payload[1+sessionIDBytes:]))).UTC(),
		expiresAt: time.UnixMilli(int64(binary.BigEndian.Uint64(payload[9+sessionIDBytes:]))).UTC(),
		subject:   string(payload[fixedBytes:]),
	}
	copy(session.binding[:], payload[17+sessionIDBytes:fixedBytes])

	if !ValidSubject(session.subject) {
		return Session{}, ErrToken
	}
	if session.Expired(now) {
		return Session{}, ErrExpired
	}
	if !hmac.Equal(session.binding[:], presented[:]) {
		return Session{}, ErrWrongCertificate
	}
	return session, nil
}

func (i *Issuer) encode(session Session, id []byte) string {
	payload := make([]byte, fixedBytes, fixedBytes+len(session.subject))
	payload[0] = tokenVersion
	copy(payload[1:], id)
	binary.BigEndian.PutUint64(payload[1+sessionIDBytes:], uint64(session.issuedAt.UnixMilli()))
	binary.BigEndian.PutUint64(payload[9+sessionIDBytes:], uint64(session.expiresAt.UnixMilli()))
	copy(payload[17+sessionIDBytes:], session.binding[:])
	payload = append(payload, session.subject...)

	encoding := base64.RawURLEncoding
	return encoding.EncodeToString(payload) + "." + encoding.EncodeToString(i.sign(payload))
}

func (i *Issuer) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, i.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

func RandomSessionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate a session key: %w", err)
	}
	return key, nil
}

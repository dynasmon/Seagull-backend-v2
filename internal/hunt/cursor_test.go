package hunt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	cursorKey   = []byte(strings.Repeat("k", 32))
	fingerprint = sha256.Sum256([]byte("events in a window"))
	resumedAt   = time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)
)

func signedToken(payload []byte, written ...[]byte) string {
	mac := hmac.New(sha256.New, cursorKey)
	for _, part := range written {
		mac.Write(part)
	}
	encoding := base64.RawURLEncoding
	return encoding.EncodeToString(payload) + "." + encoding.EncodeToString(mac.Sum(nil))
}

func instant(at time.Time) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(at.UnixMilli()))
}

func TestAPositionCarriesEveryNameItWasGiven(t *testing.T) {
	for _, names := range [][]string{{"web-01", "aaaa-1111"}, {"", "aaaa-1111"}, {"dddd-4444"}} {
		after, err := decodeCursor(cursorKey, fingerprint, encodeCursor(cursorKey, fingerprint, resumedAt, names...))
		if err != nil {
			t.Fatalf("decode a position named %q: %v", names, err)
		}
		if !after.Set || !after.Time.Equal(resumedAt) || !slices.Equal(after.Names, names) {
			t.Errorf("a position named %q resumed at %+v", names, after)
		}
	}
}

// Before events were named by their agent, a position was the instant followed
// by one bare identifier, signed over the query and the position alone. One
// written that way can spell a valid position of the current layout, so it has
// to be refused on its signature rather than on how it reads.
func TestACursorWrittenInTheEarlierLayoutIsRefused(t *testing.T) {
	identifier := "0" + strings.Repeat("a", 48)
	payload := append(instant(resumedAt), identifier...)

	if _, err := decodeCursor(cursorKey, fingerprint, signedToken(payload, fingerprint[:], payload)); !errors.Is(err, ErrCursor) {
		t.Fatalf("a cursor of the earlier layout was accepted: %v", err)
	}
}

func TestAPositionThatIsNotWellFormedIsRefusedEvenWhenSigned(t *testing.T) {
	name := func(value string) []byte { return append(binary.AppendUvarint(nil, uint64(len(value))), value...) }

	for reason, position := range map[string][]byte{
		"no name":             nil,
		"a name cut short":    {9, 'w', 'e', 'b'},
		"bytes after a name":  append(name("web-01"), 'x'),
		"three names":         slices.Concat(name("web-01"), name("aaaa-1111"), name("bbbb-2222")),
		"a name over the cap": name(strings.Repeat("a", maxCursorName+1)),
	} {
		t.Run(reason, func(t *testing.T) {
			payload := append(instant(resumedAt), position...)
			token := signedToken(payload, []byte(cursorLayout), fingerprint[:], payload)
			if _, err := decodeCursor(cursorKey, fingerprint, token); !errors.Is(err, ErrCursor) {
				t.Fatalf("a position with %s was accepted: %v", reason, err)
			}
		})
	}
}

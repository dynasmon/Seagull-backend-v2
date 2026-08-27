package hunt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxCursorIdentifier = 128

var ErrCursor = errors.New("the cursor was not issued for this query")

// Where the next page starts, named by the last record of the page before it
// rather than by how many records were skipped. An offset re-reads everything it
// steps over and moves under a concurrent write; a key does neither, and the
// store is sorted by exactly this pair.
type After struct {
	Set  bool
	Time time.Time
	ID   string
}

// A cursor is signed with a key the server holds, and the query it belongs to is
// signed along with it. A caller therefore cannot compose a position, and cannot
// carry page two of one question into a different one — which is what keeps a
// page from being served under a scope or a filter that did not produce it.
func encodeCursor(key []byte, fingerprint [sha256.Size]byte, at time.Time, id string) string {
	payload := make([]byte, 8, 8+len(id))
	binary.BigEndian.PutUint64(payload, uint64(at.UnixMilli()))
	payload = append(payload, id...)

	encoding := base64.RawURLEncoding
	return encoding.EncodeToString(payload) + "." + encoding.EncodeToString(sign(key, fingerprint, payload))
}

func decodeCursor(key []byte, fingerprint [sha256.Size]byte, token string) (After, error) {
	written, signature, found := strings.Cut(token, ".")
	if !found {
		return After{}, ErrCursor
	}

	encoding := base64.RawURLEncoding
	payload, err := encoding.DecodeString(written)
	if err != nil {
		return After{}, ErrCursor
	}
	presented, err := encoding.DecodeString(signature)
	if err != nil {
		return After{}, ErrCursor
	}
	if !hmac.Equal(presented, sign(key, fingerprint, payload)) {
		return After{}, ErrCursor
	}
	if len(payload) < 8 || len(payload) > 8+maxCursorIdentifier {
		return After{}, ErrCursor
	}

	return After{
		Set:  true,
		Time: time.UnixMilli(int64(binary.BigEndian.Uint64(payload))).UTC(),
		ID:   string(payload[8:]),
	}, nil
}

func sign(key []byte, fingerprint [sha256.Size]byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(fingerprint[:])
	mac.Write(payload)
	return mac.Sum(nil)
}

// A key nobody configured is a key nobody shares, which is the safe default: the
// cursors a process issues stop being spendable when it stops running.
func RandomCursorKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate a cursor key: %w", err)
	}
	return key, nil
}

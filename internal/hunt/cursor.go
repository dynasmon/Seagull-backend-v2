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

const (
	maxCursorName  = 128
	maxCursorNames = 2
)

// The layout of a position is signed along with it, so a cursor written in any
// other layout is refused instead of being read as a different position.
const cursorLayout = "seagull.hunt.cursor/2"

var ErrCursor = errors.New("the cursor was not issued for this query")

// Where the next page starts, named by the last record of the page before it
// rather than by how many records were skipped. An offset re-reads everything it
// steps over and moves under a concurrent write; a key does neither, and the
// store is sorted by exactly this: the instant, then the names that tell two
// records of one instant apart.
type After struct {
	Set   bool
	Time  time.Time
	Names []string
}

// A cursor is signed with a key the server holds, and the query it belongs to is
// signed along with it. A caller therefore cannot compose a position, and cannot
// carry page two of one question into a different one — which is what keeps a
// page from being served under a scope or a filter that did not produce it.
func encodeCursor(key []byte, fingerprint [sha256.Size]byte, at time.Time, names ...string) string {
	payload := binary.BigEndian.AppendUint64(nil, uint64(at.UnixMilli()))
	for _, name := range names {
		payload = binary.AppendUvarint(payload, uint64(len(name)))
		payload = append(payload, name...)
	}

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
	if len(payload) < 8 {
		return After{}, ErrCursor
	}
	names, ok := readNames(payload[8:])
	if !ok {
		return After{}, ErrCursor
	}

	return After{
		Set:   true,
		Time:  time.UnixMilli(int64(binary.BigEndian.Uint64(payload))).UTC(),
		Names: names,
	}, nil
}

func readNames(written []byte) ([]string, bool) {
	var names []string
	for len(written) > 0 {
		length, read := binary.Uvarint(written)
		if read <= 0 || length > maxCursorName || length > uint64(len(written)-read) || len(names) == maxCursorNames {
			return nil, false
		}
		end := read + int(length)
		names = append(names, string(written[read:end]))
		written = written[end:]
	}
	return names, len(names) > 0
}

func sign(key []byte, fingerprint [sha256.Size]byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cursorLayout))
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

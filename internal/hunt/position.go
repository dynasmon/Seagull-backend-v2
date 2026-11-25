package hunt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	maxPositionValues = 8
	maxPositionValue  = 1024
)

// A listing resumes after the key its store sorts by, which only the store can
// name: a package's name and version, an asset's tenant and agent. The plane
// treats the values as opaque and signs them with the question, in a layout of
// their own, so a hunt's cursor is never read as a listing's or the reverse.
const positionLayout = "seagull.listing.cursor/1"

func encodePosition(key []byte, fingerprint [sha256.Size]byte, values []string) (string, error) {
	if len(values) == 0 || len(values) > maxPositionValues {
		return "", fmt.Errorf("a position names between 1 and %d values and this one names %d", maxPositionValues, len(values))
	}
	var payload []byte
	for _, value := range values {
		if len(value) > maxPositionValue {
			return "", fmt.Errorf("a position holds values of at most %d bytes and one is %d", maxPositionValue, len(value))
		}
		payload = binary.AppendUvarint(payload, uint64(len(value)))
		payload = append(payload, value...)
	}
	encoding := base64.RawURLEncoding
	return encoding.EncodeToString(payload) + "." + encoding.EncodeToString(sign(positionLayout, key, fingerprint, payload)), nil
}

func decodePosition(key []byte, fingerprint [sha256.Size]byte, token string) ([]string, error) {
	written, signature, found := strings.Cut(token, ".")
	if !found {
		return nil, ErrCursor
	}
	encoding := base64.RawURLEncoding
	payload, err := encoding.DecodeString(written)
	if err != nil {
		return nil, ErrCursor
	}
	presented, err := encoding.DecodeString(signature)
	if err != nil || !hmac.Equal(presented, sign(positionLayout, key, fingerprint, payload)) {
		return nil, ErrCursor
	}

	var values []string
	for len(payload) > 0 {
		length, read := binary.Uvarint(payload)
		if read <= 0 || length > maxPositionValue || length > uint64(len(payload)-read) || len(values) == maxPositionValues {
			return nil, ErrCursor
		}
		end := read + int(length)
		values = append(values, string(payload[read:end]))
		payload = payload[end:]
	}
	if len(values) == 0 {
		return nil, errors.Join(ErrCursor, errors.New("it names no position"))
	}
	return values, nil
}

package disposition

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func newID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("draw a disposition identifier: %w", err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	text := hex.EncodeToString(id[:])
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:], nil
}

// A disposition is named by the identifier the platform drew for it, written
// the one way it draws it, so a name read from a path is never anything else.
func ValidID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index, character := range id {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

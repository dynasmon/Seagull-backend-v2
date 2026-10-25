package broker

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAQuarantineReasonTravelsWithinTheRoomBesideTheRecord(t *testing.T) {
	long := strings.Repeat("é", 64<<10)

	held := bounded(long)
	if len(held) > 4<<10 {
		t.Errorf("a reason of %d bytes travels as %d", len(long), len(held))
	}
	if !utf8.ValidString(held) || !strings.HasPrefix(long, held) || held == "" {
		t.Errorf("a long reason was cut into %q rather than at a character boundary", held[max(0, len(held)-8):])
	}

	short := "items[3].package.name is longer than 256 bytes"
	if bounded(short) != short {
		t.Errorf("a short reason travels as %q", bounded(short))
	}
}

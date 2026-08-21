package event_test

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
)

func BenchmarkValidate(b *testing.B) {
	at := time.Now().UTC()
	record := fixtures.SSHAuthentication{At: at}.Event()
	policy := event.Policy{MaxClockSkew: 5 * time.Minute, MaxAge: 168 * time.Hour}

	b.ReportAllocs()
	for range b.N {
		if err := event.Validate(record, at, policy); err != nil {
			b.Fatalf("validate: %v", err)
		}
	}
}

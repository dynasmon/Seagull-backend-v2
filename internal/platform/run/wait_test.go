package run_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
)

func TestADependencyIsAskedUntilItAnswersAndNoLongerThanPatienceAllows(t *testing.T) {
	refused := errors.New("connection refused")
	asked := 0
	if err := run.Until(context.Background(), time.Minute, time.Millisecond, func(context.Context) error {
		if asked++; asked < 3 {
			return refused
		}
		return nil
	}); err != nil || asked != 3 {
		t.Fatalf("a dependency answering on the third ask was given up on after %d asks: %v", asked, err)
	}

	started := time.Now()
	err := run.Until(context.Background(), 20*time.Millisecond, time.Millisecond, func(context.Context) error { return refused })
	if !errors.Is(err, refused) || time.Since(started) > time.Second {
		t.Fatalf("a dependency that never answers ended the wait with %v after %s", err, time.Since(started))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run.Until(ctx, time.Hour, time.Hour, func(context.Context) error { return refused }); !errors.Is(err, context.Canceled) {
		t.Fatalf("a stopped wait ended with %v", err)
	}
}

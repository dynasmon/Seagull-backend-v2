package run

import (
	"context"
	"fmt"
	"time"
)

// Until asks whether a dependency answers until it does, pausing between asks,
// for no longer than patience: one still starting is waited for, and one that
// never answers is an error naming its last refusal rather than a hang.
func Until(ctx context.Context, patience, pause time.Duration, answers func(context.Context) error) error {
	deadline := time.Now().Add(patience)
	for {
		err := answers(ctx)
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil:
			return ctx.Err()
		case !time.Now().Before(deadline):
			return fmt.Errorf("no answer within %s: %w", patience, err)
		}
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

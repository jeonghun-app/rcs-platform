package awsstore

import (
	"context"
	"time"
)

// pause waits pace before every write of a long run but its first (done
// is how many went before), or returns ctx's error when ctx ends first.
func pause(ctx context.Context, done int, pace time.Duration) error {
	if done == 0 || pace <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(pace)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

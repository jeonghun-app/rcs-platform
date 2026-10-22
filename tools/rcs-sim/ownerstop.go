package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// ownerStopPoll is how often ownerStopper looks for the host's answer.
const ownerStopPoll = 100 * time.Millisecond

// ownerStopper stops a group's owner task through the handshake directory
// dir, which make e2e-compose gives (scripts/e2e-compose.sh): it writes the
// conference URI to dir/conference, for the e2e test to find the owner and
// have the host stop it, and returns once dir/stopped is there, or with an
// error once dir/failed is, or when ctx ends. The URI goes only to that
// file, never to a result line.
func ownerStopper(dir string) func(ctx context.Context, conf sip.URI) error {
	return func(ctx context.Context, conf sip.URI) error {
		tmp := filepath.Join(dir, "conference.tmp")
		if err := os.WriteFile(tmp, []byte(conf.String()), 0o644); err != nil {
			return errors.New("writing the owner stop request failed")
		}
		if err := os.Rename(tmp, filepath.Join(dir, "conference")); err != nil {
			return errors.New("writing the owner stop request failed")
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "stopped")); err == nil {
				return nil
			}
			if _, err := os.Stat(filepath.Join(dir, "failed")); err == nil {
				return errors.New("the host could not stop the group's owner")
			}
			select {
			case <-ctx.Done():
				return errors.New("the group's owner was not stopped in time")
			case <-time.After(ownerStopPoll):
			}
		}
	}
}

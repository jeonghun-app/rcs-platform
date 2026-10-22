// Package anchor plays pcscf's part toward msrp-relay: it allocates,
// completes and releases bindings through the relay's control API
// (docs/api/msrp-relay.yaml) in the order pcscf does while it rewrites SDP
// (docs/msrp-relay.md, "How a session is anchored"). Step 1 of the simulator
// has no SIP, so the simulator itself takes this part; step 2 leaves it to
// pcscf.
//
// The control API is internal (ADR 0007): this works against a local stack,
// not from outside a deployed VPC. The token is never printed, and the
// client_path the relay returns, which carries the session id that admits a
// client, stays in the Binding the caller holds.
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// Control is a client of one relay's control API.
type Control struct {
	// HTTP sends requests; it must not follow redirects (ADR 0007 §5).
	HTTP *http.Client
	// URL is the control API's base, e.g. http://msrp-relay.rcs.local:8082.
	URL *url.URL
	// Token is pcscf's bearer token, which prints as "[redacted]" under the
	// valid verbs and as its closure's address under the invalid ones, never
	// as its bytes (#538, #570).
	Token secret.Key
}

// Binding is what POST returned.
type Binding struct {
	ID string
	// ClientPath is the relay's URI the client connects to; CoreLocal the
	// relay's URI the core side sees.
	ClientPath, CoreLocal msrp.URI
	ExpiresAt             time.Time
}

// Paths are the endpoint paths known so far; a zero URI is not sent.
type Paths struct {
	Core, Client msrp.URI
}

func (p Paths) body(expires time.Duration) map[string]any {
	b := map[string]any{}
	if p.Core.SessionID != "" {
		b["core_path"] = []string{p.Core.String()}
	}
	if p.Client.SessionID != "" {
		b["client_endpoint_path"] = []string{p.Client.String()}
	}
	if expires > 0 {
		b["expires_in"] = int64(expires / time.Second)
	}
	return b
}

// StatusError is an answer other than the one expected.
type StatusError struct {
	Op     string
	Status int
}

func (e *StatusError) Error() string {
	return "anchor: " + e.Op + ": HTTP " + strconv.Itoa(e.Status)
}

// Allocate creates a binding with the paths known at the offer.
func (c *Control) Allocate(ctx context.Context, p Paths, expires time.Duration) (Binding, error) {
	var out struct {
		ID            string `json:"id"`
		ClientPath    string `json:"client_path"`
		CorePathLocal string `json:"core_path_local"`
		ExpiresAt     string `json:"expires_at"`
	}
	if err := c.call(ctx, "allocate", http.MethodPost, "/v1/bindings", p.body(expires), http.StatusCreated, &out); err != nil {
		return Binding{}, err
	}
	client, err1 := msrp.ParseURI(out.ClientPath)
	core, err2 := msrp.ParseURI(out.CorePathLocal)
	expiresAt, err3 := time.Parse(time.RFC3339Nano, out.ExpiresAt)
	if err1 != nil || err2 != nil || err3 != nil || out.ID == "" {
		return Binding{}, errors.New("anchor: allocate: malformed answer")
	}
	return Binding{ID: out.ID, ClientPath: client, CoreLocal: core, ExpiresAt: expiresAt}, nil
}

// Complete records the path learnt from the answer, and may extend the
// binding; pcscf does this before forwarding the answer.
func (c *Control) Complete(ctx context.Context, id string, p Paths, expires time.Duration) error {
	return c.call(ctx, "complete", http.MethodPatch, "/v1/bindings/"+url.PathEscape(id), p.body(expires), http.StatusOK, nil)
}

// Release deletes the binding, as pcscf does on BYE.
func (c *Control) Release(ctx context.Context, id string) error {
	return c.call(ctx, "release", http.MethodDelete, "/v1/bindings/"+url.PathEscape(id), nil, http.StatusNoContent, nil)
}

func (c *Control) call(ctx context.Context, op, method, path string, body map[string]any, want int, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL.JoinPath(path).String(), rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token.RevealString())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("anchor: %s: %w", op, safeerr.Reason(err))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != want {
		return &StatusError{Op: op, Status: resp.StatusCode}
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(out); err != nil {
			return fmt.Errorf("anchor: %s: malformed answer", op)
		}
	}
	return nil
}

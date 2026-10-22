package pcscf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// The relay's control API (docs/api/msrp-relay.yaml), through which pcscf
// allocates, completes, extends and releases the MSRP bindings of the
// sessions it anchors (ADR 0004).
var (
	// errRelayConflict is a 409: the binding has another path already,
	// which a new session needs a new binding for (RFC 4975 §8.4).
	errRelayConflict = errors.New("pcscf: relay binding has another path")
	// errRelayGone is a 404: the binding expired or was released.
	errRelayGone = errors.New("pcscf: relay binding gone")
	// errRelayInvalid is a 400: the relay will not take a path pcscf sent,
	// which waiting will not change.
	errRelayInvalid = errors.New("pcscf: relay refused a path")
)

// maxRelayResponse bounds a control API answer read; one is a few hundred
// bytes.
const maxRelayResponse = 16 << 10

// relayBindingID is the form of a binding id: SHA-256, base32.
var relayBindingID = regexp.MustCompile(`^[a-z2-7]{52}$`)

// relayBinding is a binding the relay allocated: its id, which may be
// logged, the client_path the client connects to, a secret that must not
// be (RFC 4975 §14.1), and the relay's own path toward rcs-as.
type relayBinding struct {
	ID            string
	ClientPath    string
	CorePathLocal string
}

// relayPaths is what pcscf tells the relay of a session: the endpoint paths
// it learnt, each set once, and for how long to keep the binding.
type relayPaths struct {
	CorePath           []string `json:"core_path,omitempty"`
	ClientEndpointPath []string `json:"client_endpoint_path,omitempty"`
	ExpiresIn          int64    `json:"expires_in,omitempty"`
}

// relayClient calls the control API with pcscf's bearer token, which
// prints as "[redacted]" under every verb (#538).
type relayClient struct {
	base   *url.URL
	token  secret.Key
	client *http.Client
}

// newRelayClient returns a client of the control API at base. timeout
// bounds each call, the dial included; dial opens its connections, in
// staging and prod a runtime.InternalDialer's, so that the token reaches
// only a private address whatever the relay's name resolves to (ADR 0007
// §5).
func newRelayClient(base *url.URL, token secret.Key, timeout time.Duration, dial func(ctx context.Context, network, address string) (net.Conn, error)) *relayClient {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dial,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
	return &relayClient{base: base, token: token, client: &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// The token must not follow a redirect to another host.
		CheckRedirect: runtime.RefuseRedirects,
	}}
}

// create allocates a binding for p.
func (c *relayClient) create(ctx context.Context, p relayPaths) (relayBinding, error) {
	var out struct {
		ID            string `json:"id"`
		ClientPath    string `json:"client_path"`
		CorePathLocal string `json:"core_path_local"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/bindings", p, http.StatusCreated, &out); err != nil {
		return relayBinding{}, err
	}
	if !relayBindingID.MatchString(out.ID) || out.ClientPath == "" || out.CorePathLocal == "" {
		return relayBinding{}, errors.New("pcscf: relay answered an incomplete binding")
	}
	return relayBinding(out), nil
}

// update completes or extends binding id with p.
func (c *relayClient) update(ctx context.Context, id string, p relayPaths) error {
	return c.call(ctx, http.MethodPatch, "/v1/bindings/"+id, p, http.StatusOK, nil)
}

// release ends binding id. One already gone is released.
func (c *relayClient) release(ctx context.Context, id string) error {
	err := c.call(ctx, http.MethodDelete, "/v1/bindings/"+id, nil, http.StatusNoContent, nil)
	if errors.Is(err, errRelayGone) {
		return nil
	}
	return err
}

// call sends one request and reads its answer into out. Errors name the
// operation and the status, never the paths or the token.
func (c *relayClient) call(ctx context.Context, method, path string, body any, want int, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = path
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return fmt.Errorf("pcscf: relay request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.RevealString())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL names a binding id at most, but keep errors plain
		}
		return fmt.Errorf("pcscf: relay %s: %w", method, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxRelayResponse+1))
	switch {
	case res.StatusCode == http.StatusConflict:
		return errRelayConflict
	case res.StatusCode == http.StatusNotFound:
		return errRelayGone
	case res.StatusCode == http.StatusBadRequest:
		return errRelayInvalid
	case res.StatusCode != want:
		return fmt.Errorf("pcscf: relay %s answered %s", method, strconv.Itoa(res.StatusCode))
	case err != nil:
		return fmt.Errorf("pcscf: relay %s: reading the answer: %w", method, err)
	case len(data) > maxRelayResponse:
		return fmt.Errorf("pcscf: relay %s: answer too large", method)
	case out == nil:
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("pcscf: relay %s: answer is not a binding", method)
	}
	return nil
}

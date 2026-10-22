package ftserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	secretkey "github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// ErrUnknownUser means a credential source has no FT credential for the user.
var ErrUnknownUser = errors.New("ftserver: no FT credential for the user")

// ErrBadCredentialRecord means the source answered but the user's credential
// cannot be used: a record for another realm or algorithm, without an IMPU or
// with a malformed HA1. It is a fault of that one subscriber's record, not of
// the source, so the client gets the same 401 as for an unknown user (a 503
// would tell such users apart) while the operator gets a metric and a log
// line.
var ErrBadCredentialRecord = errors.New("ftserver: the user's FT credential record is unusable")

// Credential is what a CredentialSource knows about one Digest user.
type Credential struct {
	// Secret verifies the user's Digest response.
	Secret digest.Secret
	// Owner is the identity uploads by this user belong to: the IMPU for a
	// subscriber. It is stored with each file and never logged unmasked.
	Owner string
}

// CredentialSource looks up the HTTP Digest credentials of the users who may
// upload (RCC.07 FT via HTTP: the content server authenticates the client).
// ft-server never learns more than a Secret: a source returns a password or
// an HA1 computed for alg. Implementations are safe for concurrent use.
type CredentialSource interface {
	// Lookup returns username's credential for alg. An error wrapping
	// ErrUnknownUser or ErrBadCredentialRecord is answered with the uniform
	// 401; any other error is a failure of the source and gets 503.
	Lookup(ctx context.Context, username string, alg digest.Algorithm) (Credential, error)
}

// StaticCredentials is a fixed set of users with passwords, each its own
// owner, for dev and test stacks (ft-server refuses it in staging and prod).
type StaticCredentials struct {
	users map[string]digest.Secret
}

// NewStaticCredentials returns a source for users, a map from user name to
// password.
func NewStaticCredentials(users map[string]secretkey.Key) *StaticCredentials {
	s := &StaticCredentials{users: make(map[string]digest.Secret, len(users))}
	for name, password := range users {
		s.users[name] = digest.Password(password.Reveal())
	}
	return s
}

// Lookup implements CredentialSource.
func (s *StaticCredentials) Lookup(_ context.Context, username string, _ digest.Algorithm) (Credential, error) {
	secret, ok := s.users[username]
	if !ok {
		return Credential{}, ErrUnknownUser
	}
	return Credential{Secret: secret, Owner: username}, nil
}

// maxHSSResponse bounds the HSS answer read; a credential is a few hundred
// bytes.
const maxHSSResponse = 16 << 10

// HSSCredentials looks credentials up in the HSS provisioning API (#12):
// GET {base}/v1/subscriptions/{impi}/ft-credential?algorithm=..., which
// returns the HA1 of the subscriber's FT credential for the FT realm and the
// public identity files are stored under. docs/api/hss.yaml is the contract.
// The Digest user name is the IMPI.
type HSSCredentials struct {
	base   *url.URL
	token  secretkey.Key
	realm  string
	client *http.Client
}

// NewHSSCredentials returns a source calling the HSS at base with the bearer
// token, expecting credentials for realm. timeout bounds each call and
// maxConns the connections to the HSS, which the server's lookup limit
// (Options.MaxConcurrentLookups) should match. dial opens its connections;
// in staging and prod it is a runtime.InternalDialer's, so that the token
// reaches only a private address whatever the HSS's name resolves to, and
// nil means the default dialer.
func NewHSSCredentials(base *url.URL, token secretkey.Key, realm string, timeout time.Duration, maxConns int, dial func(ctx context.Context, network, address string) (net.Conn, error)) *HSSCredentials {
	// A transport of its own: the default one has no connection limit and
	// is shared with whatever else uses it.
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: dial,
		// A DialContext of its own turns HTTP/2 off unless asked for; an
		// https HSS keeps it in every environment.
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     maxConns,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	return &HSSCredentials{
		base:  base,
		token: token,
		realm: realm,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// The token must not follow a redirect to another host.
			CheckRedirect: runtime.RefuseRedirects,
		},
	}
}

// hssCredential is the response body of the ft-credential operation.
type hssCredential struct {
	IMPI      string `json:"impi"`
	IMPU      string `json:"impu"`
	Realm     string `json:"realm"`
	Algorithm string `json:"algorithm"`
	HA1       string `json:"ha1"`
}

// Lookup implements CredentialSource.
func (h *HSSCredentials) Lookup(ctx context.Context, username string, alg digest.Algorithm) (Credential, error) {
	if username == "" || username == "." || username == ".." {
		// Not an IMPI, and a dot segment would change the request path.
		return Credential{}, ErrUnknownUser
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.credentialURL(username, alg), nil)
	if err != nil {
		return Credential{}, fmt.Errorf("ftserver: hss request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token.RevealString())
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("ftserver: hss: %w", redactURL(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHSSResponse+1))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Credential{}, ErrUnknownUser
	case resp.StatusCode != http.StatusOK:
		return Credential{}, fmt.Errorf("ftserver: hss answered %d", resp.StatusCode)
	case err != nil:
		return Credential{}, fmt.Errorf("ftserver: hss: reading the response: %w", err)
	case len(body) > maxHSSResponse:
		return Credential{}, fmt.Errorf("%w: hss response too large", ErrBadCredentialRecord)
	}
	return parseHSSCredential(body, username, h.realm, alg)
}

// credentialURL is the ft-credential URL for impi. The IMPI is escaped as
// one path segment; url.JoinPath is not used because it treats its
// arguments as already escaped.
func (h *HSSCredentials) credentialURL(impi string, alg digest.Algorithm) string {
	u := *h.base
	const tail = "/ft-credential"
	u.Path = strings.TrimSuffix(h.base.Path, "/") + "/v1/subscriptions/" + impi + tail
	u.RawPath = strings.TrimSuffix(h.base.EscapedPath(), "/") + "/v1/subscriptions/" + url.PathEscape(impi) + tail
	u.RawQuery = url.Values{"algorithm": {string(alg)}}.Encode()
	return u.String()
}

// parseHSSCredential checks an ft-credential response against the IMPI,
// realm and algorithm asked for. A realm or algorithm mismatch is an error,
// not a fallback: an HA1 for another realm or algorithm cannot verify
// anything.
//
// The IMPI must come back byte for byte. An HSS that matched the name
// loosely (say, the domain case-insensitively) would let a captured
// Authorization be replayed under a respelt user name, which keys a fresh
// nonce-count; such an answer is treated as an unknown user.
func parseHSSCredential(body []byte, impi, realm string, alg digest.Algorithm) (Credential, error) {
	var c hssCredential
	if err := json.Unmarshal(body, &c); err != nil {
		return Credential{}, fmt.Errorf("%w: hss response is not an ft-credential", ErrBadCredentialRecord)
	}
	switch {
	case c.IMPI != impi:
		return Credential{}, fmt.Errorf("%w: the hss answered for another impi", ErrUnknownUser)
	case c.Realm != realm:
		return Credential{}, fmt.Errorf("%w: credential for another realm", ErrBadCredentialRecord)
	case !strings.EqualFold(c.Algorithm, string(alg)):
		return Credential{}, fmt.Errorf("%w: credential for another algorithm", ErrBadCredentialRecord)
	case c.IMPU == "":
		return Credential{}, fmt.Errorf("%w: credential names no public identity", ErrBadCredentialRecord)
	}
	s, err := digest.HA1(alg, c.HA1)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %w", ErrBadCredentialRecord, err)
	}
	return Credential{Secret: s, Owner: c.IMPU}, nil
}

// redactURL drops the request URL from a client error: it carries the IMPI.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

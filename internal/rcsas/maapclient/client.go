// Package maapclient is rcs-as's client of maap's internal API, /v1/rcs/*
// (ADR 0009 §4, §12): admissions, delivery checks, and the delivery of
// subscribers' messages and notifications to chatbots. Each of the three
// kinds of call has its own timeout, cap on the calls in flight per task, and
// breaker, so that a slow or failing maap is answered for at once instead of
// stalling the subscriber's path, and a queue drain cannot starve admissions
// (§12). The caps and breakers belong to a *Client, so a task makes one and
// every caller shares it: two would double the caps and split the breakers.
//
// maap is outside the SIP trust domain (§1), so its answers are untrusted:
// they go through chatbot.DecodeEnvelope under chatbot.MaxAnswerBytes, which
// validates them, and their headers are bounded too. Every call fails
// closed: anything but a valid answer is [ErrUnavailable]. Neither a body
// nor the token reaches a log, and no error quotes either.
//
// A caller's deadline counts against the breaker only as a deadline: a
// context ended by cancel, as one from context.WithCancel or an
// AfterFunc(cancel) timer, reads as a caller that gave up.
package maapclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// ErrUnavailable is wrapped by the error of every call that got no valid
// answer from maap: a timeout, an open breaker, a full cap, a status the call
// does not expect (a 5xx above all), or an answer that does not decode. The
// caller holds or refuses as ADR 0009 §4 says; it never proceeds.
var ErrUnavailable = errors.New("maapclient: maap unavailable")

// The causes of ErrUnavailable that never reach maap.
var (
	ErrBreakerOpen = fmt.Errorf("%w: breaker open", ErrUnavailable)
	ErrCapFull     = fmt.Errorf("%w: too many calls in flight", ErrUnavailable)
)

// Metrics records counts and timings; *runtime.Metrics is one.
type Metrics interface {
	Count(name string, n int64)
	Timing(name string, d time.Duration)
}

// Config is what New needs. The caller reads it from rcs-as's settings.
type Config struct {
	// URL is maap's internal API: http or https, with no user, path, query
	// or fragment. Plain http needs a host runtime.IsPrivateHost accepts in
	// Namespace, the Cloud Map namespace (ADR 0007 §5).
	URL       *url.URL
	Namespace string
	// Token is rcs-as's bearer token for maap (ADR 0007 §3, ADR 0009 §7).
	Token secret.Key
	// Dev lifts ADR 0007 §5 for dev and test (RCS_ENV), where maap may be
	// on loopback or a compose name: plain http to any host, connections to
	// any address, and Transport. Its zero value keeps the rules of staging
	// and prod, where the default transport connects only to private
	// addresses (runtime.InternalDialer).
	Dev bool
	// Transport sends the requests, for tests; nil means the client's own.
	// It needs Dev, since it bypasses the dial and header rules.
	Transport http.RoundTripper
	// Metrics is required. Logger nil discards; Now nil is time.Now.
	Metrics Metrics
	Logger  *slog.Logger
	Now     func() time.Time
}

// Bounds of the client's own transport: the dial and TLS handshake, which
// a request's timeout does not reach once http.Transport works for its pool
// (the shortest call timeout), and an answer's headers, which
// chatbot.MaxAnswerBytes does not cover and Go would read up to 10 MiB of.
const (
	dialTimeout    = 2 * time.Second
	maxHeaderBytes = 16 << 10
)

// maxInFlight is each kind's cap on calls in flight per task (§12).
const maxInFlight = 64

// Client calls maap. Its methods are safe for concurrent use.
type Client struct {
	base    string
	token   secret.Key
	http    *http.Client
	metrics Metrics
	log     *slog.Logger
	now     func() time.Time

	admission, deliveryCheck, delivery *kind
}

// kind is one kind of call with its own bounds (ADR 0009 §12), and its own
// metrics (#674, #747): chatbot.<name>_unavailable (every call that ended
// unavailable, full caps and open breakers included), _cap_full,
// _breaker_opened, and the timing _latency of each call that reached maap.
type kind struct {
	name    string
	timeout time.Duration
	slots   chan struct{}
	breaker breaker
}

func newKind(name string, timeout time.Duration) *kind {
	return &kind{name: name, timeout: timeout, slots: make(chan struct{}, maxInFlight)}
}

func (k *kind) metric(suffix string) string { return "chatbot." + k.name + suffix }

// New returns a client of the maap that cfg names, or an error if cfg breaks
// a rule above.
func New(cfg Config) (*Client, error) {
	u := cfg.URL
	switch {
	case u == nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, errors.New("maapclient: the URL is not an http or https URL without a user, path, query or fragment")
	case !cfg.Dev && u.Scheme == "http" && !runtime.IsPrivateInternalURL(u, cfg.Namespace):
		return nil, errors.New("maapclient: the URL is plain http to a host that is not private (ADR 0007 §5)")
	case !cfg.Dev && cfg.Transport != nil:
		return nil, errors.New("maapclient: a Transport of the caller's needs Dev")
	case cfg.Token.IsZero():
		return nil, errors.New("maapclient: no token")
	case cfg.Metrics == nil:
		return nil, errors.New("maapclient: no metrics")
	}
	c := &Client{
		base:          strings.TrimSuffix(u.String(), "/"),
		token:         cfg.Token,
		metrics:       cfg.Metrics,
		log:           cfg.Logger,
		now:           cfg.Now,
		admission:     newKind("admission", 2*time.Second),
		deliveryCheck: newKind("delivery_check", 2*time.Second),
		// Above the webhook's 10 s, below RCSAS_DELIVERY_TIMEOUT (§12).
		delivery: newKind("delivery", 15*time.Second),
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	transport := cfg.Transport
	if transport == nil {
		dial := runtime.InternalDialer{Timeout: dialTimeout}.DialContext
		if cfg.Dev {
			dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
		}
		transport = &http.Transport{
			Proxy:                  nil,
			DialContext:            dial,
			TLSHandshakeTimeout:    dialTimeout,
			MaxResponseHeaderBytes: maxHeaderBytes,
			ForceAttemptHTTP2:      true,
			MaxIdleConnsPerHost:    3 * maxInFlight,
			IdleConnTimeout:        90 * time.Second,
		}
	}
	// The token must not follow a redirect (ADR 0007 §5).
	c.http = &http.Client{Transport: transport, CheckRedirect: runtime.RefuseRedirects}
	return c, nil
}

// Admit asks maap whether a subscriber's message or session may reach a
// chatbot (ADR 0009 §4, subscriber → chatbot step 3). With a nil error the
// answer is valid: admitted if its Reason is empty, its State telling whether
// the chatbot is suspended, else refused for Reason. An error wrapping
// ErrUnavailable means no answer, which rcs-as answers 500 with
// Retry-After: 5 (§12); any other error is an invalid a.
func (c *Client) Admit(ctx context.Context, a chatbot.Admission) (chatbot.AdmissionAnswer, error) {
	var answer chatbot.AdmissionAnswer
	_, err := c.call(ctx, c.admission, "/v1/rcs/admissions", a, &answer, nil)
	if err != nil {
		return chatbot.AdmissionAnswer{}, err
	}
	return answer, nil
}

// CheckDelivery asks maap whether a chatbot's message may be delivered now
// (ADR 0009 §4, chatbot → subscriber step 5). With a nil error the answer is
// valid: deliver only if *Deliver is true, else the message is undeliverable
// for Reason. An error wrapping ErrUnavailable means no answer, and the
// message is held; any other error is an invalid check.
func (c *Client) CheckDelivery(ctx context.Context, check chatbot.DeliveryCheck) (chatbot.DeliveryCheckAnswer, error) {
	var answer chatbot.DeliveryCheckAnswer
	_, err := c.call(ctx, c.deliveryCheck, "/v1/rcs/delivery-checks", check, &answer, nil)
	if err != nil {
		return chatbot.DeliveryCheckAnswer{}, err
	}
	return answer, nil
}

// Delivery is what maap answered a delivery (ADR 0009 §4, subscriber →
// chatbot step 5).
type Delivery int

// The answers to a delivery. The zero value is no answer, so that a result
// read without its error fails closed.
const (
	DeliveryUnavailable Delivery = iota
	// Delivered is a 200: the webhook took it, so it is dequeued.
	Delivered
	// DeliveryRetry is a 503 with a chatbot.DeliveryRefusal that asks for a
	// retry: the chatbot's webhook failed or is busy, so it is kept for retry
	// until its TTL.
	DeliveryRetry
	// Undeliverable is a 404 with a chatbot.DeliveryRefusal of an unknown or
	// suspended chatbot, or a blocked pair.
	Undeliverable
)

// DeliverMessage hands maap a subscriber's message to a chatbot. An error
// comes with DeliveryUnavailable: wrapping ErrUnavailable, no answer, and the
// message is kept for retry; otherwise an invalid m.
func (c *Client) DeliverMessage(ctx context.Context, m chatbot.SubscriberMessage) (Delivery, error) {
	return c.deliver(ctx, "/v1/rcs/messages", m, &chatbot.SubscriberMessageAnswer{})
}

// DeliverNotification hands maap a subscriber's notification about a
// chatbot's message, or one rcs-as generated, as DeliverMessage does.
func (c *Client) DeliverNotification(ctx context.Context, n chatbot.SubscriberNotification) (Delivery, error) {
	return c.deliver(ctx, "/v1/rcs/notifications", n, &chatbot.SubscriberNotificationAnswer{})
}

func (c *Client) deliver(ctx context.Context, path string, body, answer validator) (Delivery, error) {
	// A refusal is about one chatbot, which maap answered for: it is not a
	// failure, so one chatbot's failing webhook does not open the breaker for
	// every chatbot. A 404 or 503 without one is anything else's, and is.
	var refusal chatbot.DeliveryRefusal
	status, err := c.call(ctx, c.delivery, path, body, answer, &refusal)
	switch {
	case err != nil:
		return DeliveryUnavailable, err
	case status == http.StatusOK:
		return Delivered, nil
	case status == http.StatusServiceUnavailable:
		return DeliveryRetry, nil
	case status == http.StatusNotFound:
		return Undeliverable, nil
	}
	// call returns no other status without an error; were it to, hold.
	return DeliveryUnavailable, fmt.Errorf("%w: delivery status %d", ErrUnavailable, status)
}

type validator interface{ Validate() error }

// call posts body to path as a call of kind k, and returns the status of an
// answer: a 200 decoded into answer, or, given a refusal to decode into, a
// 404 or 503 that carries one for its status. Its errors name the kind and
// the cause, never a body.
func (c *Client) call(ctx context.Context, k *kind, path string, body, answer validator, refusal *chatbot.DeliveryRefusal) (int, error) {
	if err := body.Validate(); err != nil {
		return 0, fmt.Errorf("maapclient: %s request: %w", k.name, err)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("maapclient: %s request: %w", k.name, err)
	}
	if err := ctx.Err(); err != nil {
		// Nothing is sent, so this says nothing of maap: not counted.
		return 0, fmt.Errorf("%w: %s: %w", ErrUnavailable, k.name, err)
	}
	status, err := c.send(ctx, k, path, data, answer, refusal)
	if err != nil {
		c.metrics.Count(k.metric("_unavailable"), 1)
	}
	return status, err
}

func (c *Client) send(ctx context.Context, k *kind, path string, data []byte, answer validator, refusal *chatbot.DeliveryRefusal) (int, error) {
	select {
	case k.slots <- struct{}{}:
		defer func() { <-k.slots }()
	default:
		c.metrics.Count(k.metric("_cap_full"), 1)
		return 0, ErrCapFull
	}
	t, ok := k.breaker.allow(c.now())
	if !ok {
		return 0, ErrBreakerOpen
	}
	start := c.now()
	status, cause := c.post(ctx, k, path, data, answer, refusal)
	c.metrics.Timing(k.metric("_latency"), c.now().Sub(start))
	result := succeeded
	switch {
	case cause == "":
	case errors.Is(ctx.Err(), context.Canceled):
		// The caller gave up, which says nothing of maap. A deadline of the
		// caller's that passed first does count: maap did not answer in time.
		result = abandoned
	default:
		result = failed
	}
	switch k.breaker.done(c.now(), t, result) {
	case opened:
		// The cause holds a status or a field's name, never a value, and
		// tells a maap that is down from one whose answers rcs-as refuses.
		c.log.Warn("rcs-as: the maap breaker opened", slog.String("call", k.name), slog.String("cause", cause))
		c.metrics.Count(k.metric("_breaker_opened"), 1)
	case closed:
		c.log.Info("rcs-as: the maap breaker closed", slog.String("call", k.name))
	}
	if cause != "" {
		return 0, fmt.Errorf("%w: %s %s", ErrUnavailable, k.name, cause)
	}
	return status, nil
}

// post sends one request within k's timeout and reads its answer. It returns
// the status, or why there is no valid answer: "timeout", "cancelled", "no
// answer", "status N", or "answer refused: " and the decoder's reason.
func (c *Client) post(ctx context.Context, k *kind, path string, data []byte, answer validator, refusal *chatbot.DeliveryRefusal) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return 0, "request not built"
	}
	req.Header.Set("Authorization", "Bearer "+c.token.RevealString())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		// The error would name the URL; the context says enough.
		return 0, ended(ctx, "no answer")
	}
	defer res.Body.Close()
	status, into := res.StatusCode, answer
	switch {
	case status == http.StatusOK:
	case refusal != nil && (status == http.StatusNotFound || status == http.StatusServiceUnavailable):
		into = refusal
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, chatbot.MaxAnswerBytes))
		return 0, "status " + strconv.Itoa(status)
	}
	err = chatbot.DecodeEnvelope(res.Body, chatbot.MaxAnswerBytes, into)
	switch {
	case err != nil && (ctx.Err() != nil || !errors.Is(err, chatbot.ErrInvalidEnvelope) && !errors.Is(err, chatbot.ErrBodyTooLarge)):
		// A read error may name an address, and once the context ended a
		// body may read as cut short rather than fail: the context says it.
		return 0, ended(ctx, "answer not read")
	case err != nil:
		return 0, "answer refused: " + err.Error()
	case status != http.StatusOK && refusal.Undeliverable() != (status == http.StatusNotFound):
		return 0, "status " + strconv.Itoa(status) + " with another status's reason"
	}
	return status, ""
}

// ended names why ctx ended, or gives otherwise if it has not.
func ended(ctx context.Context, otherwise string) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "timeout"
	case ctx.Err() != nil:
		return "cancelled"
	}
	return otherwise
}

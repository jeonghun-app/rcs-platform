// Package maapclient is rcs-as's client of maap's internal API, /v1/rcs/*
// (ADR 0009 §4, §12): admissions, delivery checks, and the delivery of
// subscribers' messages and notifications to chatbots. Each of the three
// kinds of call has its own timeout, cap on the calls in flight per task, and
// breaker, so that a slow or failing maap is answered for at once instead of
// stalling the subscriber's path, and a queue drain cannot starve admissions
// (§12).
//
// maap is outside the SIP trust domain (§1), so its answers are untrusted:
// they go through chatbot.DecodeEnvelope under chatbot.MaxAnswerBytes, which
// validates them. Every call fails closed: anything but a valid answer is
// [ErrUnavailable]. Neither a body nor the token reaches a log, and no error
// quotes either.
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
	// or fragment.
	URL *url.URL
	// Token is rcs-as's bearer token for maap (ADR 0007 §3, ADR 0009 §7).
	Token secret.Key
	// Production applies ADR 0007 §5 as staging and prod must: plain http
	// only to a host runtime.IsPrivateHost accepts in Namespace, the Cloud
	// Map namespace, and, when Transport is nil, connections only to
	// private addresses (runtime.InternalDialer).
	Production bool
	Namespace  string
	// Transport sends the requests; nil means one of the client's own.
	Transport http.RoundTripper
	// Metrics is required. Logger nil discards; Now nil is time.Now.
	Metrics Metrics
	Logger  *slog.Logger
	Now     func() time.Time
}

// The metrics of ADR 0009 §12 and #674's operations follow-ups, which #684
// alarms on. Their unavailable counts include full caps and open breakers.
const (
	metricAdmissionUnavailable       = "chatbot.admission_unavailable"
	metricAdmissionLatency           = "chatbot.admission_latency"
	metricDeliveryCheckUnavailable   = "chatbot.delivery_check_unavailable"
	metricDeliveryCheckBreakerOpened = "chatbot.delivery_check_breaker_opened"
)

// dialTimeout bounds a connection's dial, which the request's own timeout
// does not reach once http.Transport dials for its pool; it is the shortest
// call timeout.
const dialTimeout = 2 * time.Second

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

// kind is one kind of call with its own bounds (ADR 0009 §12).
type kind struct {
	name    string
	timeout time.Duration
	slots   chan struct{}
	breaker breaker
	// Metrics this kind records, "" for none.
	unavailable, latency, opened string
}

// maxInFlight is each kind's cap on calls in flight per task (§12).
const maxInFlight = 64

func newKind(name string, timeout time.Duration) *kind {
	return &kind{name: name, timeout: timeout, slots: make(chan struct{}, maxInFlight)}
}

// New returns a client of the maap that cfg names, or an error if cfg breaks
// a rule above.
func New(cfg Config) (*Client, error) {
	u := cfg.URL
	switch {
	case u == nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, errors.New("maapclient: the URL is not an http or https URL without a user, path, query or fragment")
	case cfg.Production && u.Scheme == "http" && !runtime.IsPrivateHost(u.Hostname(), cfg.Namespace):
		return nil, errors.New("maapclient: the URL is plain http to a host that is not private (ADR 0007 §5)")
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
	c.admission.unavailable, c.admission.latency = metricAdmissionUnavailable, metricAdmissionLatency
	c.deliveryCheck.unavailable, c.deliveryCheck.opened = metricDeliveryCheckUnavailable, metricDeliveryCheckBreakerOpened
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	transport := cfg.Transport
	if transport == nil {
		dial := (&net.Dialer{Timeout: dialTimeout}).DialContext
		if cfg.Production {
			dial = runtime.InternalDialer{Timeout: dialTimeout}.DialContext
		}
		transport = &http.Transport{
			Proxy:               nil,
			DialContext:         dial,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 3 * maxInFlight,
			IdleConnTimeout:     90 * time.Second,
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
	_, err := c.call(ctx, c.admission, "/v1/rcs/admissions", a, &answer)
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
	_, err := c.call(ctx, c.deliveryCheck, "/v1/rcs/delivery-checks", check, &answer)
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
	// DeliveryRetry is a 503: the chatbot's webhook failed or is busy, so it
	// is kept for retry until its TTL.
	DeliveryRetry
	// Undeliverable is a 404: an unknown or suspended chatbot, or a blocked
	// pair.
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
	// A 503 or 404 is about one chatbot, which maap answered for: it is not a
	// failure, so one chatbot's failing webhook does not open the breaker for
	// every chatbot.
	status, err := c.call(ctx, c.delivery, path, body, answer, http.StatusServiceUnavailable, http.StatusNotFound)
	switch {
	case err != nil:
		return DeliveryUnavailable, err
	case status == http.StatusServiceUnavailable:
		return DeliveryRetry, nil
	case status == http.StatusNotFound:
		return Undeliverable, nil
	}
	return Delivered, nil
}

type validator interface{ Validate() error }

// call posts body to path as a call of kind k, and returns the status of an
// answer: a 200 decoded into answer, or one of also, whose body is not read
// as an answer. Its errors name the kind and the cause, never a body.
func (c *Client) call(ctx context.Context, k *kind, path string, body, answer validator, also ...int) (int, error) {
	if err := body.Validate(); err != nil {
		return 0, fmt.Errorf("maapclient: %s request: %w", k.name, err)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("maapclient: %s request: %w", k.name, err)
	}
	status, err := c.send(ctx, k, path, data, answer, also)
	if err != nil && k.unavailable != "" {
		c.metrics.Count(k.unavailable, 1)
	}
	return status, err
}

func (c *Client) send(ctx context.Context, k *kind, path string, data []byte, answer validator, also []int) (int, error) {
	select {
	case k.slots <- struct{}{}:
		defer func() { <-k.slots }()
	default:
		return 0, ErrCapFull
	}
	trial, ok := k.breaker.allow(c.now())
	if !ok {
		return 0, ErrBreakerOpen
	}
	start := c.now()
	status, cause := c.post(ctx, k, path, data, answer, also)
	if k.latency != "" {
		c.metrics.Timing(k.latency, c.now().Sub(start))
	}
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
	switch k.breaker.done(c.now(), trial, result) {
	case opened:
		c.log.Warn("rcs-as: the maap breaker opened", slog.String("call", k.name))
		if k.opened != "" {
			c.metrics.Count(k.opened, 1)
		}
	case closed:
		c.log.Info("rcs-as: the maap breaker closed", slog.String("call", k.name))
	}
	if cause != "" {
		return 0, fmt.Errorf("%w: %s %s", ErrUnavailable, k.name, cause)
	}
	return status, nil
}

// post sends one request within k's timeout and reads its answer. It returns
// the status, or why there is no valid answer.
func (c *Client) post(ctx context.Context, k *kind, path string, data []byte, answer validator, also []int) (int, string) {
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
		if ctx.Err() != nil {
			return 0, "timed out or cancelled"
		}
		return 0, "no answer"
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, chatbot.MaxAnswerBytes))
		for _, s := range also {
			if res.StatusCode == s {
				return s, ""
			}
		}
		return 0, "answered " + strconv.Itoa(res.StatusCode)
	}
	if err := chatbot.DecodeEnvelope(res.Body, chatbot.MaxAnswerBytes, answer); err != nil {
		if ctx.Err() != nil {
			return 0, "timed out or cancelled"
		}
		return 0, "answer refused: " + err.Error()
	}
	return http.StatusOK, ""
}

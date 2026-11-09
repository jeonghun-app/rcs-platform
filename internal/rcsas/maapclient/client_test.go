package maapclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

const (
	testBot   = "sip:mybot@botplatform.mnc001.mcc001.3gppnetwork.org"
	testSub   = "tel:+15550100001"
	testToken = "token-SENTINEL-4f1d"
)

func ptr[T any](v T) *T { return &v }

func admission() chatbot.Admission {
	return chatbot.Admission{Chatbot: testBot, Subscriber: testSub, Anonymous: ptr(false)}
}

func check() chatbot.DeliveryCheck {
	return chatbot.DeliveryCheck{Chatbot: testBot, Subscriber: testSub}
}

func message(body string) chatbot.SubscriberMessage {
	return chatbot.SubscriberMessage{Chatbot: testBot, Subscriber: testSub, Anonymous: ptr(true), MessageID: "m-1",
		ContentType: "text/plain;charset=utf-8", Body: &body, Dispositions: &chatbot.Dispositions{}, AcceptedAtMS: 1}
}

func notification() chatbot.SubscriberNotification {
	return chatbot.SubscriberNotification{Chatbot: testBot, Subscriber: testSub, Anonymous: ptr(false), MessageID: "m-2",
		Kind: imdn.DeliveryNotification, Status: imdn.Delivered}
}

// calls makes one call of each kind, delivery twice, with valid requests.
var calls = []struct {
	name, path string
	call       func(context.Context, *Client) error
}{
	{"admission", "/v1/rcs/admissions", func(ctx context.Context, c *Client) error { _, err := c.Admit(ctx, admission()); return err }},
	{"delivery_check", "/v1/rcs/delivery-checks", func(ctx context.Context, c *Client) error { _, err := c.CheckDelivery(ctx, check()); return err }},
	{"message", "/v1/rcs/messages", func(ctx context.Context, c *Client) error { _, err := c.DeliverMessage(ctx, message("hi")); return err }},
	{"notification", "/v1/rcs/notifications", func(ctx context.Context, c *Client) error {
		_, err := c.DeliverNotification(ctx, notification())
		return err
	}},
}

// positive answers a positive 200 to each call.
func positive(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/rcs/admissions":
		_, _ = io.WriteString(w, `{"state":"active"}`)
	case "/v1/rcs/delivery-checks":
		_, _ = io.WriteString(w, `{"deliver":true}`)
	default:
		_, _ = io.WriteString(w, `{}`)
	}
}

// newTest returns a client of a fake maap over real HTTP (TLS) that answers
// with handler, and the harness its logs, metrics and clock are in.
func newTest(t *testing.T, handler http.HandlerFunc) (*Client, *runtimetest.Harness) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A request's context ends with its connection only once its body
		// was read, and the slow handlers wait for that end.
		data, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(data))
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	h := runtimetest.New(t, "rcs-as")
	u, _ := url.Parse(srv.URL)
	c, err := New(Config{URL: u, Token: secret.NewString(testToken), Transport: srv.Client().Transport,
		Metrics: h.Runtime.Metrics, Logger: h.Runtime.Logger, Now: h.Now})
	if err != nil {
		t.Fatal(err)
	}
	return c, h
}

func TestEachCallPostsItsValidatedBodyWithTheTokenToItsPath(t *testing.T) {
	want := map[string]any{"/v1/rcs/admissions": admission(), "/v1/rcs/delivery-checks": check(),
		"/v1/rcs/messages": message("hi"), "/v1/rcs/notifications": notification()}
	var mu sync.Mutex
	got := map[string]any{}
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		v := reflect.New(reflect.TypeOf(want[r.URL.Path]))
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testToken ||
			r.Header.Get("Content-Type") != "application/json" || chatbot.DecodeEnvelope(r.Body, 1<<20, v.Interface()) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		got[r.URL.Path] = v.Elem().Interface()
		mu.Unlock()
		positive(w, r)
	})
	for _, k := range calls {
		if err := k.call(t.Context(), c); err != nil {
			t.Errorf("%s: %v", k.name, err)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("maap got %+v, want %+v", got, want)
	}
}

func TestPositiveAndNegativeAnswersAreToldApart(t *testing.T) {
	admit := func(ctx context.Context, c *Client) (string, error) {
		a, err := c.Admit(ctx, admission())
		return fmt.Sprintf("state=%s text=%s reason=%s", a.State, a.OutOfServiceText, a.Reason), err
	}
	checkDelivery := func(ctx context.Context, c *Client) (string, error) {
		a, err := c.CheckDelivery(ctx, check())
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("deliver=%v reason=%s", *a.Deliver, a.Reason), nil
	}
	deliver := func(ctx context.Context, c *Client) (string, error) {
		d, err := c.DeliverMessage(ctx, message("hi"))
		return fmt.Sprint(d), err
	}
	notify := func(ctx context.Context, c *Client) (string, error) {
		d, err := c.DeliverNotification(ctx, notification())
		return fmt.Sprint(d), err
	}
	for _, tc := range []struct {
		name   string
		status int
		answer string
		call   func(context.Context, *Client) (string, error)
		want   string
	}{
		{"admitted", 200, `{"state":"active"}`, admit, "state=active text= reason="},
		{"admitted suspended", 200, `{"state":"suspended","out_of_service_text":"Closed"}`, admit, "state=suspended text=Closed reason="},
		{"blocked", 200, `{"reason":"blocked"}`, admit, "state= text= reason=blocked"},
		{"over limit", 200, `{"reason":"over_limit"}`, admit, "state= text= reason=over_limit"},
		{"unknown chatbot", 200, `{"reason":"unknown"}`, admit, "state= text= reason=unknown"},
		{"deliver", 200, `{"deliver":true}`, checkDelivery, "deliver=true reason="},
		{"do not deliver", 200, `{"deliver":false,"reason":"suspended"}`, checkDelivery, "deliver=false reason=suspended"},
		{"message delivered", 200, `{}`, deliver, fmt.Sprint(Delivered)},
		{"message retry", 503, ``, deliver, fmt.Sprint(DeliveryRetry)},
		{"message undeliverable", 404, `{"error":"x"}`, deliver, fmt.Sprint(Undeliverable)},
		{"notification delivered", 200, `{}`, notify, fmt.Sprint(Delivered)},
		{"notification retry", 503, `{"error":"x"}`, notify, fmt.Sprint(DeliveryRetry)},
		{"notification undeliverable", 404, ``, notify, fmt.Sprint(Undeliverable)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.answer)
			})
			got, err := tc.call(t.Context(), c)
			if err != nil || got != tc.want {
				t.Errorf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestEveryOtherAnswerIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		only    string // one call's path, or "" for every call
	}{
		{"500", status(500, `{"state":"active"}`), ""},
		{"502", status(502, ``), ""},
		{"400", status(400, ``), ""},
		{"401", status(401, ``), ""},
		{"403", status(403, ``), ""},
		{"201", status(201, `{}`), ""},
		{"204", status(204, ``), ""},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				t.Error("the redirect was followed")
			}
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		}, ""},
		{"empty 200", status(200, ``), ""},
		{"not JSON", status(200, `state=active`), ""},
		{"an unknown field", status(200, `{"state":"active","deliver":true,"x":1}`), ""},
		{"trailing data", status(200, `{"state":"active"} {}`), ""},
		{"over MaxAnswerBytes", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat(" ", chatbot.MaxAnswerBytes))
			positive(w, r)
		}, ""},
		{"admission 503", status(503, `{"state":"active"}`), "/v1/rcs/admissions"},
		{"admission 404", status(404, `{"state":"active"}`), "/v1/rcs/admissions"},
		{"no state", status(200, `{}`), "/v1/rcs/admissions"},
		{"a state and a reason", status(200, `{"state":"active","reason":"blocked"}`), "/v1/rcs/admissions"},
		{"a state in another case", status(200, `{"state":"Active"}`), "/v1/rcs/admissions"},
		{"check 503", status(503, `{"deliver":true}`), "/v1/rcs/delivery-checks"},
		{"check 404", status(404, `{"deliver":true}`), "/v1/rcs/delivery-checks"},
		{"no deliver", status(200, `{}`), "/v1/rcs/delivery-checks"},
		{"deliver with a reason", status(200, `{"deliver":true,"reason":"blocked"}`), "/v1/rcs/delivery-checks"},
		{"an admission reason", status(200, `{"deliver":false,"reason":"over_limit"}`), "/v1/rcs/delivery-checks"},
		{"slow answer", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, ""},
		{"slow body", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"state":`)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}, ""},
	} {
		for _, k := range calls {
			if tc.only != "" && tc.only != k.path {
				continue
			}
			t.Run(tc.name+"/"+k.name, func(t *testing.T) {
				c, h := newTest(t, tc.handler)
				for _, kd := range []*kind{c.admission, c.deliveryCheck, c.delivery} {
					kd.timeout = 100 * time.Millisecond
				}
				if err := k.call(t.Context(), c); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("got %v, want ErrUnavailable", err)
				}
				for name, metric := range map[string]string{"admission": metricAdmissionUnavailable, "delivery_check": metricDeliveryCheckUnavailable} {
					if n, _ := h.Metric(metric); (n == 1) != (name == k.name) {
						t.Errorf("%s = %v", metric, n)
					}
				}
			})
		}
	}
}

func TestAnUnavailableCallReturnsNoPartOfAnAnswer(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/rcs/admissions":
			_, _ = io.WriteString(w, `{"state":"active","reason":"blocked"}`)
		case "/v1/rcs/delivery-checks":
			_, _ = io.WriteString(w, `{"deliver":true,"reason":"blocked"}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	if a, err := c.Admit(t.Context(), admission()); a != (chatbot.AdmissionAnswer{}) || err == nil {
		t.Errorf("admission: got %+v, %v", a, err)
	}
	if a, err := c.CheckDelivery(t.Context(), check()); a.Deliver != nil || err == nil {
		t.Errorf("delivery check: got %+v, %v", a, err)
	}
	if d, err := c.DeliverMessage(t.Context(), message("hi")); d != DeliveryUnavailable || err == nil {
		t.Errorf("delivery: got %v, %v", d, err)
	}
}

func status(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func TestTheBreakerOpensAfterFiveFailuresInARowAndThenTriesOneCall(t *testing.T) {
	var answer atomic.Int64 // the status of delivery checks
	answer.Store(500)
	var checks atomic.Int64
	arrived, release := make(chan struct{}), make(chan int)
	c, h := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/rcs/delivery-checks" {
			positive(w, r)
			return
		}
		checks.Add(1)
		code := int(answer.Load())
		if code == 0 { // hold until the test answers
			arrived <- struct{}{}
			code = <-release
		}
		w.WriteHeader(code)
		positive(w, r)
	})
	call := func() error { _, err := c.CheckDelivery(t.Context(), check()); return err }
	expect := func(step string, want error, wantChecks int64) {
		t.Helper()
		err := call()
		if want == nil && err != nil || want != nil && !errors.Is(err, want) || errors.Is(err, ErrBreakerOpen) != (want == ErrBreakerOpen) {
			t.Fatalf("%s: got %v, want %v", step, err, want)
		}
		if n := checks.Load(); n != wantChecks {
			t.Fatalf("%s: maap got %d checks, want %d", step, n, wantChecks)
		}
	}
	opened := func(want float64) {
		t.Helper()
		if n, _ := h.Metric(metricDeliveryCheckBreakerOpened); n != want {
			t.Fatalf("%s = %v, want %v", metricDeliveryCheckBreakerOpened, n, want)
		}
	}

	for i := range 4 {
		expect(fmt.Sprint("failure ", i+1), ErrUnavailable, int64(i+1))
	}
	answer.Store(200)
	expect("a success between", nil, 5)
	answer.Store(500)
	for i := range 5 {
		expect(fmt.Sprint("failure ", i+1, " in a row"), ErrUnavailable, int64(6+i))
	}
	opened(1)
	expect("open", ErrBreakerOpen, 10)
	for _, k := range calls {
		if k.name != "delivery_check" {
			if err := k.call(t.Context(), c); err != nil {
				t.Fatalf("%s while the check breaker is open: %v", k.name, err)
			}
		}
	}
	h.Advance(breakerOpenFor - time.Nanosecond)
	expect("open until 10 s", ErrBreakerOpen, 10)

	h.Advance(time.Nanosecond)
	answer.Store(0)
	trial := make(chan error)
	go func() { trial <- call() }()
	<-arrived
	expect("while the trial is in flight", ErrBreakerOpen, 11)
	release <- 500
	if err := <-trial; !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("the trial got %v", err)
	}
	opened(2) // the count is of every flush so far
	expect("open again", ErrBreakerOpen, 11)

	h.Advance(breakerOpenFor)
	answer.Store(200)
	expect("a successful trial", nil, 12)
	expect("closed", nil, 13)
	opened(2)
	if len(h.Logs("rcs-as: the maap breaker opened")) != 2 || len(h.Logs("rcs-as: the maap breaker closed")) != 1 {
		t.Errorf("logs: %s", h.Output())
	}
}

func TestOnlyACallerThatCancelsLeavesTheBreakerAlone(t *testing.T) {
	arrived := make(chan struct{}, 1)
	var hits atomic.Int64
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		arrived <- struct{}{}
		<-r.Context().Done()
	})
	for range 2 * breakerFailures {
		ctx, cancel := context.WithCancel(t.Context())
		go func() { <-arrived; cancel() }()
		if _, err := c.Admit(ctx, admission()); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrBreakerOpen) {
			t.Fatalf("got %v", err)
		}
	}
	for range breakerFailures {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		go func() { <-arrived }()
		_, err := c.Admit(ctx, admission())
		cancel()
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrBreakerOpen) {
			t.Fatalf("got %v", err)
		}
	}
	if _, err := c.Admit(t.Context(), admission()); !errors.Is(err, ErrBreakerOpen) || hits.Load() != 3*breakerFailures {
		t.Fatalf("after the caller's deadlines passed: %v, %d calls reached maap", err, hits.Load())
	}
}

func TestAFullCapRefusesOnlyItsKindOfCall(t *testing.T) {
	for _, full := range []struct {
		name  string
		paths []string
	}{
		{"admission", []string{"/v1/rcs/admissions"}},
		{"delivery_check", []string{"/v1/rcs/delivery-checks"}},
		{"delivery", []string{"/v1/rcs/messages", "/v1/rcs/notifications"}},
	} {
		t.Run(full.name, func(t *testing.T) {
			arrived, release := make(chan struct{}, maxInFlight), make(chan struct{})
			var holding atomic.Int64
			c, h := newTest(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == full.paths[0] && holding.Add(1) <= maxInFlight {
					arrived <- struct{}{}
					<-release
				}
				positive(w, r)
			})
			var held []func(context.Context, *Client) error
			for _, k := range calls {
				if slices.Contains(full.paths, k.path) {
					held = append(held, k.call)
				}
			}
			var wg sync.WaitGroup
			for range maxInFlight {
				wg.Go(func() {
					if err := held[0](context.Background(), c); err != nil {
						t.Errorf("a held call: %v", err)
					}
				})
			}
			for range maxInFlight {
				<-arrived
			}
			for _, k := range calls {
				err := k.call(t.Context(), c)
				if isHeld := slices.Contains(full.paths, k.path); isHeld && err != ErrCapFull || !isHeld && err != nil {
					t.Errorf("%s with %s's cap full: %v", k.name, full.name, err)
				}
			}
			close(release)
			wg.Wait()
			for _, call := range held {
				if err := call(t.Context(), c); err != nil {
					t.Errorf("after the cap was released: %v", err)
				}
			}
			for name, metric := range map[string]string{"admission": metricAdmissionUnavailable, "delivery_check": metricDeliveryCheckUnavailable} {
				if n, _ := h.Metric(metric); (n == 1) != (name == full.name) {
					t.Errorf("%s = %v", metric, n)
				}
			}
		})
	}
}

func TestTheLimitsAreADR0009s(t *testing.T) {
	c, _ := newTest(t, positive)
	for _, tc := range []struct {
		k       *kind
		timeout time.Duration
	}{{c.admission, 2 * time.Second}, {c.deliveryCheck, 2 * time.Second}, {c.delivery, 15 * time.Second}} {
		if tc.k.timeout != tc.timeout || cap(tc.k.slots) != 64 {
			t.Errorf("%s: timeout %v, cap %d", tc.k.name, tc.k.timeout, cap(tc.k.slots))
		}
	}
	if breakerFailures != 5 || breakerOpenFor != 10*time.Second {
		t.Errorf("breaker: %d failures, open %v", breakerFailures, breakerOpenFor)
	}
}

func TestAdmissionsAreTimed(t *testing.T) {
	var h *runtimetest.Harness
	c, h := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		h.Advance(30 * time.Millisecond)
		positive(w, r)
	})
	if _, err := c.Admit(t.Context(), admission()); err != nil {
		t.Fatal(err)
	}
	if got := h.MetricValues(metricAdmissionLatency); !reflect.DeepEqual(got, []float64{30}) {
		t.Errorf("%s = %v", metricAdmissionLatency, got)
	}
}

func TestAnInvalidRequestNeverReachesMaap(t *testing.T) {
	c, h := newTest(t, func(w http.ResponseWriter, r *http.Request) { t.Error("maap was called") })
	a := admission()
	a.Anonymous = nil
	if _, err := c.Admit(t.Context(), a); !errors.Is(err, chatbot.ErrInvalidEnvelope) || errors.Is(err, ErrUnavailable) {
		t.Errorf("got %v", err)
	}
	if _, ok := h.Metric(metricAdmissionUnavailable); ok {
		t.Errorf("an invalid request was counted as unavailable")
	}
}

func TestNoBodyTokenOrIdentityReachesALogOrAnError(t *testing.T) {
	const bodySentinel, answerSentinel = "BODY-SENTINEL-9c2e", "ANSWER-SENTINEL-51ab"
	c, h := newTest(t, status(200, `{"`+answerSentinel+`":"`+answerSentinel+`"}`))
	var errs []string
	for range breakerFailures + 1 {
		_, err := c.DeliverMessage(t.Context(), message(bodySentinel))
		errs = append(errs, err.Error())
		_, err = c.Admit(t.Context(), admission())
		errs = append(errs, err.Error())
	}
	h.Runtime.Metrics.Flush()
	if len(h.Logs("rcs-as: the maap breaker opened")) == 0 {
		t.Fatal("nothing was logged, so the test shows nothing")
	}
	all := h.Output() + strings.Join(errs, "\n")
	for _, s := range []string{bodySentinel, answerSentinel, testToken, testSub, testBot} {
		if strings.Contains(all, s) {
			t.Errorf("%q reached a log or an error:\n%s", s, all)
		}
	}
}

func TestTheURLFollowsADR0007(t *testing.T) {
	for _, tc := range []struct {
		url        string
		production bool
		ok         bool
	}{
		{"https://maap.example.com", true, true},
		{"https://maap.example.com:8443/", true, true},
		{"http://10.0.3.4:8081", true, true},
		{"http://[fd00::4]:8081", true, true},
		{"http://maap.rcs.local:8081", true, true},
		{"http://maap.example.com", true, false},
		{"http://127.0.0.1:8081", true, false},
		{"http://169.254.169.254", true, false},
		{"http://maap.example.com", false, true},
		{"http://127.0.0.1:8081", false, true},
		{"ftp://maap.rcs.local", false, false},
		{"https://user:pw@maap.rcs.local", false, false},
		{"https://maap.rcs.local/v1", false, false},
		{"https://maap.rcs.local?a=b", false, false},
		{"https://maap.rcs.local?", false, false},
		{"https://maap.rcs.local#f", false, false},
		{"https:maap.rcs.local", false, false},
		{"", false, false},
	} {
		u, _ := url.Parse(tc.url)
		h := runtimetest.New(t, "rcs-as")
		_, err := New(Config{URL: u, Production: tc.production, Namespace: "rcs.local", Token: secret.NewString("t"), Metrics: h.Runtime.Metrics})
		if (err == nil) != tc.ok {
			t.Errorf("%q production=%v: %v", tc.url, tc.production, err)
		}
	}
	h := runtimetest.New(t, "rcs-as")
	u, _ := url.Parse("https://maap.rcs.local")
	if _, err := New(Config{URL: u, Metrics: h.Runtime.Metrics}); err == nil {
		t.Error("no token was taken")
	}
	if _, err := New(Config{URL: u, Token: secret.NewString("t")}); err == nil {
		t.Error("no metrics were taken")
	}
}

func TestInProductionTheDefaultTransportDialsOnlyPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(positive))
	defer srv.Close()
	u, _ := url.Parse("https://maap.rcs.local")
	for _, production := range []bool{true, false} {
		h := runtimetest.New(t, "rcs-as")
		c, err := New(Config{URL: u, Production: production, Token: secret.NewString(testToken), Metrics: h.Runtime.Metrics})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := c.http.Transport.(*http.Transport).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
		if conn != nil {
			conn.Close()
		}
		if errors.Is(err, runtime.ErrAddressNotPrivate) != production {
			t.Errorf("production=%v: dialling loopback: %v", production, err)
		}
	}
}

func TestOnlyTheTrialDecidesAnOpenBreaker(t *testing.T) {
	var b breaker
	now := runtimetest.Start
	early, _ := b.allow(now) // in flight when the breaker opens
	for range breakerFailures {
		trial, _ := b.allow(now)
		b.done(now, trial, failed)
	}
	if b.done(now, early, succeeded) != unchanged {
		t.Error("a call from before the breaker opened closed it")
	}
	now = now.Add(breakerOpenFor)
	if trial, ok := b.allow(now); !trial || !ok || b.done(now, trial, abandoned) != unchanged {
		t.Fatal("no trial, or an abandoned one decided")
	}
	if trial, ok := b.allow(now); !trial || !ok || b.done(now, trial, succeeded) != closed {
		t.Error("the call after an abandoned trial was not the next trial")
	}
}

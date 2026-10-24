// Command rcs-bridge lets an application send and receive RCS standalone
// messages through the platform over HTTP and a WebSocket, without speaking
// SIP itself (#658). docs/rcs-bridge.md has the API and how to run it on
// the local compose stack (make bridge-up).
//
// Settings come from the environment:
//
//	RCS_BRIDGE_TOKEN          the bearer token every request needs; required, 32 bytes or more
//	RCS_BRIDGE_ADDR           listen address, 127.0.0.1:8720 (the compose service sets :8720)
//	RCS_BRIDGE_IMPI_KEY       keys the IMPIs made from endpoint names; required, 32 bytes or more
//	RCS_BRIDGE_HSS_URL        hss's provisioning API, http://hss:8081
//	RCS_BRIDGE_HSS_TOKEN      an operator token of hss (HSS_ADMIN_TOKEN); required
//	RCS_BRIDGE_PCSCF          pcscf's client listener, pcscf:5060, plain TCP
//	RCS_BRIDGE_MAX_ENDPOINTS  endpoints online at once, 64
//	RCS_IMS_DOMAIN            the home network domain; required
//	RCS_PII_HMAC_KEY          keys the log hints of identifiers (internal/pii)
//	RCS_LOG_LEVEL             debug, info, warn or error; info
//
// rcs-bridge -healthcheck asks the running bridge's /healthz on
// RCS_BRIDGE_ADDR, with the token, and exits 0 if it answers 200: the
// container's health check, the image having no shell or curl.
//
// It is a development tool for the local stack, not a platform service. It
// speaks plain HTTP and holds hss's operator token, so it must not be
// reachable beyond the host's loopback, which is why it listens there by
// default. Nothing it logs carries a token, a key or a message body.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/buildinfo"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/bridge"
)

// Exit statuses.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// minTokenLength is the shortest token taken: 256 bits in hex is 64, and
// anything below 32 bytes is too easy to guess for an API that registers
// subscribers.
const minTokenLength = 32

// httpTimeouts are the HTTP server's; a variable for the test that a
// connection without the token does not stay.
var httpTimeouts = struct{ read, write, idle time.Duration }{10 * time.Second, 45 * time.Second, 60 * time.Second}

// At exit, httpShutdownTimeout bounds the wait for requests in flight and
// shutdownTimeout the unregistrations after it; both together stay under
// compose's stop grace (25 s).
const (
	httpShutdownTimeout = 5 * time.Second
	shutdownTimeout     = 15 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

// config is the settings read from the environment.
type config struct {
	token, hssToken     secret.Key
	impiKey             secret.Key
	addr, hssURL, pcscf string
	domain              string
	maxEndpoints        int
	piiKey              []byte
	level               slog.Level
}

func readConfig(lookup func(string) (string, bool)) (config, error) {
	get := func(name, def string) string {
		if v, ok := lookup(name); ok && v != "" {
			return v
		}
		return def
	}
	c := config{
		addr:   get("RCS_BRIDGE_ADDR", "127.0.0.1:8720"),
		hssURL: get("RCS_BRIDGE_HSS_URL", "http://hss:8081"),
		pcscf:  get("RCS_BRIDGE_PCSCF", "pcscf:5060"),
		domain: get("RCS_IMS_DOMAIN", ""),
	}
	var errs []error
	token := get("RCS_BRIDGE_TOKEN", "")
	switch {
	case token == "":
		errs = append(errs, errors.New("RCS_BRIDGE_TOKEN is required"))
	case len(token) < minTokenLength:
		errs = append(errs, fmt.Errorf("RCS_BRIDGE_TOKEN is shorter than %d bytes", minTokenLength))
	}
	c.token = secret.NewString(token)
	hssToken := get("RCS_BRIDGE_HSS_TOKEN", "")
	if hssToken == "" {
		errs = append(errs, errors.New("RCS_BRIDGE_HSS_TOKEN is required"))
	}
	c.hssToken = secret.NewString(hssToken)
	// Kept apart from the token: it must stay the same across restarts,
	// so that a name finds its subscription again, while the token may
	// change.
	impiKey := get("RCS_BRIDGE_IMPI_KEY", "")
	switch {
	case impiKey == "":
		errs = append(errs, errors.New("RCS_BRIDGE_IMPI_KEY is required"))
	case len(impiKey) < minTokenLength:
		errs = append(errs, fmt.Errorf("RCS_BRIDGE_IMPI_KEY is shorter than %d bytes", minTokenLength))
	}
	c.impiKey = secret.NewString(impiKey)
	if c.domain == "" {
		errs = append(errs, errors.New("RCS_IMS_DOMAIN is required"))
	}
	if _, _, err := net.SplitHostPort(c.addr); err != nil {
		errs = append(errs, errors.New("RCS_BRIDGE_ADDR is not host:port"))
	}
	n, err := strconv.Atoi(get("RCS_BRIDGE_MAX_ENDPOINTS", strconv.Itoa(bridge.DefaultMaxEndpoints)))
	if err != nil || n < 1 || n > 1000 {
		errs = append(errs, errors.New("RCS_BRIDGE_MAX_ENDPOINTS is not 1 to 1000"))
	}
	c.maxEndpoints = n
	if key := get("RCS_PII_HMAC_KEY", ""); key != "" {
		if len(key) < 32 {
			errs = append(errs, errors.New("RCS_PII_HMAC_KEY is shorter than 32 bytes"))
		}
		c.piiKey = []byte(key)
	}
	switch get("RCS_LOG_LEVEL", "info") {
	case "debug":
		c.level = slog.LevelDebug
	case "info":
		c.level = slog.LevelInfo
	case "warn":
		c.level = slog.LevelWarn
	case "error":
		c.level = slog.LevelError
	default:
		errs = append(errs, errors.New("RCS_LOG_LEVEL is not one of debug, info, warn, error"))
	}
	return c, errors.Join(errs...)
}

func run(ctx context.Context, args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rcs-bridge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	health := fs.Bool("healthcheck", false, "ask the running bridge's /healthz and exit 0 if it answers 200")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	c, err := readConfig(lookup)
	if err != nil {
		fmt.Fprintf(stderr, "rcs-bridge: %v\n", err)
		return exitUsage
	}
	if *health {
		return healthcheck(ctx, c, stderr)
	}
	pii.SetDefault(pii.NewRedactor(c.piiKey))
	log := runtime.NewLogger(stdout, "rcs-bridge", buildinfo.Version, c.level)
	if c.piiKey == nil {
		log.Warn("RCS_PII_HMAC_KEY is unset: log hints would show the last two characters of each identifier")
	}
	hss, err := bridge.NewHSS(bridge.HSSConfig{URL: c.hssURL, Token: c.hssToken, IMPIKey: c.impiKey, Domain: c.domain})
	if err != nil {
		fmt.Fprintf(stderr, "rcs-bridge: %v\n", err)
		return exitUsage
	}
	sipNet, err := bridge.NewSIP(bridge.SIPConfig{Proxy: c.pcscf, Domain: c.domain})
	if err != nil {
		fmt.Fprintf(stderr, "rcs-bridge: %v\n", err)
		return exitUsage
	}
	b, err := bridge.New(bridge.Config{
		Domain: c.domain, Provisioner: hss, SIP: sipNet, Token: c.token,
		MaxEndpoints: c.maxEndpoints, Logger: log,
	})
	if err != nil {
		fmt.Fprintf(stderr, "rcs-bridge: %v\n", err)
		return exitUsage
	}
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		log.Error("listening failed", slog.String("addr", c.addr))
		return exitFailed
	}
	srv := &http.Server{
		Handler: b.Handler(),
		// The event stream outlives these: websocket.Upgrade clears the
		// connection's deadlines once it has taken it over. They bound the
		// rest, so that a connection that sends nothing, or keeps an idle
		// keep-alive after a 401, does not hold its descriptor for ever.
		// The write timeout is above the bridge's own bound of a request's
		// SIP or hss work (bridge.DefaultOpTimeout, 30 s).
		ReadHeaderTimeout: httpTimeouts.read,
		ReadTimeout:       httpTimeouts.read,
		WriteTimeout:      httpTimeouts.write,
		IdleTimeout:       httpTimeouts.idle,
		ErrorLog:          runtime.HTTPErrorLog(log),
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("listening", slog.String("addr", ln.Addr().String()))
	select {
	case <-ctx.Done():
	case err := <-served:
		log.Error("the server stopped", slog.String("reason", err.Error()))
		return exitFailed
	}
	log.Info("shutting down")
	// Requests in flight get a moment to finish; the event streams are
	// hijacked connections, which Shutdown does not wait for. The
	// bridge's Close then ends them, cuts short what is still running and
	// removes the registrations, within a deadline of its own.
	hctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	_ = srv.Shutdown(hctx)
	cancel()
	bctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	b.Close(bctx)
	return exitOK
}

// healthcheck asks the bridge on c.addr for /healthz.
func healthcheck(ctx context.Context, c config, stderr io.Writer) int {
	_, port, _ := net.SplitHostPort(c.addr)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if err != nil {
		return exitFailed
	}
	req.Header.Set("Authorization", "Bearer "+c.token.RevealString())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "rcs-bridge: healthcheck: no answer")
		return exitFailed
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "rcs-bridge: healthcheck: answered %d\n", res.StatusCode)
		return exitFailed
	}
	return exitOK
}

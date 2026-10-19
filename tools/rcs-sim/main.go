// Command rcs-sim simulates an RCS client against a running stack for
// end-to-end tests: file transfer over HTTP against ft-server, and chat over
// MSRP through msrp-relay with delivery and display notifications. This is
// step 1 (#62). It has no SIP yet, so the simulator also plays pcscf
// toward the relay's control API and stands in for rcs-as behind it; step 2
// takes those parts back from SIP.
//
// Usage:
//
//	rcs-sim [flags] scenario...   (or "all"; -list names them)
//
// Each step prints one JSON line to standard output. The exit status is 0
// when every step succeeded, 1 when one failed, and 2 for a usage error.
// Secrets come only from the environment: RCS_SIM_FT_PASSWORD and
// RCS_SIM_RELAY_TOKEN. Neither is ever printed, and neither are session ids.
// docs/rcs-sim.md has the details.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/buildinfo"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
)

// Exit statuses.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// The default addresses are the reserved fictional numbers of
// .github/allowed-test-identifiers.txt in the MCC 001 test network.
const (
	defaultSelf = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	defaultPeer = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

// run is main without the process, for tests.
func run(ctx context.Context, args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rcs-sim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		list          = fs.Bool("list", false, "list the scenarios and exit")
		version       = fs.Bool("version", false, "print the version and exit")
		uploadURL     = fs.String("ft-upload-url", "", "ft-server upload URI (ftHTTPCSURI)")
		ftUser        = fs.String("ft-user", envOr(lookup, "RCS_SIM_FT_USER", ""), "FT user name (ftHTTPCSUser); also RCS_SIM_FT_USER")
		fileSize      = fs.Int("file-size", 256<<10, "size of the file the ft scenario sends")
		resumeSize    = fs.Int("resume-size", 12<<20, "size of the file ft-resume sends; must exceed FT_PART_SIZE")
		control       = fs.String("relay-control", "", "msrp-relay control API base URL")
		coreListen    = fs.String("core-listen", "127.0.0.1:0", "where the rcs-as stand-in listens")
		coreAdvertise = fs.String("core-advertise", "", "host the relay connects to for the stand-in (default: the listener's)")
		keepAlive     = fs.Duration("msrp-keepalive", msrp.DefaultKeepAliveInterval, "MSRP keep-alive interval of both ends")
		idleWait      = fs.Duration("idle-wait", 0, "stay quiet this long in chat scenarios to see keep-alives (0 skips)")
		self          = fs.String("self", defaultSelf, "the simulated client's address")
		peer          = fs.String("peer", defaultPeer, "the far end's address")
		stepTimeout   = fs.Duration("step-timeout", 30*time.Second, "bound on each step")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	switch {
	case *version:
		fmt.Fprintln(stdout, buildinfo.String("rcs-sim"))
		return exitOK
	case *list:
		for _, n := range scenario.Names() {
			fmt.Fprintln(stdout, n)
		}
		return exitOK
	case fs.NArg() == 0:
		fmt.Fprintln(stderr, "rcs-sim: name at least one scenario, or all; -list shows them")
		return exitUsage
	}

	usage := func(msg string) int {
		fmt.Fprintln(stderr, "rcs-sim: "+msg)
		return exitUsage
	}
	// Redirects are never followed: an upload must not be replayed
	// elsewhere, and ADR 0007 forbids it for the internal control API.
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cfg := scenario.Config{
		FileSize:      *fileSize,
		ResumeSize:    *resumeSize,
		CoreListen:    *coreListen,
		CoreAdvertise: *coreAdvertise,
		MSRP:          msrp.Config{KeepAliveInterval: *keepAlive},
		IdleWait:      *idleWait,
		StepTimeout:   *stepTimeout,
	}
	var err error
	if cfg.Self, err = cpim.ParseAddress("<" + *self + ">"); err != nil {
		return usage("-self is not a SIP or tel URI")
	}
	if cfg.Peer, err = cpim.ParseAddress("<" + *peer + ">"); err != nil {
		return usage("-peer is not a SIP or tel URI")
	}
	if *fileSize < 1 || *resumeSize < 1 {
		return usage("-file-size and -resume-size must be positive")
	}
	if *uploadURL != "" {
		u, err := absolute(*uploadURL)
		if err != nil {
			return usage("-ft-upload-url: " + err.Error())
		}
		password, _ := lookup("RCS_SIM_FT_PASSWORD")
		if *ftUser == "" || password == "" {
			return usage("file transfer needs -ft-user (or RCS_SIM_FT_USER) and RCS_SIM_FT_PASSWORD")
		}
		cfg.FT = &ft.Client{HTTP: httpClient, UploadURL: u, User: *ftUser, Password: ft.NewSecret(password)}
	}
	if *control != "" {
		u, err := absolute(*control)
		if err != nil {
			return usage("-relay-control: " + err.Error())
		}
		token, _ := lookup("RCS_SIM_RELAY_TOKEN")
		if token == "" {
			return usage("the relay control API needs RCS_SIM_RELAY_TOKEN")
		}
		cfg.Control = &anchor.Control{HTTP: httpClient, URL: u, Token: anchor.NewToken(token)}
	}

	enc := json.NewEncoder(stdout)
	ok, err := scenario.Run(ctx, cfg, fs.Args(), func(r scenario.Result) { _ = enc.Encode(r) })
	if err != nil {
		return usage(err.Error())
	}
	if !ok {
		return exitFailed
	}
	return exitOK
}

func envOr(lookup func(string) (string, bool), name, def string) string {
	if v, ok := lookup(name); ok && v != "" {
		return v
	}
	return def
}

// absolute parses an http or https URL. The error never repeats it.
func absolute(v string) (*url.URL, error) {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("not an absolute http or https URL without user info")
	}
	return u, nil
}

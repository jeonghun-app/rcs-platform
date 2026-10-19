// Command stack-init prepares the local docker compose stack
// (deploy/docker-compose.yml, docs/local-stack.md).
//
//	stack-init tables   create the DynamoDB tables and the S3 bucket
//	stack-init seed     provision the test subscriber in hss and acs
//
// Both are idempotent: what exists is left as it is, so `make up` can run
// them again on a stack that is already up. It is a development tool. In
// AWS the tables and the bucket come from CloudFormation (#56), and
// subscribers from the operator and acs.
//
// Settings come from the environment, under the names the services
// themselves read where there is one (HSS_SUBSCRIBERS_TABLE, FT_S3_BUCKET,
// ...), so the compose file states each value once. Nothing secret is
// printed: tokens are sent as bearer tokens and never echoed.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Exit statuses.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// timeout bounds a whole run: the stores and services it waits for are on
// the same host, and compose restarts nothing that fails.
const timeout = 2 * time.Minute

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: stack-init tables | seed")
		return exitUsage
	}
	env := environment{lookup: lookup}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var err error
	switch args[0] {
	case "tables":
		var c tablesConfig
		if c, err = readTablesConfig(env); err == nil {
			err = createTables(ctx, c, stdout)
		}
	case "seed":
		var c seedConfig
		if c, err = readSeedConfig(env); err == nil {
			err = seed(ctx, c, stdout)
		}
	default:
		fmt.Fprintln(stderr, "usage: stack-init tables | seed")
		return exitUsage
	}
	var ce *configError
	switch {
	case errors.As(err, &ce):
		fmt.Fprintf(stderr, "stack-init %s: %v\n", args[0], err)
		return exitUsage
	case err != nil:
		fmt.Fprintf(stderr, "stack-init %s: %v\n", args[0], err)
		return exitFailed
	}
	return exitOK
}

// environment reads settings, with defaults.
type environment struct {
	lookup func(string) (string, bool)
}

func (e environment) get(name, def string) string {
	if v, ok := e.lookup(name); ok && v != "" {
		return v
	}
	return def
}

// configError is a missing or unusable setting.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

func (e environment) required(name string) (string, error) {
	if v := e.get(name, ""); v != "" {
		return v, nil
	}
	return "", &configError{msg: name + " is required"}
}

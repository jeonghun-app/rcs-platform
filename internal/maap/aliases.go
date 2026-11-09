package maap

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// aliasIDRandom is an alias ID's randomness: 128 bits (ADR 0009 §10).
const aliasIDRandom = 16

var aliasEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// errMalformedAlias refuses an alias ID not in its one form, which #683
// and #712 answer 400. Its text names the rule, never the value, and
// nothing logs the value: pii.Redact masks an ID written in one case only
// (#721 security review), so a value in mixed case is never folded and
// passed on either.
var errMalformedAlias = errors.New("maap: not an alias ID: 26 characters of lower-case base32")

// aliases maps subscribers to what chatbots learn of them and back (ADR
// 0009 §10, U1), for #683's admissions and sends. It records an alias's
// use at most once per useInterval per task, as the authenticator does a
// credential's.
type aliases struct {
	subs store.Subscribers
	// host is MAAP_ALIAS_HOST, in lower case.
	host string
	// random is crypto/rand.Reader but in tests.
	random io.Reader
	now    func() time.Time
	log    *slog.Logger

	mu sync.Mutex
	// used is when this task last wrote, or tried to write, each alias's
	// use, by chatbot and alias ID: one entry per alias used in the last
	// useInterval, once swept.
	used  map[[2]string]time.Time
	swept time.Time
	// warned is when a failed write was last logged; quiet counts the
	// failures since that were not.
	warned time.Time
	quiet  int
	// writes are the use writes in progress, which #683 waits for at
	// shutdown.
	writes sync.WaitGroup
}

func newAliases(subs store.Subscribers, host string, random io.Reader, now func() time.Time, log *slog.Logger) *aliases {
	return &aliases{subs: subs, host: host, random: random, now: now, log: log, used: map[[2]string]time.Time{}}
}

// uri is the alias URI of an alias ID (RCC.07 v13.0 §2.5.4.2).
func (a *aliases) uri(aliasID string) string { return "sip:" + aliasID + "@" + a.host + ";user=rcstk" }

// identifier returns what chatbot c learns of the subscriber, a key as
// store.ValidSubscriber has it, in a conversation: the MSISDN as its tel
// URI with the MSISDN permission, unless the client asked for anonymity
// (§3.6.5.1); otherwise the alias URI of that kind of conversation, which
// is stored if there is none live.
func (a *aliases) identifier(ctx context.Context, c store.Chatbot, subscriber string, anonymous bool) (string, error) {
	if !store.ValidSubscriber(subscriber) {
		return "", fmt.Errorf("%w: not a subscriber's tel URI", store.ErrInvalid)
	}
	if c.Permissions.MSISDN && !anonymous {
		return subscriber, nil
	}
	random := make([]byte, aliasIDRandom)
	if _, err := io.ReadFull(a.random, random); err != nil {
		return "", fmt.Errorf("maap: drawing an alias ID: %w", err)
	}
	now := a.now()
	id := strings.ToLower(aliasEncoding.EncodeToString(random))
	al, err := a.subs.Alias(ctx, store.Alias{ID: id, Chatbot: c.ID, Subscriber: subscriber, Anonymous: anonymous, Created: now})
	if err != nil {
		return "", err
	}
	a.recordUse(ctx, al, now, al.ID == id)
	return a.uri(al.ID), nil
}

// resolve returns the subscriber and anonymity of the chatbot's alias with
// the ID: errMalformedAlias for an ID not in its form, which is never
// read; store.ErrNotFound for none, as for another chatbot's or one
// expired.
func (a *aliases) resolve(ctx context.Context, chatbotID, aliasID string) (store.Alias, error) {
	if !store.ValidAliasID(aliasID) {
		return store.Alias{}, errMalformedAlias
	}
	now := a.now()
	al, err := a.subs.Resolve(ctx, chatbotID, aliasID, now)
	if err != nil {
		return store.Alias{}, err
	}
	a.recordUse(ctx, al, now, false)
	return al, nil
}

// recordUse writes al's use at now, off the request's path, if this task
// has not written or tried to in the last useInterval; stored says the
// alias was stored at now, which is its use already. A write that failed
// waits for the next hour.
func (a *aliases) recordUse(ctx context.Context, al store.Alias, now time.Time, stored bool) {
	k := [2]string{al.Chatbot, al.ID}
	a.mu.Lock()
	if last, ok := a.used[k]; ok && now.Sub(last) < useInterval {
		a.mu.Unlock()
		return
	}
	if now.Sub(a.swept) >= cacheTTL && len(a.used) >= sweepAt {
		a.swept = now
		for k, t := range a.used {
			if now.Sub(t) >= useInterval {
				delete(a.used, k)
			}
		}
	}
	a.used[k] = now
	a.mu.Unlock()
	if stored {
		return
	}
	a.writes.Add(1)
	go func() {
		defer a.writes.Done()
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
		if err := a.subs.Used(wctx, al, now); err != nil {
			a.warn(now, al, err)
		}
	}()
}

// warn logs a failed use write, at most once per warnEvery, with how many
// it left out since the last line. The alias goes through pii.Identity
// only (ADR 0009 §10).
func (a *aliases) warn(now time.Time, al store.Alias, err error) {
	a.mu.Lock()
	if !a.warned.IsZero() && now.Sub(a.warned) < warnEvery {
		a.quiet++
		a.mu.Unlock()
		return
	}
	quiet := a.quiet
	a.warned, a.quiet = now, 0
	a.mu.Unlock()
	a.log.Warn("recording an alias's use failed", slog.String("chatbot", al.Chatbot),
		pii.Identity("alias", a.uri(al.ID)), slog.String("error", err.Error()), slog.Int("not_logged_since", quiet))
}

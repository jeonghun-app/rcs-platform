package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/url"
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// AuditChanges returns what an audit line says of a change from before to
// after (ADR 0009 §7): a group per changed field, named by its JSON path
// (webhook.url, limits.sends_per_day), with a before and an after. No value
// is written (§10): a field shows its length in bytes and the first 8 hex
// digits of its SHA-256, which tells two values apart; the webhook URL
// shows its host only, since its path may hold the chatbot's secret; the
// URI goes through pii.URI. A field not set has length 0. Registering is a
// change from the zero Chatbot. Walking the encoded record, rather than a
// list of fields, keeps a field added later from being missed.
func AuditChanges(before, after Chatbot) []slog.Attr {
	b, a := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	flatten(b, "", before)
	flatten(a, "", after)
	var names []string
	for _, m := range []map[string]json.RawMessage{b, a} {
		for name := range m {
			if !slices.Contains(names, name) && string(b[name]) != string(a[name]) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	attrs := make([]slog.Attr, 0, len(names))
	for _, name := range names {
		attrs = append(attrs, slog.Group(name, describe("before", name, b[name]), describe("after", name, a[name])))
	}
	return attrs
}

// flatten stores in out each value of v's JSON form that is not an object,
// keyed by its path.
func flatten(out map[string]json.RawMessage, prefix string, v any) {
	data, _ := json.Marshal(v)
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		out[prefix[:len(prefix)-1]] = data
		return
	}
	for name, raw := range fields {
		flatten(out, prefix+name+".", raw)
	}
}

func describe(key, name string, raw json.RawMessage) slog.Attr {
	var s string
	if raw != nil && json.Unmarshal(raw, &s) != nil {
		s = string(raw) // a number, a flag or a list: its JSON
	}
	switch name {
	case "uri":
		return pii.URI(key, s)
	case "webhook.url":
		host := ""
		if u, err := url.Parse(s); err == nil {
			host = u.Hostname()
		}
		return slog.String(key, host)
	}
	sum := sha256.Sum256([]byte(s))
	return slog.Group(key, slog.Int("len", len(s)), slog.String("sha256", hex.EncodeToString(sum[:4])))
}

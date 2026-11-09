package store

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// AuditChanges returns what an audit line says of a change from before to
// after (ADR 0009 §7, as the lead decided on #709): a group per changed
// field, named by its JSON path (webhook.url, limits.sends_per_day).
// Structured fields (the ID, permissions, limits, state, source networks,
// the webhook's verified flag) carry their values before and after. The
// webhook URL carries its host only, without userinfo or an IPv6 zone,
// since the rest may hold the chatbot's secret; the URI goes through
// pii.URI. Any other field, the display name and out-of-service text
// among them, is free text (§10): it says it changed, and its new length
// in bytes. Registering is a change from the zero Chatbot. Walking the
// encoded record, rather than a list of fields, keeps a field added later
// from being missed, and logs it as free text until it is listed here.
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
		attrs = append(attrs, change(name, b[name], a[name]))
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

func change(name string, before, after json.RawMessage) slog.Attr {
	switch {
	case name == "id" || name == "state" || name == "sources" || name == "webhook.verified" ||
		strings.HasPrefix(name, "permissions.") || strings.HasPrefix(name, "limits."):
		return slog.Group(name, slog.Any("before", value(before)), slog.Any("after", value(after)))
	case name == "uri":
		return slog.Group(name, uri("before", text(before)), uri("after", text(after)))
	case name == "webhook.url":
		return slog.Group(name, slog.String("before", host(text(before))), slog.String("after", host(text(after))))
	}
	return slog.Group(name, slog.Bool("changed", true), slog.Int("len", len(text(after))))
}

// value is a structured field's value, nil when it is not set; numbers
// stay exact.
func value(raw json.RawMessage) any {
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	_ = d.Decode(&v)
	return v
}

// text is a string field's value, "" when it is not set.
func text(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func host(webhook string) string {
	u, err := url.Parse(webhook)
	if err != nil {
		return ""
	}
	h, _, _ := strings.Cut(u.Hostname(), "%")
	return h
}

// uri is a URI through pii.URI, or "" when it is not set, which pii would
// mask as if it were one.
func uri(key, v string) slog.Attr {
	if v == "" {
		return slog.String(key, "")
	}
	return pii.URI(key, v)
}

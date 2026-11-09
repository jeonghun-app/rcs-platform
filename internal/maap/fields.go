package maap

import (
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// chatbotBody is a chatbot as the operator sends it: every field to
// register one, only those to change in a change. A field left out, or
// null, keeps its value. Permissions and limits merge field by field, as
// in a JSON merge patch (RFC 7396), so that lowering one limit cannot
// raise the others to their defaults (#742 review, lead decision); the
// webhook, one value, is replaced whole. The string bounds are the
// registry's (store.MaxDisplayNameBytes and the rest), which
// DecodeEnvelope enforces.
type chatbotBody struct {
	ID           string           `json:"id" maxbytes:"64"`
	URI          string           `json:"uri" maxbytes:"255"`
	DisplayName  *string          `json:"display_name" maxbytes:"128"`
	OutOfService *string          `json:"out_of_service" maxbytes:"512"`
	Webhook      *webhookBody     `json:"webhook"`
	Permissions  *permissionsBody `json:"permissions"`
	Limits       *limitsBody      `json:"limits"`
	Sources      *[]string        `json:"sources" maxbytes:"43"`
}

// permissionsBody is store.Permissions with each field optional.
type permissionsBody struct {
	MSISDN             *bool `json:"msisdn"`
	StartConversations *bool `json:"start_conversations"`
}

// limitsBody is store.Limits with each field optional, in the same order
// with the same names (TestTheLimitsBodyMirrorsStoreLimits); 0 sets a
// limit back to its default.
type limitsBody struct {
	SendsPerMinute                 *int64 `json:"sends_per_minute"`
	SendsPerDay                    *int64 `json:"sends_per_day"`
	StartsPerMinute                *int64 `json:"starts_per_minute"`
	StartsPerDay                   *int64 `json:"starts_per_day"`
	SendsPerSubscriberPerMinute    *int64 `json:"sends_per_subscriber_per_minute"`
	SendsPerSubscriberPerDay       *int64 `json:"sends_per_subscriber_per_day"`
	ReceivedPerSubscriberPerMinute *int64 `json:"received_per_subscriber_per_minute"`
	ReceivedPerMinute              *int64 `json:"received_per_minute"`
	RequestsPerMinute              *int64 `json:"requests_per_minute"`
}

// webhookBody is the webhook as the operator sets it: whether it is
// verified is maap's to find out (#683).
type webhookBody struct {
	URL string `json:"url" maxbytes:"512"`
}

// defaultLimits are the platform's bounds of ADR 0009 §9, one per field of
// store.Limits, which an operator may lower but never raise.
var defaultLimits = store.Limits{
	SendsPerMinute: 600, SendsPerDay: 20_000,
	StartsPerMinute: 60, StartsPerDay: 1_000,
	SendsPerSubscriberPerMinute: 20, SendsPerSubscriberPerDay: 200,
	ReceivedPerSubscriberPerMinute: 30,
	ReceivedPerMinute:              6_000,
	RequestsPerMinute:              1_200,
}

// fieldRules are the settings the operator's values are checked against.
type fieldRules struct {
	// ports are the webhook ports besides 443, MAAP_WEBHOOK_PORTS.
	ports []uint16
	// allowHTTP allows http webhooks, outside staging and prod.
	allowHTTP bool
	// allowInternal allows loopback and private IP addresses as a
	// webhook's host, in dev only, for the compose stack.
	allowInternal bool
}

// apply checks each field b sets and writes it into c, then the rules
// between fields. Every refusal is 400 and names the field, never the
// value.
func (f fieldRules) apply(c *store.Chatbot, b chatbotBody) error {
	if b.DisplayName != nil {
		// It reaches CPIM From and P-Asserted-Identity (#687 review).
		if err := refuseControls("display_name", *b.DisplayName); err != nil {
			return err
		}
		if reason := displayNameProblem(*b.DisplayName); reason != "" {
			return fail(http.StatusBadRequest, "display_name holds "+reason)
		}
		c.DisplayName = *b.DisplayName
	}
	if b.OutOfService != nil {
		// Subscribers get it as a message body: ADR 0009 §5's rules for
		// text/plain content, then refuseInvisible's.
		if chatbot.ValidateContent("text/plain", []byte(*b.OutOfService)) != nil {
			return fail(http.StatusBadRequest, "out_of_service is not text/plain without control characters")
		}
		if err := refuseInvisible("out_of_service", *b.OutOfService); err != nil {
			return err
		}
		c.OutOfService = *b.OutOfService
	}
	if b.Webhook != nil {
		if reason := webhookProblem(b.Webhook.URL, f.ports, f.allowHTTP, f.allowInternal); reason != "" {
			return fail(http.StatusBadRequest, "webhook.url: "+reason)
		}
		if b.Webhook.URL != c.Webhook.URL {
			// A newly set URL must answer its challenge before it is
			// used (memo F6).
			c.Webhook = store.Webhook{URL: b.Webhook.URL}
		}
	}
	if p := b.Permissions; p != nil {
		if p.MSISDN != nil {
			c.Permissions.MSISDN = *p.MSISDN
		}
		if p.StartConversations != nil {
			c.Permissions.StartConversations = *p.StartConversations
		}
	}
	if b.Limits != nil {
		if err := mergeLimits(&c.Limits, *b.Limits); err != nil {
			return err
		}
	}
	if b.Sources != nil {
		sources, err := sourceNetworks(*b.Sources)
		if err != nil {
			return err
		}
		c.Sources = sources
	}
	if c.Permissions.StartConversations && !c.Permissions.MSISDN {
		// A chatbot that starts a conversation names someone it has no
		// alias for (ADR 0009 §9).
		return fail(http.StatusBadRequest, "permissions.start_conversations requires permissions.msisdn")
	}
	return nil
}

// refuseInvisible refuses, in the out-of-service text, DEL, the C1
// controls and the format characters (Unicode Cf: every bidi control,
// zero-width characters), with which a text can show as other than it is
// (T13, #717 review). The zero-width joiner, U+200D, is allowed, so that
// emoji sequences keep working (lead decision on #709); the display name
// has the stricter displayNameProblem. The registry is these texts' only
// source, so it refuses them rather than every reader.
func refuseInvisible(field, v string) error {
	if strings.ContainsFunc(v, func(r rune) bool {
		return 0x7f <= r && r <= 0x9f || unicode.Is(unicode.Cf, r) && r != zeroWidthJoiner
	}) {
		return fail(http.StatusBadRequest, field+" holds a control or format character")
	}
	return nil
}

// webhookProblem says why raw cannot be a webhook URL, or returns "" (ADR
// 0009 §8, the #682 decision): https, or http where allowed; a host, and no
// userinfo; port 443 or one on ports, in decimal without leading zeros, the
// scheme's default port counting as named; at most 512 bytes, without
// control characters; and written as net/url writes it back, so that
// #683's dialer reads the URL judged here. The host has no "%", so no IPv6
// zone, and hostProblem's rules for an IP address (security review of
// #741, lead decision). "" itself is no webhook, which is allowed. What a
// host name resolves to is #683's to check when it dials.
func webhookProblem(raw string, ports []uint16, allowHTTP, allowInternal bool) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	switch {
	case len(raw) > store.MaxWebhookBytes:
		return "longer than 512 bytes"
	case strings.ContainsFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "a control character"
	case err != nil || u.String() != raw:
		return "not a URL in the form it is written back as"
	case u.Scheme != "https" && (!allowHTTP || u.Scheme != "http"):
		return "not https"
	case u.User != nil:
		return "userinfo"
	case u.Opaque != "" || u.Hostname() == "":
		return "no host"
	case strings.Contains(u.Host, "%"):
		return "a % in the host, such as an IPv6 zone"
	}
	if reason := hostProblem(u.Hostname(), allowInternal); reason != "" {
		return reason
	}
	port := u.Port()
	switch {
	case port == "" && strings.HasSuffix(u.Host, ":"):
		return "an empty port"
	case port == "" && u.Scheme == "https":
		port = "443"
	case port == "":
		port = "80"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || strconv.FormatUint(n, 10) != port || n != 443 && !slices.Contains(ports, uint16(n)) {
		return "a port other than 443 or one on MAAP_WEBHOOK_PORTS"
	}
	return ""
}

// nat64 is the well-known NAT64 prefix (RFC 6052), which embeds an IPv4
// address as 4-in-6 forms do.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// hostProblem refuses a webhook host that is an internal IP address, when
// the operator sets it, a layer before #683's dialer, the primary control
// (ADR 0009 §8, memo F5): an IPv4 address inside IPv6 (mapped, NAT64,
// compatible), loopback and private (RFC 1918, ULA) unless allowInternal,
// and anything else that is not global unicast (link-local, the metadata
// address 169.254.169.254 among them, unspecified, multicast). A host whose
// last label is a number, 127.1, 2130706433 or 0x7f000001, is an IPv4
// address to some resolvers (inet_aton) and URL parsers (WHATWG): it is
// refused unless it is one in dotted decimal, which is then judged as an
// address.
func hostProblem(host string, allowInternal bool) string {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		name := strings.TrimSuffix(host, ".")
		if numeric(name[strings.LastIndexByte(name, '.')+1:]) {
			return "an IP address in a form other than dotted decimal"
		}
		return ""
	}
	switch {
	case addr.Is4In6() || nat64.Contains(addr) || ipv4Compatible(addr):
		return "an IPv4 address inside IPv6"
	case addr.IsLoopback() || addr.IsPrivate():
		if allowInternal {
			return ""
		}
		return "a loopback or private address"
	case !addr.IsGlobalUnicast():
		return "an address that is not global unicast"
	}
	return ""
}

// ipv4Compatible reports whether addr is in the deprecated ::/96 of IPv4-
// compatible addresses (RFC 4291 §2.5.5.1), :: and ::1 apart.
func ipv4Compatible(addr netip.Addr) bool {
	b := addr.As16()
	return addr.Is6() && [12]byte(b[:12]) == [12]byte{} && !addr.IsLoopback() && !addr.IsUnspecified()
}

// numeric reports whether label is a number in decimal or 0x hex, as
// inet_aton and the WHATWG URL parser read a host's labels.
func numeric(label string) bool {
	if rest, ok := strings.CutPrefix(strings.ToLower(label), "0x"); ok {
		return strings.Trim(rest, "0123456789abcdef") == ""
	}
	return label != "" && strings.Trim(label, "0123456789") == ""
}

// mergeLimits writes into l each limit b gives, refusing one below 0 or
// above its default; 0 is the default. A limit b leaves out is not
// checked: it keeps its stored value.
func mergeLimits(l *store.Limits, b limitsBody) error {
	given, to, max := reflect.ValueOf(b), reflect.ValueOf(l).Elem(), reflect.ValueOf(defaultLimits)
	for i := range given.NumField() {
		if given.Field(i).IsNil() {
			continue
		}
		if v := given.Field(i).Elem().Int(); v < 0 || v > max.Field(i).Int() {
			name, _, _ := strings.Cut(given.Type().Field(i).Tag.Get("json"), ",")
			return fail(http.StatusBadRequest, "limits."+name+" is not from 0, the default, to "+strconv.FormatInt(max.Field(i).Int(), 10))
		}
		to.Field(i).SetInt(given.Field(i).Elem().Int())
	}
	return nil
}

// sourceNetworks returns the network prefixes of list in canonical form,
// nil for none. A prefix with host bits set is refused rather than
// widened: 192.0.2.1/24 is more likely a slip than a /24.
func sourceNetworks(list []string) ([]string, error) {
	var out []string
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return nil, fail(http.StatusBadRequest, "sources holds an item that is not a network prefix without host bits")
		}
		out = append(out, p.String())
	}
	return out, nil
}

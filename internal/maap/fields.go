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
// null, keeps its value; an object given replaces the whole object. The
// string bounds are the registry's (store.MaxDisplayNameBytes and the
// rest), which DecodeEnvelope enforces.
type chatbotBody struct {
	ID           string             `json:"id" maxbytes:"64"`
	URI          string             `json:"uri" maxbytes:"255"`
	DisplayName  *string            `json:"display_name" maxbytes:"128"`
	OutOfService *string            `json:"out_of_service" maxbytes:"512"`
	Webhook      *webhookBody       `json:"webhook"`
	Permissions  *store.Permissions `json:"permissions"`
	Limits       *store.Limits      `json:"limits"`
	Sources      *[]string          `json:"sources" maxbytes:"43"`
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
		if err := refuseInvisible("display_name", *b.DisplayName); err != nil {
			return err
		}
		c.DisplayName = *b.DisplayName
	}
	if b.OutOfService != nil {
		// Subscribers get it as a message body: ADR 0009 §5's rules for
		// text/plain content, then those of a display name.
		if chatbot.ValidateContent("text/plain", []byte(*b.OutOfService)) != nil {
			return fail(http.StatusBadRequest, "out_of_service is not text/plain without control characters")
		}
		if err := refuseInvisible("out_of_service", *b.OutOfService); err != nil {
			return err
		}
		c.OutOfService = *b.OutOfService
	}
	if b.Webhook != nil {
		if reason := webhookProblem(b.Webhook.URL, f.ports, f.allowHTTP); reason != "" {
			return fail(http.StatusBadRequest, "webhook.url: "+reason)
		}
		if b.Webhook.URL != c.Webhook.URL {
			// A newly set URL must answer its challenge before it is
			// used (memo F6).
			c.Webhook = store.Webhook{URL: b.Webhook.URL}
		}
	}
	if b.Permissions != nil {
		c.Permissions = *b.Permissions
	}
	if b.Limits != nil {
		if err := checkLimits(*b.Limits); err != nil {
			return err
		}
		c.Limits = *b.Limits
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

// refuseInvisible refuses DEL, the C1 controls and the format characters
// (Unicode Cf: every bidi control, zero-width characters), with which a
// name can show as another's (T13, #717 review). The zero-width joiner,
// U+200D, is allowed, so that emoji sequences keep working (lead decision
// on #709). The registry is these texts' only source, so it refuses them
// rather than every reader.
func refuseInvisible(field, v string) error {
	if strings.ContainsFunc(v, func(r rune) bool {
		return 0x7f <= r && r <= 0x9f || unicode.Is(unicode.Cf, r) && r != zeroWidthJoiner
	}) {
		return fail(http.StatusBadRequest, field+" holds a control or format character")
	}
	return nil
}

const zeroWidthJoiner = '\u200d'

// webhookProblem says why raw cannot be a webhook URL, or returns "" (ADR
// 0009 §8, the #682 decision): https, or http where allowed; a host, and no
// userinfo; port 443 or one on ports, in decimal without leading zeros, the
// scheme's default port counting as named; at most 512 bytes, without
// control characters; and written as net/url writes it back, so that
// #683's dialer reads the URL judged here.
// "" itself is no webhook, which is allowed. The address is #683's to check
// when it dials.
func webhookProblem(raw string, ports []uint16, allowHTTP bool) string {
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

// checkLimits refuses a limit below 0 or above its default; 0 is the
// default.
func checkLimits(l store.Limits) error {
	got, max := reflect.ValueOf(l), reflect.ValueOf(defaultLimits)
	for i := range got.NumField() {
		if v := got.Field(i).Int(); v < 0 || v > max.Field(i).Int() {
			name, _, _ := strings.Cut(got.Type().Field(i).Tag.Get("json"), ",")
			return fail(http.StatusBadRequest, "limits."+name+" is not from 0, the default, to "+strconv.FormatInt(max.Field(i).Int(), 10))
		}
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

package sip

import "strings"

// Typed accessors. Each parses the current field values on every call, so a
// service that changes a field reads the change back. A single-valued field that
// is absent yields an error wrapping ErrMissingHeader; a list field that is absent
// yields an empty list. A field that appears more than once where the grammar
// allows one, or does not parse, yields an error wrapping ErrMalformed.

// Via returns every Via element, top first.
func (h *Header) Via() ([]Via, error) {
	return listOf(h, "Via", parseViaElement)
}

// From returns the From address.
func (h *Header) From() (Address, error) { return singleOf(h, "From", ParseAddress) }

// To returns the To address.
func (h *Header) To() (Address, error) { return singleOf(h, "To", ParseAddress) }

// CallID returns the Call-ID.
func (h *Header) CallID() (string, error) {
	return singleOf(h, "Call-ID", func(s string) (string, error) {
		if !isCallID(s) {
			return "", syntaxError("invalid Call-ID")
		}
		return s, nil
	})
}

// CSeq returns the CSeq.
func (h *Header) CSeq() (CSeq, error) { return singleOf(h, "CSeq", parseCSeq) }

// MaxForwards returns Max-Forwards, which is 0 to 255 (RFC 3261 §20.22).
func (h *Header) MaxForwards() (int, error) {
	return singleOf(h, "Max-Forwards", func(s string) (int, error) {
		n, ok := parseDelta(s)
		if !ok || n > 255 {
			return 0, syntaxError("invalid Max-Forwards")
		}
		return int(n), nil
	})
}

// Contact returns the Contact elements. A "*" contact is returned alone with Star
// set; "*" mixed with addresses is malformed.
func (h *Header) Contact() ([]Contact, error) {
	els, err := h.Elements("Contact")
	if err != nil || els == nil {
		return nil, err
	}
	cs, err := parseContactElements(els)
	return cs, inHeader("Contact", err)
}

// Route returns the Route elements, which must be name-addrs (RFC 3261 §20.34).
func (h *Header) Route() ([]Address, error) { return h.nameAddrs("Route") }

// RecordRoute returns the Record-Route elements (RFC 3261 §20.30).
func (h *Header) RecordRoute() ([]Address, error) { return h.nameAddrs("Record-Route") }

// Path returns the Path elements (RFC 3327 §4).
func (h *Header) Path() ([]Address, error) { return h.nameAddrs("Path") }

// ServiceRoute returns the Service-Route elements (RFC 3608).
func (h *Header) ServiceRoute() ([]Address, error) { return h.nameAddrs("Service-Route") }

// PAssociatedURI returns the P-Associated-URI elements (RFC 7315 §4.1).
func (h *Header) PAssociatedURI() ([]Address, error) { return h.nameAddrs("P-Associated-URI") }

// PAssertedIdentity returns the P-Asserted-Identity elements (RFC 3325 §9.1),
// at most one SIP or SIPS URI and one tel URI in practice.
func (h *Header) PAssertedIdentity() ([]Address, error) {
	return listOf(h, "P-Asserted-Identity", ParseAddress)
}

// PPreferredIdentity returns the P-Preferred-Identity elements (RFC 3325 §9.2).
func (h *Header) PPreferredIdentity() ([]Address, error) {
	return listOf(h, "P-Preferred-Identity", ParseAddress)
}

// PCalledPartyID returns P-Called-Party-ID, a name-addr (RFC 7315 §4.2).
func (h *Header) PCalledPartyID() (Address, error) {
	return singleOf(h, "P-Called-Party-ID", func(s string) (Address, error) {
		return parseAddress(s, true)
	})
}

// PVisitedNetworkID returns the P-Visited-Network-ID elements (RFC 7315 §4.3).
func (h *Header) PVisitedNetworkID() ([]VisitedNetwork, error) {
	return listOf(h, "P-Visited-Network-ID", parseVisitedNetwork)
}

// PChargingVector returns P-Charging-Vector (RFC 7315 §4.6).
func (h *Header) PChargingVector() (ChargingVector, error) {
	return singleOf(h, "P-Charging-Vector", parseChargingVector)
}

// Expires returns Expires in seconds (RFC 3261 §20.19). An overlarge value is
// reported as malformed, not clamped: whether to clamp it or use a default is the
// registrar's decision (RFC 3261 §10.2.1, RFC 4475 §3.1.2.4).
func (h *Header) Expires() (uint32, error) {
	return singleOf(h, "Expires", func(s string) (uint32, error) {
		n, ok := parseDelta(s)
		if !ok {
			return 0, syntaxError("invalid delta-seconds")
		}
		return n, nil
	})
}

// Allow returns the methods in Allow. An empty Allow, meaning no method, is
// allowed by RFC 3261 §20.5 and yields an empty list, as an absent one does; use
// Has to tell them apart.
func (h *Header) Allow() ([]string, error) { return h.tokens("Allow", true) }

// Supported returns the option tags in Supported, which may be empty (RFC 3261
// §20.37).
func (h *Header) Supported() ([]string, error) { return h.tokens("Supported", true) }

// Require returns the option tags in Require (RFC 3261 §20.32).
func (h *Header) Require() ([]string, error) { return h.tokens("Require", false) }

// ContentType returns Content-Type.
func (h *Header) ContentType() (MediaType, error) {
	return singleOf(h, "Content-Type", parseMediaType)
}

// WWWAuthenticate returns one challenge per WWW-Authenticate field.
func (h *Header) WWWAuthenticate() ([]Challenge, error) {
	return perLine(h, "WWW-Authenticate", parseChallenge)
}

// ProxyAuthenticate returns one challenge per Proxy-Authenticate field.
func (h *Header) ProxyAuthenticate() ([]Challenge, error) {
	return perLine(h, "Proxy-Authenticate", parseChallenge)
}

// Authorization returns one set of credentials per Authorization field.
func (h *Header) Authorization() ([]Credentials, error) {
	return perLine(h, "Authorization", parseCredentials)
}

// ProxyAuthorization returns one set of credentials per Proxy-Authorization field.
func (h *Header) ProxyAuthorization() ([]Credentials, error) {
	return perLine(h, "Proxy-Authorization", parseCredentials)
}

// AcceptContact returns the Accept-Contact elements (RFC 3841).
func (h *Header) AcceptContact() ([]AcceptContact, error) {
	return listOf(h, "Accept-Contact", parseAcceptContact)
}

// Event returns Event (RFC 6665 §8.2.1).
func (h *Header) Event() (Event, error) {
	return singleOf(h, "Event", func(s string) (Event, error) {
		t, ps, err := parseTokenParams(s)
		return Event{Type: t, Params: ps}, err
	})
}

// SubscriptionState returns Subscription-State (RFC 6665 §8.2.3).
func (h *Header) SubscriptionState() (SubscriptionState, error) {
	return singleOf(h, "Subscription-State", parseSubscriptionState)
}

// SessionExpires returns Session-Expires (RFC 4028 §4).
func (h *Header) SessionExpires() (SessionExpires, error) {
	return singleOf(h, "Session-Expires", func(s string) (SessionExpires, error) {
		n, ps, err := parseDeltaParams(s)
		if err != nil {
			return SessionExpires{}, err
		}
		if r, ok := ps.Get("refresher"); ok && !strings.EqualFold(r, "uac") && !strings.EqualFold(r, "uas") {
			return SessionExpires{}, syntaxError("refresher must be uac or uas")
		}
		return SessionExpires{Delta: n, Params: ps}, nil
	})
}

// MinSE returns Min-SE (RFC 4028 §5).
func (h *Header) MinSE() (MinSE, error) {
	return singleOf(h, "Min-SE", func(s string) (MinSE, error) {
		n, ps, err := parseDeltaParams(s)
		return MinSE{Delta: n, Params: ps}, err
	})
}

// Reason returns the Reason elements (RFC 3326 §2).
func (h *Header) Reason() ([]Reason, error) { return listOf(h, "Reason", parseReason) }

func (h *Header) nameAddrs(name string) ([]Address, error) {
	return listOf(h, name, func(s string) (Address, error) { return parseAddress(s, true) })
}

func (h *Header) tokens(name string, allowEmpty bool) ([]string, error) {
	key := headerKey(name)
	var out []string
	for i := range h.fields {
		f := &h.fields[i]
		if f.key != key {
			continue
		}
		if f.value == "" && allowEmpty {
			continue
		}
		els, err := splitList(f.value)
		if err != nil {
			return nil, inHeader(name, err)
		}
		for _, el := range els {
			if !isAll(el, classToken) {
				return nil, headerError(name, "element is not a token")
			}
		}
		out = append(out, els...)
	}
	return out, nil
}

func parseChallenge(s string) (Challenge, error) {
	scheme, ps, err := parseAuth(s)
	return Challenge{Scheme: scheme, Params: ps}, err
}

func parseCredentials(s string) (Credentials, error) {
	scheme, ps, err := parseAuth(s)
	return Credentials{Scheme: scheme, Params: ps}, err
}

func singleOf[T any](h *Header, name string, parse func(string) (T, error)) (T, error) {
	v, err := h.single(name)
	if err != nil {
		var zero T
		return zero, err
	}
	t, err := parse(v)
	if err != nil {
		var zero T
		return zero, inHeader(name, err)
	}
	return t, nil
}

func listOf[T any](h *Header, name string, parse func(string) (T, error)) ([]T, error) {
	els, err := h.Elements(name)
	if err != nil || els == nil {
		return nil, err
	}
	out := make([]T, 0, len(els))
	for _, el := range els {
		t, err := parse(el)
		if err != nil {
			return nil, inHeader(name, err)
		}
		out = append(out, t)
	}
	return out, nil
}

func perLine[T any](h *Header, name string, parse func(string) (T, error)) ([]T, error) {
	var out []T
	for _, v := range h.Values(name) {
		t, err := parse(v)
		if err != nil {
			return nil, inHeader(name, err)
		}
		out = append(out, t)
	}
	return out, nil
}

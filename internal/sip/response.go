package sip

import "errors"

// NewResponse builds a response to req as RFC 3261 §8.2.6 describes: Via, From,
// Call-ID and CSeq are copied byte for byte and in order, and so is To, with
// toTag added when the request's To has no tag and the response is not a 100. A
// 100 also copies Timestamp (§8.2.6.1). An empty reason takes DefaultReason(code).
//
// toTag is a parameter rather than generated here because a UAS must use the same
// tag in every response that can create the dialog (RFC 3261 §12.1.1); the caller
// generates it once, with IDGenerator.Tag, and passes it to each response.
// NewResponse fails if a tag is needed and toTag is empty, or if To is missing or
// malformed, since a tag cannot then be added. Other fields are copied as they
// are, so a request that has not passed Validate gives a response that may not.
func NewResponse(req *Request, code int, reason, toTag string) (*Response, error) {
	if code < 100 || code > 699 {
		return nil, errors.New("sip: status code outside 100-699")
	}
	if reason == "" {
		reason = DefaultReason(code)
	}
	res := &Response{StatusCode: code, Reason: reason}

	var to field
	addTag := false
	if code > 100 {
		a, err := req.Header.To()
		if err != nil {
			return nil, err
		}
		if a.Tag() == "" {
			if toTag == "" {
				return nil, errors.New("sip: response needs a To tag")
			}
			if !isAll(toTag, classToken) {
				return nil, errors.New("sip: To tag is not a token")
			}
			a.Params.Set("tag", toTag)
			to, err = newField("To", a.String())
			if err != nil {
				return nil, err
			}
			addTag = true
		}
	}

	for _, f := range req.Header.fields {
		switch f.key {
		case "via", "from", "call-id", "cseq":
		case "to":
			if addTag {
				f = to
			}
		case "timestamp":
			if code != 100 {
				continue
			}
		default:
			continue
		}
		res.Header.fields = append(res.Header.fields, f)
	}
	return res, nil
}

var reasonPhrases = map[int]string{
	100: "Trying",
	180: "Ringing",
	181: "Call Is Being Forwarded",
	182: "Queued",
	183: "Session Progress",
	199: "Early Dialog Terminated", // RFC 6228
	200: "OK",
	202: "Accepted",        // RFC 3265
	204: "No Notification", // RFC 5839
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Moved Temporarily",
	305: "Use Proxy",
	380: "Alternative Service",
	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	410: "Gone",
	412: "Conditional Request Failed", // RFC 3903
	413: "Request Entity Too Large",
	414: "Request-URI Too Long",
	415: "Unsupported Media Type",
	416: "Unsupported URI Scheme",
	417: "Unknown Resource-Priority", // RFC 4412
	420: "Bad Extension",
	421: "Extension Required",
	422: "Session Interval Too Small", // RFC 4028
	423: "Interval Too Brief",
	428: "Use Identity Header",              // RFC 8224
	429: "Provide Referrer Identity",        // RFC 3892
	430: "Flow Failed",                      // RFC 5626
	433: "Anonymity Disallowed",             // RFC 5079
	436: "Bad Identity Info",                // RFC 8224
	437: "Unsupported Credential",           // RFC 8224
	438: "Invalid Identity Header",          // RFC 8224
	439: "First Hop Lacks Outbound Support", // RFC 5626
	440: "Max-Breadth Exceeded",             // RFC 5393
	469: "Bad Info Package",                 // RFC 6086
	470: "Consent Needed",                   // RFC 5360
	480: "Temporarily Unavailable",
	481: "Call/Transaction Does Not Exist",
	482: "Loop Detected",
	483: "Too Many Hops",
	484: "Address Incomplete",
	485: "Ambiguous",
	486: "Busy Here",
	487: "Request Terminated",
	488: "Not Acceptable Here",
	489: "Bad Event", // RFC 6665
	491: "Request Pending",
	493: "Undecipherable",
	494: "Security Agreement Required", // RFC 3329
	500: "Server Internal Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Server Time-out",
	505: "Version Not Supported",
	513: "Message Too Large",
	555: "Push Notification Service Not Supported", // RFC 8599
	580: "Precondition Failure",                    // RFC 3312
	600: "Busy Everywhere",
	603: "Decline",
	604: "Does Not Exist Anywhere",
	606: "Not Acceptable",
	607: "Unwanted", // RFC 8197
	608: "Rejected", // RFC 8688
}

// DefaultReason returns the reason phrase registered for code (RFC 3261 §21 and
// the extensions noted in the table), or the name of its class (RFC 3261 §7.2)
// for an unregistered code, or "" outside 100–699.
func DefaultReason(code int) string {
	if r, ok := reasonPhrases[code]; ok {
		return r
	}
	switch code / 100 {
	case 1:
		return "Provisional"
	case 2:
		return "Success"
	case 3:
		return "Redirection"
	case 4:
		return "Client Error"
	case 5:
		return "Server Error"
	case 6:
		return "Global Failure"
	}
	return ""
}

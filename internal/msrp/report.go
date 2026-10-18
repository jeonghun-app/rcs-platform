package msrp

import "errors"

// ShouldRespond reports whether a transaction response with code may be
// sent for req. REPORT requests are never answered (§7.1.2). Otherwise
// Failure-Report decides (§7.1.4, §7.2): "no" forbids every response,
// "partial" forbids only 200, and "yes" or no header asks for all of them.
func ShouldRespond(req *Message, code int) bool {
	if !req.IsRequest() || req.Method == MethodReport {
		return false
	}
	switch req.FailureMode() {
	case ReportNo:
		return false
	case ReportPartial:
		return code != StatusOK
	}
	return true
}

// ShouldReport reports whether a REPORT with code may be sent about the
// SEND request req: a success REPORT only on Success-Report yes (§7.1.3), a
// failure REPORT unless Failure-Report is no (§7.1.4).
func ShouldReport(req *Message, code int) bool {
	if req.Method != MethodSend {
		return false
	}
	if code == StatusOK {
		return req.WantsSuccessReport()
	}
	return req.FailureMode() != ReportNo
}

// NewResponse builds the response with code to req (§7.2). A response to
// SEND goes back to the previous hop only; any other response carries the
// whole path back. The responder's From-Path is the URI the request was
// addressed to.
func NewResponse(req *Message, code int, comment string) (*Message, error) {
	if len(req.ToPath) == 0 || len(req.FromPath) == 0 {
		return nil, errors.New("msrp: cannot answer a request without paths")
	}
	to := req.FromPath
	if req.Method == MethodSend {
		to = to[:1]
	}
	return &Message{
		TransactionID: req.TransactionID,
		StatusCode:    code,
		Comment:       comment,
		ToPath:        append([]URI(nil), to...),
		FromPath:      []URI{req.ToPath[0]},
	}, nil
}

// NewReport builds a REPORT about the SEND request req on the bytes in r:
// a success report for code 200 (§7.1.3) and a failure report otherwise
// (§7.1.4). It goes back along the request's whole From-Path; from is the
// reporter's own URI in the session. The transaction id is left for the
// sender to choose.
func NewReport(req *Message, from URI, r ByteRange, code int) *Message {
	return &Message{
		Method:    MethodReport,
		ToPath:    append([]URI(nil), req.FromPath...),
		FromPath:  []URI{from},
		MessageID: req.MessageID,
		ByteRange: &r,
		Status:    &Status{Namespace: 0, Code: code, Comment: StatusText(code)},
	}
}

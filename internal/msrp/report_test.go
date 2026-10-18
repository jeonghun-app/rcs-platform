package msrp

import "testing"

func TestTransactionResponsesFollowFailureReport(t *testing.T) {
	tests := []struct {
		method string
		mode   ReportMode
		code   int
		want   bool
	}{
		{MethodSend, ReportUnset, StatusOK, true},
		{MethodSend, ReportUnset, StatusNoSession, true},
		{MethodSend, ReportYes, StatusOK, true},
		{MethodSend, ReportYes, StatusUnsupportedMediaType, true},
		{MethodSend, ReportPartial, StatusOK, false},
		{MethodSend, ReportPartial, StatusMessageTooLarge, true},
		{MethodSend, ReportNo, StatusOK, false},
		{MethodSend, ReportNo, StatusBadRequest, false},
		{MethodNickname, ReportUnset, StatusOK, true},
		{MethodReport, ReportUnset, StatusOK, false},
		{MethodReport, ReportUnset, StatusBadRequest, false},
	}
	for _, tt := range tests {
		req := &Message{Method: tt.method, FailureReport: tt.mode}
		if got := ShouldRespond(req, tt.code); got != tt.want {
			t.Errorf("%s Failure-Report %q, code %d: ShouldRespond = %v, want %v", tt.method, tt.mode, tt.code, got, tt.want)
		}
	}
	if ShouldRespond(&Message{StatusCode: 200}, StatusOK) {
		t.Error("a response is never answered")
	}
}

func TestReportsFollowSuccessReportAndFailureReport(t *testing.T) {
	tests := []struct {
		method          string
		success, failed ReportMode
		code            int
		want            bool
	}{
		{MethodSend, ReportUnset, ReportUnset, StatusOK, false}, // no success reports by default
		{MethodSend, ReportNo, ReportUnset, StatusOK, false},
		{MethodSend, ReportYes, ReportNo, StatusOK, true},
		{MethodSend, ReportUnset, ReportUnset, StatusForbidden, true}, // failure reports by default
		{MethodSend, ReportUnset, ReportYes, StatusForbidden, true},
		{MethodSend, ReportUnset, ReportPartial, StatusForbidden, true},
		{MethodSend, ReportYes, ReportNo, StatusForbidden, false},
		{MethodReport, ReportUnset, ReportUnset, StatusForbidden, false}, // never a REPORT about a REPORT
		{MethodNickname, ReportYes, ReportYes, StatusOK, false},
	}
	for _, tt := range tests {
		req := &Message{Method: tt.method, SuccessReport: tt.success, FailureReport: tt.failed}
		if got := ShouldReport(req, tt.code); got != tt.want {
			t.Errorf("%s SR %q FR %q code %d: ShouldReport = %v, want %v", tt.method, tt.success, tt.failed, tt.code, got, tt.want)
		}
	}
}

func TestResponseToSendGoesBackToThePreviousHopOnly(t *testing.T) {
	us, relay, sender := mustURI(t, toURI), mustURI(t, "msrp://relay.example.net:2855/r1;tcp"), mustURI(t, fromURI)
	req := &Message{TransactionID: "abcd", Method: MethodSend, ToPath: []URI{us}, FromPath: []URI{relay, sender}}
	resp, err := NewResponse(req, StatusOK, "OK")
	if err != nil {
		t.Fatal(err)
	}
	if resp.TransactionID != "abcd" || resp.StatusCode != 200 || len(resp.ToPath) != 1 || !resp.ToPath[0].Equal(relay) ||
		len(resp.FromPath) != 1 || !resp.FromPath[0].Equal(us) {
		t.Fatalf("response %+v", resp)
	}
	if _, err := resp.Marshal(); err != nil {
		t.Fatal(err)
	}
}

func TestResponseToOtherMethodsCarriesTheWholePathBack(t *testing.T) {
	us, relay, sender := mustURI(t, toURI), mustURI(t, "msrp://relay.example.net:2855/r1;tcp"), mustURI(t, fromURI)
	req := &Message{TransactionID: "abcd", Method: MethodNickname, ToPath: []URI{us}, FromPath: []URI{relay, sender}}
	resp, _ := NewResponse(req, 425, "Nickname reserved or already in use")
	if len(resp.ToPath) != 2 || !resp.ToPath[1].Equal(sender) {
		t.Fatalf("To-Path %v", resp.ToPath)
	}
}

func TestARequestWithoutPathsCannotBeAnswered(t *testing.T) {
	if _, err := NewResponse(&Message{TransactionID: "abcd", Method: MethodSend}, StatusBadRequest, ""); err == nil {
		t.Fatal("answered a request with no paths")
	}
}

func TestReportGoesBackAlongTheWholeFromPath(t *testing.T) {
	us, relay, sender := mustURI(t, toURI), mustURI(t, "msrp://relay.example.net:2855/r1;tcp"), mustURI(t, fromURI)
	req := &Message{Method: MethodSend, ToPath: []URI{us}, FromPath: []URI{relay, sender}, MessageID: "msg1"}
	rep := NewReport(req, us, ByteRange{Start: 1, End: 10, Total: 10}, StatusOK)
	if rep.Method != MethodReport || rep.MessageID != "msg1" || len(rep.ToPath) != 2 || !rep.FromPath[0].Equal(us) {
		t.Fatalf("report %+v", rep)
	}
	if rep.Status.Namespace != 0 || rep.Status.Code != 200 || rep.SuccessReport != ReportUnset || rep.FailureReport != ReportUnset {
		t.Fatalf("status %+v", rep.Status)
	}
	rep.TransactionID = "rep1"
	if _, err := rep.Marshal(); err != nil {
		t.Fatalf("a built report does not marshal: %v", err)
	}
}

func TestStatusErrorsNameTheirCode(t *testing.T) {
	if got := (&StatusError{Code: 415}).Error(); got != "msrp: status 415 Unsupported Media Type" {
		t.Fatalf("Error() = %q", got)
	}
	for _, code := range []int{200, 400, 403, 408, 413, 415, 423, 481, 501, 506} {
		if StatusText(code) == "" {
			t.Errorf("no text for %d", code)
		}
	}
	if StatusText(299) != "" {
		t.Error("text for an unknown code")
	}
}

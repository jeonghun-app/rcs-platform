package cpim

import (
	"strings"
	"testing"
)

// benchMessage is a chat message as rcs-as receives one: the core headers,
// an IMDN request, and a short text body.
var benchMessage = []byte(strings.ReplaceAll("From: <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>\n"+
	"To: <sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>\n"+
	"DateTime: 2026-10-22T12:00:00.000Z\n"+
	"NS: imdn <urn:ietf:params:imdn>\n"+
	"imdn.Message-ID: 0123456789abcdef\n"+
	"imdn.Disposition-Notification: positive-delivery, display\n"+
	"\n"+
	"Content-Type: text/plain;charset=UTF-8\n"+
	"Content-Length: 26\n"+
	"\n"+
	"meet me at the usual place", "\n", "\r\n"))

var (
	parseSink   *Message
	marshalSink []byte
)

// BenchmarkParse and BenchmarkMarshal are the CPIM work of every message
// rcs-as takes and sends on (#547: the body is a content.Body).
func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		m, err := Parse(benchMessage)
		if err != nil {
			b.Fatal(err)
		}
		parseSink = m
	}
}

func BenchmarkMarshal(b *testing.B) {
	m, err := Parse(benchMessage)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		out, err := m.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		marshalSink = out
	}
}

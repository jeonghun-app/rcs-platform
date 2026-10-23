// Package sip stands for internal/sip in printguard's tests: the same
// method sets on Request, Response and Body.
package sip

import (
	"fmt"
	"io"
	"log/slog"
)

type Body []byte

func (Body) String() string             { return "[redacted body]" }
func (Body) GoString() string           { return "[redacted body]" }
func (Body) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "[redacted body]") }
func (b Body) LogValue() slog.Value     { return slog.IntValue(len(b)) }

type Request struct {
	Method string
	Header []string
	Body   Body
}

func (Request) String() string              { return "request" }
func (Request) GoString() string            { return "request" }
func (*Request) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "request") }
func (Request) LogValue() slog.Value        { return slog.StringValue("request") }
func (*Request) message()                   {}

type Response struct {
	StatusCode int
	Body       Body
}

func (Response) String() string              { return "response" }
func (Response) GoString() string            { return "response" }
func (*Response) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "response") }
func (Response) LogValue() slog.Value        { return slog.StringValue("response") }
func (*Response) message()                   {}

type Message interface{ message() }

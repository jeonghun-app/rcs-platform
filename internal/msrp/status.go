package msrp

import (
	"errors"
	"strconv"
)

// Status codes of RFC 4975 §10 and of RFC 7701 §10.3, which a
// RequestHandler serving NICKNAME may return.
const (
	StatusOK                   = 200
	StatusBadRequest           = 400
	StatusForbidden            = 403
	StatusRequestTimeout       = 408
	StatusMessageTooLarge      = 413
	StatusUnsupportedMediaType = 415
	StatusOutOfBounds          = 423
	StatusNoSession            = 481
	StatusNotImplemented       = 501
	StatusSessionInUse         = 506
	StatusNicknameInvalid      = 424
	StatusNicknameInUse        = 425
)

// StatusText returns the comment this package writes for code. MSRP
// comments are free text (§9); these follow the §10 descriptions.
func StatusText(code int) string {
	switch code {
	case StatusOK:
		return "OK"
	case StatusBadRequest:
		return "Bad Request"
	case StatusForbidden:
		return "Forbidden"
	case StatusRequestTimeout:
		return "Request Timeout"
	case StatusMessageTooLarge:
		return "Message Too Large"
	case StatusUnsupportedMediaType:
		return "Unsupported Media Type"
	case StatusOutOfBounds:
		return "Parameter Out Of Bounds"
	case StatusNoSession:
		return "Session Does Not Exist"
	case StatusNotImplemented:
		return "Not Implemented"
	case StatusSessionInUse:
		return "Session Already Bound"
	case StatusNicknameInvalid:
		return "Nickname Not Valid"
	case StatusNicknameInUse:
		return "Nickname Reserved Or In Use"
	}
	return ""
}

// StatusError carries an MSRP status code as a Go error. Handlers and
// binders return one to choose the code sent to the peer; Send returns one
// when the peer stopped a message.
type StatusError struct {
	Code    int
	Comment string
}

func (e *StatusError) Error() string {
	c := e.Comment
	if c == "" {
		c = StatusText(e.Code)
	}
	return "msrp: status " + strconv.Itoa(e.Code) + " " + c
}

func statusError(code int) *StatusError {
	return &StatusError{Code: code, Comment: StatusText(code)}
}

// codeOf maps an error to the status sent to a peer, using fallback when
// the error does not name one.
func codeOf(err error, fallback int) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return fallback
}

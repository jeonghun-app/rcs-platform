package diameter

import (
	"errors"
	"fmt"
)

// Error is a Diameter-level failure with the Result-Code to answer it with.
// The decoder returns one for a message it can frame but not accept, and a
// [Handler] returns one to make the node answer with that result code instead
// of writing the answer itself.
type Error struct {
	ResultCode uint32
	// FailedAVP is the offending AVP, sent inside Failed-AVP (RFC 6733
	// §7.5). For a missing AVP it is an example of the missing AVP with a
	// minimal payload.
	FailedAVP *AVP
	// Message becomes Error-Message (§7.3). It is read by operators of the
	// other node: say what was wrong with the message, never what it
	// contained.
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("diameter: result %d: %s", e.ResultCode, e.Message)
	}
	return fmt.Sprintf("diameter: result %d", e.ResultCode)
}

// Errors returned by the peer and request API.
var (
	// ErrPeerUnavailable means the peer has no open connection, or its
	// watchdog has marked it suspect (RFC 3539 §3.4.1) and it must not be
	// given new requests.
	ErrPeerUnavailable = errors.New("diameter: peer unavailable")
	// ErrTimeout means no answer arrived within the request timeout.
	ErrTimeout = errors.New("diameter: request timed out")
	// ErrConnectionClosed means the connection closed before the answer
	// arrived. The request may or may not have been processed; a caller that
	// retries on another peer sets the T bit (RFC 6733 §5.5.4).
	ErrConnectionClosed = errors.New("diameter: connection closed")
	// ErrNodeClosed is returned after [Node.Shutdown].
	ErrNodeClosed = errors.New("diameter: node closed")
	// ErrMessageTooLarge means a message exceeds the configured size limit.
	ErrMessageTooLarge = errors.New("diameter: message exceeds the size limit")
	// ErrInvalidHeader means a message header cannot be framed (a length
	// shorter than the header), so the connection cannot continue.
	ErrInvalidHeader = errors.New("diameter: invalid message header")
)

// missingAVP builds the error for an absent required AVP. The Failed-AVP
// carries the AVP's code with a zero payload of the minimal size for its type
// (RFC 6733 §7.5).
func missingAVP(def AVPDef) *Error {
	return &Error{
		ResultCode: ResultMissingAVP,
		FailedAVP:  NewAVP(def.Code, FlagMandatory, def.VendorID, make([]byte, def.Type.minPayload())),
		Message:    "missing " + def.Name,
	}
}

// invalidAVP builds the error for an AVP whose value is unacceptable.
func invalidAVP(a *AVP, name string) *Error {
	return &Error{ResultCode: ResultInvalidAVPValue, FailedAVP: a, Message: "invalid " + name}
}

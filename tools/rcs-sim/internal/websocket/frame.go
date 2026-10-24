package websocket

import (
	"encoding/binary"
	"io"
)

// Opcodes (RFC 6455 §5.2, §11.8). The others are reserved, and a frame with
// one fails the connection.
const (
	opContinuation byte = 0x0
	// OpText and OpBinary are the data messages Read returns.
	OpText   byte = 0x1
	OpBinary byte = 0x2
	opClose  byte = 0x8
	opPing   byte = 0x9
	opPong   byte = 0xA
)

// maxControlPayload is the largest payload of a control frame (§5.5).
const maxControlPayload = 125

// header is a frame's header as a client sent it.
type header struct {
	fin    bool
	opcode byte
	length uint64
	mask   [4]byte
}

func isControl(op byte) bool { return op&0x8 != 0 }

// readHeader reads one frame header and refuses what RFC 6455 forbids of a
// client's frame. Every refusal is a *closeError with the status the
// connection is failed with.
func readHeader(r io.Reader) (header, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:2]); err != nil {
		return header{}, err
	}
	h := header{fin: b[0]&0x80 != 0, opcode: b[0] & 0x0f}
	// §5.2: RSV1-3 must be 0 unless an extension defines them, and none is
	// negotiated.
	if b[0]&0x70 != 0 {
		return header{}, protocolError("reserved bits set")
	}
	switch h.opcode {
	case opContinuation, OpText, OpBinary, opClose, opPing, opPong:
	default:
		return header{}, protocolError("reserved opcode")
	}
	// §5.1: a server must close the connection on a frame that is not
	// masked.
	if b[1]&0x80 == 0 {
		return header{}, protocolError("frame not masked")
	}
	switch n := b[1] & 0x7f; n {
	case 126:
		if _, err := io.ReadFull(r, b[:2]); err != nil {
			return header{}, unexpected(err)
		}
		h.length = uint64(binary.BigEndian.Uint16(b[:2]))
		// §5.2: the minimal number of bytes must be used for the length.
		if h.length < 126 {
			return header{}, protocolError("length not in its shortest form")
		}
	case 127:
		if _, err := io.ReadFull(r, b[:8]); err != nil {
			return header{}, unexpected(err)
		}
		h.length = binary.BigEndian.Uint64(b[:8])
		// §5.2: the most significant bit must be 0.
		if h.length>>63 != 0 {
			return header{}, protocolError("length out of range")
		}
		if h.length <= 0xffff {
			return header{}, protocolError("length not in its shortest form")
		}
	default:
		h.length = uint64(n)
	}
	// §5.5: control frames are never fragmented and carry 125 bytes at most.
	if isControl(h.opcode) && (!h.fin || h.length > maxControlPayload) {
		return header{}, protocolError("control frame fragmented or too long")
	}
	if _, err := io.ReadFull(r, h.mask[:]); err != nil {
		return header{}, unexpected(err)
	}
	return h, nil
}

// unexpected turns a clean end of input inside a frame into
// io.ErrUnexpectedEOF: only a frame boundary may end the stream cleanly.
func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// unmask applies the masking key to p in place (§5.3).
func unmask(p []byte, key [4]byte) {
	for i := range p {
		p[i] ^= key[i&3]
	}
}

// appendFrame appends a server frame to b: final, unmasked (§5.1: a server
// never masks), with the length in its shortest form.
func appendFrame(b []byte, opcode byte, payload []byte) []byte {
	b = append(b, 0x80|opcode)
	switch n := len(payload); {
	case n < 126:
		b = append(b, byte(n))
	case n <= 0xffff:
		b = append(b, 126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	return append(b, payload...)
}

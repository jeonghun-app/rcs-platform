package msrp

import "github.com/jeonghun-app/rcs-platform/internal/content"

// Body is a message body: chat content, which no fmt verb, slog record or
// JSON encoding may show (#530). It is content.Body, which cpim and
// rcs-as's store hold their content in too (#547); the name stays so that
// the relay and its callers read as before.
type Body = content.Body

// BodyOf is a Body of b, sharing b's array (content.BodyOf).
func BodyOf(b []byte) Body { return content.BodyOf(b) }

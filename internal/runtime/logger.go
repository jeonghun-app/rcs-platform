package runtime

import (
	"context"
	"io"
	"log"
	"log/slog"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// NewLogger returns the JSON-lines logger every service uses: one object per
// line on w, each carrying service and version so CloudWatch Logs Insights can
// filter one service and one release across tasks.
//
// The logger does not redact anything by itself. Identifiers go through
// internal/pii before they are logged (docs/architecture.md §8).
func NewLogger(w io.Writer, service, version string, level slog.Leveler) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h).With(slog.String("service", service), slog.String("version", version))
}

// syncWriter serialises writes so that log records and metric lines, which
// share stdout, never interleave within a line however long the line is.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// HTTPErrorLog returns the ErrorLog every http.Server of a service uses: its
// lines go to logger at Warn, with each IP address in them truncated to its
// network (pii.TruncateIPsIn). net/http writes the peer's address into some
// of them ("TLS handshake error from 203.0.113.5:51234"), and a client's
// address is personal data (#36).
func HTTPErrorLog(logger *slog.Logger) *log.Logger {
	return slog.NewLogLogger(truncatingHandler{logger.Handler()}, slog.LevelWarn)
}

// truncatingHandler truncates the IP addresses in the message of each
// record before h handles it.
type truncatingHandler struct{ h slog.Handler }

func (t truncatingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return t.h.Enabled(ctx, l)
}

func (t truncatingHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = pii.TruncateIPsIn(r.Message)
	return t.h.Handle(ctx, r)
}

func (t truncatingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return truncatingHandler{t.h.WithAttrs(as)}
}

func (t truncatingHandler) WithGroup(name string) slog.Handler {
	return truncatingHandler{t.h.WithGroup(name)}
}

package runtime

import (
	"io"
	"log/slog"
	"sync"
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

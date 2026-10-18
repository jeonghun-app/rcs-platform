package runtime

import (
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// Metrics writes CloudWatch Embedded Metric Format (EMF) lines to stdout, which
// CloudWatch extracts into metrics from the service's log group, so no metrics
// agent or client is needed (docs/architecture.md §8).
//
// The only dimension is Service, and the API has no way to add another: a
// dimension per subscriber, session or address would leak identifiers into
// CloudWatch metrics (docs/architecture.md §8) and multiply metric cost by the
// number of distinct values.
//
// Metrics is safe for concurrent use.
type Metrics struct {
	mu        sync.Mutex
	w         io.Writer
	namespace string
	service   string
	now       func() time.Time
	log       *slog.Logger
	// badName is set once an invalid name has been reported, so a hot path with
	// a bad name logs once instead of on every call.
	badName atomic.Bool
}

// NewMetrics returns a Metrics writing to w in namespace with Service=service.
// now stamps each line; log receives the one report of an invalid metric name.
func NewMetrics(w io.Writer, namespace, service string, now func() time.Time, log *slog.Logger) *Metrics {
	return &Metrics{w: w, namespace: namespace, service: service, now: now, log: log}
}

// Count records n occurrences of the event name.
func (m *Metrics) Count(name string, n int64) {
	m.emit(name, "Count", n)
}

// Timing records one duration for name, in milliseconds.
func (m *Metrics) Timing(name string, d time.Duration) {
	m.emit(name, "Milliseconds", float64(d)/float64(time.Millisecond))
}

type emfMetric struct {
	Name string `json:"Name"`
	Unit string `json:"Unit"`
}

type emfDirective struct {
	Namespace  string      `json:"Namespace"`
	Dimensions [][]string  `json:"Dimensions"`
	Metrics    []emfMetric `json:"Metrics"`
}

type emfMetadata struct {
	Timestamp         int64          `json:"Timestamp"`
	CloudWatchMetrics []emfDirective `json:"CloudWatchMetrics"`
}

func (m *Metrics) emit(name, unit string, value any) {
	if !validMetricName(name) {
		// Dropping keeps a bad name from failing the request that measured it.
		if m.badName.CompareAndSwap(false, true) {
			m.log.Error("metric dropped: invalid name", slog.String("name", pii.Redact(name)))
		}
		return
	}
	line, err := json.Marshal(map[string]any{
		"_aws": emfMetadata{
			Timestamp: m.now().UnixMilli(),
			CloudWatchMetrics: []emfDirective{{
				Namespace:  m.namespace,
				Dimensions: [][]string{{"Service"}},
				Metrics:    []emfMetric{{Name: name, Unit: unit}},
			}},
		},
		"Service": m.service,
		name:      value,
	})
	if err != nil {
		return // unreachable: every value is a string or a number
	}
	line = append(line, '\n')
	m.mu.Lock()
	defer m.mu.Unlock()
	// A failed write to stdout has nowhere better to be reported.
	_, _ = m.w.Write(line)
}

// validMetricName accepts a letter followed by up to 254 letters, digits, '.',
// '_' or '-' (EMF allows 1-255 characters), and refuses "Service", which would
// overwrite the dimension value in the same JSON object. The narrow character
// set also keeps identifiers such as "+1555…" or "sip:…" out of metric names.
func validMetricName(name string) bool {
	if len(name) == 0 || len(name) > 255 || name == "Service" {
		return false
	}
	if c := name[0]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
		return false
	}
	for i := 1; i < len(name); i++ {
		if c := name[i]; !(isAlnum(c) || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

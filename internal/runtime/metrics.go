package runtime

import (
	"cmp"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// Metrics writes CloudWatch Embedded Metric Format (EMF) lines to stdout, which
// CloudWatch extracts into metrics from the service's log group, so no metrics
// agent or client is needed (docs/architecture.md §8).
//
// Values are aggregated in memory and written by [Metrics.Flush], which the
// runtime calls every DefaultMetricsInterval and once more at shutdown: one
// line per metric per interval, however many events it counts. A line per
// event would cost a CloudWatch Logs write per SIP message on a hot path
// (#25). Counts and byte totals are exact sums. A timing is written as at
// most 100 values, the limit for one EMF metric: every value when the
// interval had 100 or fewer, otherwise 100 quantiles of the interval's
// values with the exact minimum and maximum at either end. CloudWatch's
// minimum and maximum of a busy timing are then exact and its percentiles
// right to about 1% in value and a hundredth in rank, but its SampleCount,
// Sum and Average describe the 100 values, not the interval: one slow
// outlier among many fast values weighs a hundredth of the average. Count
// events with Count where their number matters.
//
// The only dimension is Service, and the API has no way to add another: a
// dimension per subscriber, session or address would leak identifiers into
// CloudWatch metrics (docs/architecture.md §8) and multiply metric cost by the
// number of distinct values.
//
// Metrics is safe for concurrent use.
type Metrics struct {
	w         io.Writer
	namespace string
	service   string
	now       func() time.Time
	log       *slog.Logger
	// badName is set once an invalid name has been reported, so a hot path with
	// a bad name logs once instead of on every call.
	badName atomic.Bool

	mu      sync.Mutex
	sums    map[metricKey]float64
	timings map[string]*timing
	// flushing serialises Flush, so that lines of two flushes never
	// interleave and a later flush never writes before an earlier one.
	flushing sync.Mutex
}

// DefaultMetricsInterval is how often the runtime flushes metrics:
// CloudWatch's standard resolution is one minute, so flushing more often
// adds lines without adding detail.
const DefaultMetricsInterval = time.Minute

type metricKey struct{ name, unit string }

// NewMetrics returns a Metrics writing to w in namespace with Service=service.
// now stamps each flushed line; log receives the one report of an invalid
// metric name.
func NewMetrics(w io.Writer, namespace, service string, now func() time.Time, log *slog.Logger) *Metrics {
	return &Metrics{
		w: w, namespace: namespace, service: service, now: now, log: log,
		sums: map[metricKey]float64{}, timings: map[string]*timing{},
	}
}

// Count records n occurrences of the event name.
func (m *Metrics) Count(name string, n int64) {
	m.add(name, "Count", float64(n))
}

// Bytes records n octets for name, with the Bytes unit so that CloudWatch
// can show and scale them as data sizes.
func (m *Metrics) Bytes(name string, n int64) {
	m.add(name, "Bytes", float64(n))
}

// Timing records one duration for name, in milliseconds.
func (m *Metrics) Timing(name string, d time.Duration) {
	if !m.valid(name) {
		return
	}
	ms := float64(d) / float64(time.Millisecond)
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.timings[name]
	if t == nil {
		t = &timing{buckets: map[int]uint64{}}
		m.timings[name] = t
	}
	t.add(ms)
}

func (m *Metrics) add(name, unit string, v float64) {
	if !m.valid(name) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sums[metricKey{name, unit}] += v
}

func (m *Metrics) valid(name string) bool {
	if validMetricName(name) {
		return true
	}
	// Dropping keeps a bad name from failing the request that measured it.
	if m.badName.CompareAndSwap(false, true) {
		m.log.Error("metric dropped: invalid name", slog.String("name", pii.Redact(name)))
	}
	return false
}

// Flush writes one EMF line for every metric recorded since the last flush,
// in name order, and starts a new interval. The runtime calls it; a service
// does not need to.
func (m *Metrics) Flush() {
	m.flushing.Lock()
	defer m.flushing.Unlock()
	m.mu.Lock()
	sums, timings := m.sums, m.timings
	m.sums, m.timings = map[metricKey]float64{}, map[string]*timing{}
	m.mu.Unlock()

	type entry struct {
		key   metricKey
		value any
	}
	entries := make([]entry, 0, len(sums)+len(timings))
	for k, v := range sums {
		entries = append(entries, entry{k, v})
	}
	for name, t := range timings {
		entries = append(entries, entry{metricKey{name, "Milliseconds"}, t.values()})
	}
	slices.SortFunc(entries, func(a, b entry) int {
		return cmp.Or(cmp.Compare(a.key.name, b.key.name), cmp.Compare(a.key.unit, b.key.unit))
	})
	stamp := m.now().UnixMilli()
	var out []byte
	for _, e := range entries {
		line, err := json.Marshal(map[string]any{
			"_aws": emfMetadata{
				Timestamp: stamp,
				CloudWatchMetrics: []emfDirective{{
					Namespace:  m.namespace,
					Dimensions: [][]string{{"Service"}},
					Metrics:    []emfMetric{{Name: e.key.name, Unit: e.key.unit}},
				}},
			},
			"Service":  m.service,
			e.key.name: e.value,
		})
		if err != nil {
			continue // unreachable: every value is a string, a number or numbers
		}
		out = append(append(out, line...), '\n')
	}
	if len(out) > 0 {
		// One write, so the lines of a flush stay together; a failed write to
		// stdout has nowhere better to be reported.
		_, _ = m.w.Write(out)
	}
}

// emfMaxValues is the most values one EMF metric may carry; a line with more
// is dropped whole by CloudWatch.
const emfMaxValues = 100

// timingResolution is the ratio between neighbouring histogram buckets: a
// value is stored as its bucket, within 1% of it.
const timingResolution = 1.02

var logResolution = math.Log(timingResolution)

// timing is one interval's durations of a metric as a histogram of
// logarithmic buckets, so its memory is bounded by the range of the values,
// not their number: a hundred buckets span about a factor of seven, and a
// thousand from a microsecond to well over a day.
type timing struct {
	buckets  map[int]uint64
	n        uint64
	min, max float64
}

// zeroBucket holds values of zero or less, which have no logarithm.
const zeroBucket = math.MinInt

func (t *timing) add(ms float64) {
	if t.n == 0 || ms < t.min {
		t.min = ms
	}
	if t.n == 0 || ms > t.max {
		t.max = ms
	}
	t.n++
	b := zeroBucket
	if ms > 0 {
		b = int(math.Floor(math.Log(ms) / logResolution))
	}
	t.buckets[b]++
}

// values returns the values to write: one per recorded value, as its
// bucket's midpoint, when there are emfMaxValues or fewer, and otherwise
// emfMaxValues quantiles at evenly spaced ranks. The smallest and largest are
// replaced by the exact minimum and maximum.
func (t *timing) values() []float64 {
	keys := slices.Sorted(maps.Keys(t.buckets))
	count := min(t.n, emfMaxValues)
	out := make([]float64, 0, count)
	var seen uint64 // values in the buckets before keys[k]
	k := 0
	for i := range count {
		// The rank of the value to write: every one when count == n, else
		// the middle of each of count equal slices of the n values.
		rank := i
		if count < t.n {
			rank = uint64((float64(i) + 0.5) * float64(t.n) / float64(count))
		}
		for seen+t.buckets[keys[k]] <= rank {
			seen += t.buckets[keys[k]]
			k++
		}
		out = append(out, midpoint(keys[k]))
	}
	out[0], out[len(out)-1] = t.min, t.max
	return out
}

func midpoint(bucket int) float64 {
	if bucket == zeroBucket {
		return 0
	}
	return math.Exp((float64(bucket) + 0.5) * logResolution)
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

// validMetricName accepts a letter followed by up to 254 letters, digits, '.',
// '_' or '-' (EMF allows 1-255 characters), and refuses "Service", which would
// overwrite the dimension value in the same JSON object. It also refuses any
// name internal/pii would mask, such as one with a run of eight or more digits
// ("auth.fail.001010000000001"): a metric name stays in CloudWatch for 15
// months and is visible to anyone allowed to list metrics, so an identifier must
// not reach one by being appended to a name.
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
	return pii.Redact(name) == name
}

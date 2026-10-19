package runtime

import (
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var epoch = time.UnixMilli(1_760_000_000_000)

func TestCountsAreSummedIntoOneEMFLineWithOnlyTheServiceDimension(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "pcscf", func() time.Time { return epoch }, discardLogger())
	m.Count("sip.register.accepted", 1)
	m.Count("sip.register.accepted", 2)
	if buf.Len() != 0 {
		t.Fatalf("written before a flush: %s", buf.String())
	}
	m.Flush()

	recs := records(t, buf.String())
	if len(recs) != 1 {
		t.Fatalf("%d lines", len(recs))
	}
	want := map[string]any{
		"_aws": map[string]any{
			"Timestamp": float64(epoch.UnixMilli()),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  "RCS",
				"Dimensions": []any{[]any{"Service"}},
				"Metrics":    []any{map[string]any{"Name": "sip.register.accepted", "Unit": "Count"}},
			}},
		},
		"Service":               "pcscf",
		"sip.register.accepted": 3.0,
	}
	if !reflect.DeepEqual(recs[0], want) {
		t.Fatalf("line = %v\nwant   %v", recs[0], want)
	}
}

func TestTimingIsInMilliseconds(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "scscf", func() time.Time { return epoch }, discardLogger())
	m.Timing("diameter.mar.latency", 1500*time.Microsecond)
	m.Flush()
	rec := records(t, buf.String())[0]
	if v, ok := rec["diameter.mar.latency"].([]any); !ok || len(v) != 1 || v[0] != 1.5 {
		t.Fatalf("value = %v", rec["diameter.mar.latency"])
	}
	unit := rec["_aws"].(map[string]any)["CloudWatchMetrics"].([]any)[0].(map[string]any)["Metrics"].([]any)[0].(map[string]any)["Unit"]
	if unit != "Milliseconds" {
		t.Fatalf("unit = %v", unit)
	}
}

func TestBytesCarryTheBytesUnit(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "msrp-relay", func() time.Time { return epoch }, discardLogger())
	m.Bytes("BytesToClients", 4096)
	m.Flush()
	rec := records(t, buf.String())[0]
	if rec["BytesToClients"] != 4096.0 {
		t.Fatalf("value = %v", rec["BytesToClients"])
	}
	unit := rec["_aws"].(map[string]any)["CloudWatchMetrics"].([]any)[0].(map[string]any)["Metrics"].([]any)[0].(map[string]any)["Unit"]
	if unit != "Bytes" {
		t.Fatalf("unit = %v", unit)
	}
}

func TestInvalidMetricNamesAreDroppedAndReportedOnce(t *testing.T) {
	var out, logs bytes.Buffer
	log := NewLogger(&logs, "pcscf", "dev", slog.LevelInfo)
	m := NewMetrics(&out, "RCS", "pcscf", time.Now, log)
	for _, name := range []string{
		"", "Service", "_aws", "1st", "sip register", "sip:alice@example.com",
		"from.+15550100001", "a/b", "ü", strings.Repeat("n", 256),
		"auth.fail.001010000000001", "msisdn15550100001", "x.12345678",
	} {
		m.Count(name, 1)
		m.Timing(name, time.Millisecond)
	}
	m.Flush()
	if out.Len() != 0 {
		t.Fatalf("invalid names were written: %s", out.String())
	}
	if n := strings.Count(logs.String(), "metric dropped"); n != 1 {
		t.Fatalf("%d reports, want 1: %s", n, logs.String())
	}
	if strings.Contains(logs.String(), "15550100001") || strings.Contains(logs.String(), "001010000000001") {
		t.Fatalf("report leaks the identifier in the name: %s", logs.String())
	}
	// A timing's name must leave room for its companion name.count.
	m.Timing(strings.Repeat("n", 250), time.Millisecond)
	m.Timing("Service", time.Millisecond)
	m.Flush()
	if out.Len() != 0 {
		t.Fatalf("a timing without room for its companions was written: %s", out.String())
	}
	for _, name := range []string{strings.Repeat("n", 255), "sip.5xx", "http.status.1234567", "rtt.p99"} {
		out.Reset()
		m.Count(name, 1)
		m.Flush()
		if out.Len() == 0 {
			t.Errorf("valid name %q was dropped", name)
		}
	}
}

func TestLogAndMetricLinesNeverInterleave(t *testing.T) {
	var buf lockedBuffer
	out := &syncWriter{w: &buf}
	log := NewLogger(out, "rcs-as", "dev", slog.LevelInfo)
	m := NewMetrics(out, "RCS", "rcs-as", time.Now, log)
	long := strings.Repeat("x", 64<<10)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 20 {
				if i%2 == 0 {
					log.Info("long", slog.String("pad", long))
				} else {
					// Flushing as often as counting puts metric lines
					// between log lines and races Count against Flush.
					m.Count(fmt.Sprintf("m%d", j), 1)
					m.Flush()
				}
			}
		})
	}
	wg.Wait()
	m.Flush()
	logs, counted := 0, 0.0
	for _, rec := range records(t, buf.String()) {
		if rec["msg"] == "long" {
			logs++
		}
		for j := range 20 {
			if v, ok := rec[fmt.Sprintf("m%d", j)].(float64); ok {
				counted += v
			}
		}
	}
	if logs != 80 || counted != 80 {
		t.Fatalf("%d whole log lines and %v counted, want 80 and 80", logs, counted)
	}
}

func TestAFlushWithNothingRecordedWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "pcscf", func() time.Time { return epoch }, discardLogger())
	m.Flush()
	m.Count("sip.invite", 1)
	m.Flush()
	buf.Reset()
	m.Flush()
	if buf.Len() != 0 {
		t.Fatalf("an empty interval wrote %q", buf.String())
	}
}

// metricLines flushes m and returns the lines that flush wrote.
func metricLines(t *testing.T, m *Metrics, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	buf.Reset()
	m.Flush()
	return records(t, buf.String())
}

// byName indexes a flush's lines by the metric each carries.
func byName(recs []map[string]any) map[string]any {
	out := map[string]any{}
	for _, rec := range recs {
		for _, m := range rec["_aws"].(map[string]any)["CloudWatchMetrics"].([]any)[0].(map[string]any)["Metrics"].([]any) {
			name := m.(map[string]any)["Name"].(string)
			out[name] = rec[name]
		}
	}
	return out
}

func TestLogVolumeDoesNotGrowWithTheNumberOfEvents(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "pcscf", func() time.Time { return epoch }, discardLogger())
	var sizes []int
	for _, events := range []int{10, 100_000} {
		total := 0.0
		for i := range events {
			m.Count("sip.message", 1)
			m.Bytes("sip.bytes", 500)
			m.Gauge("sip.dialogs", int64(i))
			m.Timing("sip.latency", time.Duration(i%5000)*time.Millisecond)
			total += float64(i % 5000)
		}
		recs := metricLines(t, m, &buf)
		sizes = append(sizes, buf.Len())
		// sip.bytes, sip.dialogs, sip.latency and its .count and .sum,
		// sip.message.
		if len(recs) != 6 {
			t.Fatalf("%d events wrote %d lines, want 6", events, len(recs))
		}
		got := byName(recs)
		for name, want := range map[string]float64{
			"sip.bytes": float64(500 * events), "sip.message": float64(events), "sip.dialogs": float64(events - 1),
			"sip.latency.count": float64(events), "sip.latency.sum": total,
		} {
			if got[name] != want {
				t.Fatalf("%d events: %s = %v, want %v", events, name, got[name], want)
			}
		}
		if n := len(got["sip.latency"].([]any)); n != min(events, 100) {
			t.Fatalf("%d events: %d timing values", events, n)
		}
	}
	// A hundred timing values, each a float with up to 17 digits, bound the
	// size whatever the number of events.
	if sizes[1] > 4<<10 {
		t.Fatalf("a flush of 100000 events is %d bytes", sizes[1])
	}
}

func TestAGaugeIsItsLastValueNotTheSumOfItsValues(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "msrp-relay", func() time.Time { return epoch }, discardLogger())
	m.Gauge("ActiveBridges", 40)
	m.Gauge("ActiveBridges", 41)
	recs := metricLines(t, m, &buf)
	if len(recs) != 1 || recs[0]["ActiveBridges"] != 41.0 {
		t.Fatalf("lines = %v, want ActiveBridges 41", recs)
	}
	unit := recs[0]["_aws"].(map[string]any)["CloudWatchMetrics"].([]any)[0].(map[string]any)["Metrics"].([]any)[0].(map[string]any)["Unit"]
	if unit != "Count" {
		t.Fatalf("unit = %v", unit)
	}
	// An interval in which the gauge is not recorded writes nothing for it.
	if recs := metricLines(t, m, &buf); len(recs) != 0 {
		t.Fatalf("an unrecorded gauge wrote %v", recs)
	}
}

// values returns a timing line's values.
func values(t *testing.T, line any) []float64 {
	t.Helper()
	var out []float64
	for _, v := range line.([]any) {
		out = append(out, v.(float64))
	}
	return out
}

func TestABusyTimingIsWrittenAsQuantilesWithinTheExactMinimumAndMaximum(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "scscf", func() time.Time { return epoch }, discardLogger())
	const n = 10_000
	// 1 ms to 10 s in shuffled order: the order of recording does not matter.
	for i := range n {
		m.Timing("diameter.sar.latency", time.Duration((i*7919)%n+1)*time.Millisecond)
	}
	got := byName(metricLines(t, m, &buf))
	vs := values(t, got["diameter.sar.latency"])
	// EMF drops a line whose metric has more than 100 values.
	if len(vs) != 100 {
		t.Fatalf("%d values", len(vs))
	}
	// CloudWatch's Minimum and Maximum are those of all the values written.
	if slices.Min(vs) != 1 || slices.Max(vs) != n || vs[0] != 1 || vs[len(vs)-1] != n {
		t.Fatalf("values from %v to %v, ends %v and %v, want exactly 1 and %d", slices.Min(vs), slices.Max(vs), vs[0], vs[len(vs)-1], n)
	}
	for i := 1; i < len(vs)-1; i++ {
		// The value of rank r, counting from 0, is r+1 ms.
		want := math.Floor((float64(i)+0.5)*n/100) + 1
		if math.Abs(vs[i]-want) > 0.01*want {
			t.Errorf("quantile %d = %v, want %v within 1%%", i, vs[i], want)
		}
	}
	if got["diameter.sar.latency.count"] != float64(n) || got["diameter.sar.latency.sum"] != float64(n*(n+1)/2) {
		t.Fatalf("count %v and sum %v, want %d and %d", got["diameter.sar.latency.count"], got["diameter.sar.latency.sum"], n, n*(n+1)/2)
	}
}

func TestABusyTimingNeverWritesAValueOutsideItsRange(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "scscf", func() time.Time { return epoch }, discardLogger())
	// One bucket whose midpoint, 10.044 ms, lies above every value in it.
	for range 200 {
		m.Timing("t", 10*time.Millisecond)
	}
	for _, v := range values(t, byName(metricLines(t, m, &buf))["t"]) {
		if v != 10 {
			t.Fatalf("wrote %v for durations that are all 10 ms", v)
		}
	}
}

func TestQuantilesOfSubMillisecondTimingsKeepTheirValue(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "hss", func() time.Time { return epoch }, discardLogger())
	// 0.1 ms to 0.9 ms, as a Cx request served from memory takes.
	for i := range 900 {
		m.Timing("cx.mar", time.Duration(100+i%9*100)*time.Microsecond)
	}
	vs := values(t, byName(metricLines(t, m, &buf))["cx.mar"])
	for i, v := range vs {
		// Ranks 0-99 of 9 values each: the value of slice i is that of
		// rank 9i+4, which is (i/11+1)/10 ms in a sorted 100-per-value run.
		want := float64(int((float64(i)+0.5)*9)/100+1) / 10
		if math.Abs(v-want) > 0.01*want {
			t.Fatalf("quantile %d = %v, want %v within 1%%: %v", i, v, want, vs)
		}
	}
}

func TestAQuietTimingIsWrittenAsEveryValueAsRecorded(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "scscf", func() time.Time { return epoch }, discardLogger())
	recorded := []time.Duration{3 * time.Millisecond, 0, 1500 * time.Microsecond, 7250 * time.Microsecond, -time.Millisecond}
	for _, d := range recorded {
		m.Timing("t", d)
	}
	got := byName(metricLines(t, m, &buf))
	if vs := values(t, got["t"]); !slices.Equal(vs, []float64{3, 0, 1.5, 7.25, -1}) {
		t.Fatalf("values = %v, want the durations as recorded", vs)
	}
	if got["t.count"] != 5.0 || got["t.sum"] != 10.75 {
		t.Fatalf("count %v, sum %v", got["t.count"], got["t.sum"])
	}
	// Exactly 100 values are still written as recorded; 101 are not.
	for i := range 100 {
		m.Timing("t", time.Duration(i)*time.Millisecond+time.Microsecond)
	}
	if vs := values(t, byName(metricLines(t, m, &buf))["t"]); len(vs) != 100 || vs[37] != 37.001 {
		t.Fatalf("100 values written as %v", vs)
	}
}

// blockingWriter holds the first Write until released, and records every
// write that arrives while another is in progress.
type blockingWriter struct {
	entered, release chan struct{}

	mu       sync.Mutex
	writing  bool
	overlaps int
	lines    []string
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	first := len(w.lines) == 0
	if w.writing {
		w.overlaps++
	}
	w.writing = true
	w.lines = append(w.lines, string(p))
	w.mu.Unlock()
	if first {
		close(w.entered)
		<-w.release
	}
	w.mu.Lock()
	w.writing = false
	w.mu.Unlock()
	return len(p), nil
}

func TestALaterFlushWaitsForAnEarlierOneToWrite(t *testing.T) {
	w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewMetrics(w, "RCS", "pcscf", func() time.Time { return epoch }, discardLogger())
	m.Count("first", 1)
	done := make(chan struct{})
	go func() { m.Flush(); close(done) }()
	<-w.entered
	m.Count("second", 1)
	second := make(chan struct{})
	go func() { m.Flush(); close(second) }()
	// The second flush must not write while the first is writing. Nothing
	// signals that it is waiting, so it gets a moment to show it does not:
	// a correct Flush passes however long this is.
	select {
	case <-second:
		t.Fatal("a second flush finished while the first was still writing")
	case <-time.After(50 * time.Millisecond):
	}
	close(w.release)
	<-done
	<-second
	if w.overlaps != 0 || len(w.lines) != 2 || !strings.Contains(w.lines[0], `"first":1`) || !strings.Contains(w.lines[1], `"second":1`) {
		t.Fatalf("writes %q with %d overlaps", w.lines, w.overlaps)
	}
}

func TestEachFlushStartsANewInterval(t *testing.T) {
	var buf bytes.Buffer
	now := epoch
	m := NewMetrics(&buf, "RCS", "pcscf", func() time.Time { return now }, discardLogger())
	m.Count("sip.invite", 5)
	m.Timing("sip.latency", 9*time.Millisecond)
	metricLines(t, m, &buf)
	now = now.Add(DefaultMetricsInterval)
	m.Count("sip.invite", 2)
	recs := metricLines(t, m, &buf)
	if len(recs) != 1 || recs[0]["sip.invite"] != 2.0 {
		t.Fatalf("second interval = %v", recs)
	}
	if stamp := recs[0]["_aws"].(map[string]any)["Timestamp"]; stamp != float64(now.UnixMilli()) {
		t.Fatalf("timestamp %v, want the flush time %d", stamp, now.UnixMilli())
	}
}

// BenchmarkMetricsUnderLoad records a count, a byte total and a timing per
// operation from every CPU, as a hot SIP path would, and reports what one
// flush then writes: the same five lines (the timing with its .count and
// .sum) and about 2.5 KB however many operations ran. Run with
// go test -bench Metrics ./internal/runtime/.
func BenchmarkMetricsUnderLoad(b *testing.B) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "pcscf", time.Now, discardLogger())
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			m.Count("sip.message", 1)
			m.Bytes("sip.bytes", 500)
			m.Timing("sip.latency", time.Duration(i%5000)*time.Microsecond)
			i++
		}
	})
	b.StopTimer()
	m.Flush()
	b.ReportMetric(float64(bytes.Count(buf.Bytes(), []byte("\n"))), "lines/flush")
	b.ReportMetric(float64(buf.Len()), "bytes/flush")
}

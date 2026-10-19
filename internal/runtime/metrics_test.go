package runtime

import (
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"reflect"
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

func TestLogVolumeDoesNotGrowWithTheNumberOfEvents(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "pcscf", func() time.Time { return epoch }, discardLogger())
	var sizes []int
	for _, events := range []int{10, 100_000} {
		for i := range events {
			m.Count("sip.message", 1)
			m.Bytes("sip.bytes", 500)
			m.Timing("sip.latency", time.Duration(i%5000)*time.Millisecond)
		}
		recs := metricLines(t, m, &buf)
		sizes = append(sizes, buf.Len())
		if len(recs) != 3 {
			t.Fatalf("%d events wrote %d lines, want 3", events, len(recs))
		}
		// Sorted by name: sip.bytes, sip.latency, sip.message.
		if recs[0]["sip.bytes"] != float64(500*events) || recs[2]["sip.message"] != float64(events) {
			t.Fatalf("%d events: sums %v and %v", events, recs[0]["sip.bytes"], recs[2]["sip.message"])
		}
		if n := len(recs[1]["sip.latency"].([]any)); n != min(events, emfMaxValues) {
			t.Fatalf("%d events: %d timing values", events, n)
		}
	}
	// A hundred timing values, each a float with up to 17 digits, bound the
	// size whatever the number of events.
	if sizes[1] > 4<<10 {
		t.Fatalf("a flush of 100000 events is %d bytes", sizes[1])
	}
}

func TestABusyTimingIsWrittenAsQuantilesWithTheExactMinimumAndMaximum(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "scscf", func() time.Time { return epoch }, discardLogger())
	const n = 10_000
	// 1 ms to 10 s in shuffled order: the order of recording does not matter.
	for i := range n {
		m.Timing("diameter.sar.latency", time.Duration((i*7919)%n+1)*time.Millisecond)
	}
	values := metricLines(t, m, &buf)[0]["diameter.sar.latency"].([]any)
	if len(values) != emfMaxValues {
		t.Fatalf("%d values", len(values))
	}
	if values[0] != 1.0 || values[len(values)-1] != float64(n) {
		t.Fatalf("min %v, max %v, want 1 and %d", values[0], values[len(values)-1], n)
	}
	for i := 1; i < len(values)-1; i++ {
		// The value of rank r, counting from 0, is r+1 ms.
		want := math.Floor((float64(i)+0.5)*n/emfMaxValues) + 1
		if got := values[i].(float64); math.Abs(got-want) > 0.01*want {
			t.Errorf("quantile %d = %v, want %v within 1%%", i, got, want)
		}
	}
}

func TestAQuietTimingIsWrittenAsEveryValueInOrder(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "scscf", func() time.Time { return epoch }, discardLogger())
	for _, d := range []time.Duration{3 * time.Millisecond, 0, 1500 * time.Microsecond, 3 * time.Millisecond, -time.Millisecond} {
		m.Timing("t", d)
	}
	values := metricLines(t, m, &buf)[0]["t"].([]any)
	// The zero and negative durations share the bucket written as 0; the
	// ends are exact.
	want := []float64{-1, 0, 1.5, 3, 3}
	if len(values) != len(want) {
		t.Fatalf("values = %v, want %v", values, want)
	}
	for i, w := range want {
		if got := values[i].(float64); math.Abs(got-w) > 0.01*math.Abs(w) {
			t.Fatalf("values = %v, want %v within 1%%", values, want)
		}
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
// flush then writes: the same three lines and about 2 KB however many
// operations ran. Run with go test -bench Metrics ./internal/runtime/.
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

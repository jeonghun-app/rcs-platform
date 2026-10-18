package runtime

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var epoch = time.UnixMilli(1_760_000_000_000)

func TestCountWritesOneEMFLineWithOnlyTheServiceDimension(t *testing.T) {
	var buf bytes.Buffer
	m := NewMetrics(&buf, "RCS", "pcscf", func() time.Time { return epoch }, discardLogger())
	m.Count("sip.register.accepted", 3)

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
	rec := records(t, buf.String())[0]
	if rec["diameter.mar.latency"] != 1.5 {
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
					m.Count(fmt.Sprintf("m%d", j), 1)
				}
			}
		})
	}
	wg.Wait()
	if n := len(records(t, buf.String())); n != 160 {
		t.Fatalf("%d whole lines, want 160", n)
	}
}

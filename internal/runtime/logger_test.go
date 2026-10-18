package runtime

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestLogLinesAreJSONWithServiceAndVersion(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "pcscf", "v1.2.3", slog.LevelInfo)
	log.Info("hello", slog.Int("n", 1))
	rec := record(t, buf.String(), "hello")
	if rec["service"] != "pcscf" || rec["version"] != "v1.2.3" || rec["level"] != "INFO" || rec["n"] != 1.0 {
		t.Fatalf("record = %v", rec)
	}
	if _, ok := rec["time"]; !ok {
		t.Fatalf("record has no time: %v", rec)
	}
}

func TestLogLevelFiltersRecords(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "hss", "dev", slog.LevelWarn)
	log.Info("quiet")
	log.Warn("loud")
	if hasRecord(t, buf.String(), "quiet") || !hasRecord(t, buf.String(), "loud") {
		t.Fatalf("output = %s", buf.String())
	}
}

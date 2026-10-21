package runtime

import (
	"bytes"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// net/http logs a failed TLS handshake with the peer's address; through
// HTTPErrorLog the line keeps only its network, at Warn (#36).
func TestAnHTTPServersErrorLinesKeepOnlyThePeersNetwork(t *testing.T) {
	var out lockedBuffer
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = HTTPErrorLog(NewLogger(&out, "ft-server", "v1", slog.LevelInfo))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	nc, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	local := nc.LocalAddr().String()
	_, _ = io.WriteString(nc, "not a TLS record\r\n\r\n")
	_ = nc.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "TLS handshake error") {
		if time.Now().After(deadline) {
			t.Fatalf("no handshake error logged: %q", out.String())
		}
		time.Sleep(time.Millisecond)
	}
	var rec map[string]any
	for _, r := range records(t, out.String()) {
		if m, _ := r["msg"].(string); strings.Contains(m, "TLS handshake error") {
			rec = r
		}
	}
	msg, _ := rec["msg"].(string)
	if strings.Contains(out.String(), local) || strings.Contains(msg, "127.0.0.1") || !strings.Contains(msg, "from 127.0.0.0/24") ||
		rec["level"] != "WARN" || rec["service"] != "ft-server" {
		t.Errorf("logged %v (peer %s)", rec, local)
	}
}

// Every http.Server of the module logs its errors through HTTPErrorLog, so
// that none writes a peer's address whole.
func TestEveryHTTPServerUsesHTTPErrorLog(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "ErrorLog:") && !strings.Contains(line, "HTTPErrorLog(") {
				t.Errorf("%s:%d: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

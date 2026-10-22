package runtime

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
// that none writes a peer's address whole: each http.Server literal has an
// ErrorLog field that is a call of HTTPErrorLog, and so has each assignment
// to an ErrorLog (#389 reviews).
func TestEveryHTTPServerUsesHTTPErrorLog(t *testing.T) {
	isCall := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			return f.Name == "HTTPErrorLog"
		case *ast.SelectorExpr:
			return f.Sel.Name == "HTTPErrorLog"
		}
		return false
	}
	servers := 0
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
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		httpName := ""
		for _, im := range f.Imports {
			if im.Path.Value == `"net/http"` {
				httpName = "http"
				if im.Name != nil {
					httpName = im.Name.Name
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				sel, ok := n.Type.(*ast.SelectorExpr)
				if !ok || httpName == "" || sel.Sel.Name != "Server" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != httpName {
					return true
				}
				servers++
				found := false
				for _, e := range n.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "ErrorLog" {
							found = isCall(kv.Value)
						}
					}
				}
				if !found {
					t.Errorf("%s: an http.Server without ErrorLog: HTTPErrorLog(...)", fset.Position(n.Pos()))
				}
			case *ast.AssignStmt:
				for i, l := range n.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "ErrorLog" && (i >= len(n.Rhs) || !isCall(n.Rhs[i])) {
						t.Errorf("%s: ErrorLog set other than to HTTPErrorLog(...)", fset.Position(n.Pos()))
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if servers < 5 {
		t.Errorf("found %d http.Server literals, want the module's five or more", servers)
	}
}

// QA's test on #389: an IPv6 peer's port is not logged either.
func TestAnIPv6PeersPortIsDropped(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	var out lockedBuffer
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Config.ErrorLog = HTTPErrorLog(NewLogger(&out, "ft-server", "v1", slog.LevelInfo))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(nc.LocalAddr().String())
	_, _ = io.WriteString(nc, "not a TLS record\r\n\r\n")
	_ = nc.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "TLS handshake error") {
		if time.Now().After(deadline) {
			t.Fatalf("no handshake error logged: %q", out.String())
		}
		time.Sleep(time.Millisecond)
	}
	if strings.Contains(out.String(), ":"+port) || !strings.Contains(out.String(), "[::/48]") {
		t.Errorf("the peer's port %s was logged, or its network was not: %s", port, out.String())
	}
}

package sip

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/content/contenttest"
)

// A body prints as redacted under every valid fmt verb, logs as its length
// and encodes to JSON as its length: alone, in a request or response, by
// value or behind a pointer, and in a struct, slice or map that holds them
// in exported fields (#573). An unexported field holding a pointer hides it
// under %v and %+v, which print the address; the other verbs, and %p and
// %w, are go vet's to refuse (Body).
func TestABodyIsPrintedNowhere(t *testing.T) {
	const chat = "meet me at the usual place"
	req := Request{Method: "MESSAGE", URI: URI{Scheme: "sip", User: "+15550100002", Host: "ims.mnc001.mcc001.3gppnetwork.org"}, Body: Body(chat)}
	res := Response{StatusCode: 200, Reason: "OK", Body: []byte(chat)}
	holder := struct {
		Request  Request
		Response *Response
		Body     Body
		All      []Request
		Pointers []*Request
		ByName   map[string]*Response
	}{req, &res, req.Body, []Request{req}, []*Request{&req}, map[string]*Response{"r": &res}}
	contenttest.HiddenFromValidVerbs(t, chat, req.Body, &req.Body, req, &req, res, &res, holder, &holder,
		[]*Request{&req}, map[string]*Response{"r": &res})
	inner := struct {
		req *Request
		res *Response
	}{&req, &res}
	for _, verb := range []string{"%v", "%+v"} {
		if out := fmt.Sprintf(verb, inner); strings.Contains(out, chat[:12]) || strings.Contains(out, "109 101 101") {
			t.Errorf("%s of unexported pointers shows the body: %s", verb, out)
		}
	}
}

// A request and a response print as they log: method or status, the
// redacted Request-URI or the registered reason, and sizes, with no header
// value (#573).
func TestAMessagePrintsAsItLogs(t *testing.T) {
	req := Request{Method: "MESSAGE", URI: URI{Scheme: "sip", User: "+15550100002", Host: "ims.mnc001.mcc001.3gppnetwork.org"}, Body: Body("hi")}
	if err := req.Header.Add("Subject", "a secret plan"); err != nil {
		t.Fatal(err)
	}
	res := Response{StatusCode: 486, Reason: "Alice is busy"}
	for verb, want := range map[string]string{
		"%v": "MESSAGE " + req.URI.redacted() + " (1 headers, 2 body octets)",
		"%s": "MESSAGE " + req.URI.redacted() + " (1 headers, 2 body octets)",
	} {
		if got := fmt.Sprintf(verb, &req); got != want {
			t.Errorf("%s of a request = %q, want %q", verb, got, want)
		}
	}
	if got, want := fmt.Sprint(res), "486 "+loggedReason(486, "Alice is busy")+" (0 headers, 0 body octets)"; got != want {
		t.Errorf("a response prints %q, want %q", got, want)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", req, res), "secret") || strings.Contains(fmt.Sprint(res), "Alice") {
		t.Error("a header value or a custom reason was printed")
	}
}

// Format is on the pointers alone, String and GoString on both: a Format
// on a value would turn off go vet's verb check for message values, and %p
// of a value would then pass vet and print the fields (#573).
func TestTheMessagesMethodSets(t *testing.T) {
	for _, v := range []any{Request{}, Response{}} {
		value, pointer := reflect.TypeOf(v), reflect.PointerTo(reflect.TypeOf(v))
		if _, ok := value.MethodByName("Format"); ok {
			t.Errorf("%v has Format on the value", value)
		}
		if _, ok := pointer.MethodByName("Format"); !ok {
			t.Errorf("%v has no Format", pointer)
		}
		for _, name := range []string{"String", "GoString"} {
			if _, ok := value.MethodByName(name); !ok {
				t.Errorf("%v has no %s", value, name)
			}
		}
	}
}

// A body is the bytes it was made from, with no copy: code that reads and
// writes bodies as []byte is unchanged.
func TestABodyIsItsBytes(t *testing.T) {
	b := []byte("hello")
	var req Request
	req.Body = b
	if string(req.Body) != "hello" || len(req.Body) != 5 || &req.Body[0] != &b[0] {
		t.Fatalf("Body = %q", []byte(req.Body))
	}
}

// No struct in the module's code holds a request, a response or a body by
// value in an unexported field, where fmt prints it field by field without
// calling Body's Format (#573). A pointer, which fmt prints as an address
// below the top level, and an exported field are allowed.
func TestNoStructHoldsAMessageOrBodyByValueUnexported(t *testing.T) {
	root := moduleRoot(t)
	const sipPath = "github.com/jeonghun-app/rcs-platform/internal/sip"
	held := map[string]bool{"Request": true, "Response": true, "Body": true}
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		inSip := filepath.Dir(path) == filepath.Join(root, "internal", "sip")
		local := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == sipPath {
				local = "sip"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		var byValue func(ast.Expr) bool
		byValue = func(e ast.Expr) bool {
			switch e := e.(type) {
			case *ast.Ident:
				return inSip && held[e.Name]
			case *ast.SelectorExpr:
				x, ok := e.X.(*ast.Ident)
				return ok && local != "" && x.Name == local && held[e.Sel.Name]
			case *ast.ArrayType:
				return byValue(e.Elt)
			case *ast.MapType:
				return byValue(e.Key) || byValue(e.Value)
			case *ast.ParenExpr:
				return byValue(e.X)
			}
			return false // a pointer, channel or function prints as an address
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if !name.IsExported() && byValue(field.Type) {
						rel, _ := filepath.Rel(root, path)
						found = append(found, rel+":"+strconv.Itoa(fset.Position(name.Pos()).Line)+" "+name.Name)
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
	for _, f := range found {
		t.Errorf("%s holds a SIP request, response or body by value, unexported: hold a pointer, or export it", f)
	}
}

// moduleRoot is the directory of go.mod above the test's.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

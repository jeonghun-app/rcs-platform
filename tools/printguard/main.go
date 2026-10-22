// Command printguard refuses print calls that can show a SIP message's
// content (#599). sip.Body, Request and Response print as redacted, or as
// they log, wherever fmt calls their methods; fmt calls no method on a value
// it reaches through an unexported field, and prints it field by field.
// printguard type-checks the module's packages and reports each call to a
// print function (fmt's, log's, slog's and testing's) whose argument can
// reach a message:
//
//   - through an unexported field, at any depth, through structs, pointers,
//     arrays, slices, maps and generic types, a Request, Response or Body by
//     value or behind a pointer, or an interface that a *Request or
//     *Response satisfies (Message, any, ...): fmt prints it field by field;
//   - a Request or Response value with a format that is not a constant:
//     String serves only %v, %s, %q, %x and %X, and go vet cannot check the
//     verb.
//
// The walk stops at a type that has a Format method, or a String method
// with a constant format or none, while the path is all exported: fmt calls
// it. Not checked: _test.go files, files of other build tags than the
// default, a value already of an interface type at the call (its dynamic
// type is unknown), a spread []any, generic code printing a value of a
// type parameter, and printing through reflection or a function value.
//
// It loads the packages with go list -export, type-checks each of the
// module's packages from source against its dependencies' export data,
// and exits 1 if it reports anything. Run it from the module root:
//
//	go run ./tools/printguard
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// msgPkg is the package whose Request, Response and Body hold content.
const msgPkg = "github.com/jeonghun-app/rcs-platform/internal/sip"

// listed is what go list -json reports of a package.
type listed struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Export     string
	Module     *struct{ Main bool }
	Error      *struct{ Err string }
}

func main() {
	start := time.Now()
	found, checked, err := run(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "printguard:", err)
		os.Exit(2)
	}
	for _, f := range found {
		fmt.Println(f)
	}
	fmt.Fprintf(os.Stderr, "printguard: %d packages, %d findings, %v\n", checked, len(found), time.Since(start).Round(time.Millisecond))
	if len(found) > 0 {
		os.Exit(1)
	}
}

// run checks the module in dir and returns what it found, with positions
// relative to dir, and how many packages it checked.
func run(dir string) ([]Finding, int, error) {
	cmd := exec.Command("go", "list", "-export", "-deps", "-json", "./...")
	cmd.Dir = dir
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, 0, fmt.Errorf("go list: %v: %s", err, stderr.String())
	}
	exports := map[string]string{}
	var own []listed
	dec := json.NewDecoder(&out)
	for {
		var p listed
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, 0, err
		}
		if p.Error != nil {
			return nil, 0, fmt.Errorf("%s: %s", p.ImportPath, p.Error.Err)
		}
		exports[p.ImportPath] = p.Export
		if p.Module != nil && p.Module.Main {
			own = append(own, p)
		}
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exports[path]
		if !ok || file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, 0, err
	}
	var found []Finding
	for _, p := range own {
		if len(p.CgoFiles) > 0 {
			return nil, 0, fmt.Errorf("%s: cgo files are not supported", p.ImportPath)
		}
		files := make([]*ast.File, 0, len(p.GoFiles))
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, 0, err
			}
			files = append(files, f)
		}
		got, err := checkPackage(fset, imp, p.ImportPath, files)
		if err != nil {
			return nil, 0, err
		}
		for _, f := range got {
			if rel, err := filepath.Rel(root, f.Pos.Filename); err == nil {
				f.Pos.Filename = rel
			}
			found = append(found, f)
		}
	}
	return found, len(own), nil
}

// checkPackage type-checks files as the package path and returns its
// findings.
func checkPackage(fset *token.FileSet, imp types.Importer, path string, files []*ast.File) ([]Finding, error) {
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses:  map[*ast.Ident]types.Object{},
		Defs:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: imp}
	pkg, err := conf.Check(path, fset, files, info)
	if err != nil {
		return nil, fmt.Errorf("type-checking %s: %w", path, err)
	}
	c := &checker{msgPkg: msgPkg, msg: dependency(pkg, msgPkg), info: info, fset: fset}
	return c.check(files), nil
}

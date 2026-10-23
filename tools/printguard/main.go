// Command printguard refuses print calls that can show a SIP message's
// content (#599). sip.Body, Request and Response print as redacted, or as
// they log, wherever fmt calls their methods, but fmt calls a method only
// for some verbs, and none on a value it reaches through an unexported
// field: it prints that value field by field. printguard type-checks the
// module's packages and follows each argument of a call to a print
// function (fmt's, log's, slog's and testing's) as fmt's print.go does,
// for each verb that prints it, and reports the call if fmt can reach a
// message without calling the message's own methods:
//
//   - through an unexported field, at any depth, through structs, pointers,
//     arrays, slices, maps and generic types, a Request, Response or Body by
//     value or behind a pointer, or an interface that one of them satisfies
//     (Message, any, fmt.Stringer, ...);
//   - with a verb its methods do not serve: Request's and Response's String
//     serves %v, %s, %q, %x and %X of a value and GoString %#v; %p prints
//     what is not a pointer field by field, and %w what is not an error, or
//     anything outside fmt.Errorf, and then fmt calls no method below;
//   - with a format that is not a constant, which may hold any verb.
//
// A type's own method stops the walk while the path is all exported, for
// the verbs fmt calls it with: Format for every verb but %p, GoString for
// %#v, Error and String for %v, %s, %q, %x and %X, and LogValue for an
// argument of slog's. What printguard does not see is listed once, in
// internal/sip/body.go's doc.
//
// It loads the packages with go list -export, type-checks each of the
// module's packages from source against its dependencies' export data,
// and exits 1 if it reports anything, 2 if it cannot check the module or
// would check too little of it. Run it from the module:
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

// module is the module printguard checks, all of it from any directory
// in it.
const module = "github.com/jeonghun-app/rcs-platform"

// msgPkg is the package whose Request, Response and Body hold content.
const msgPkg = module + "/internal/sip"

// minPackages is fewer than the module has (81 when printguard came in):
// go list matching fewer means the module is not the one printguard was
// written for.
const minPackages = 50

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
	cmd := exec.Command("go", "list", "-export", "-deps", "-json", module+"/...")
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
	if len(own) < minPackages {
		return nil, 0, fmt.Errorf("go list matched %d packages of %s, fewer than %d", len(own), module, minPackages)
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exports[path]
		if !ok || file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
	// Without msgPkg's types the walk would match nothing, and pass.
	msg, err := imp.Import(msgPkg)
	if err != nil {
		return nil, 0, fmt.Errorf("loading %s: %w", msgPkg, err)
	}
	for _, name := range []string{"Request", "Response", "Body", "Message"} {
		if _, ok := msg.Scope().Lookup(name).(*types.TypeName); !ok {
			return nil, 0, fmt.Errorf("%s has no type %s", msgPkg, name)
		}
	}
	ifaces, err := loadPrintInterfaces(imp)
	if err != nil {
		return nil, 0, err
	}
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
		got, err := checkPackage(fset, imp, msg, ifaces, p.ImportPath, files)
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
// findings; msg is msgPkg and ifaces are fmt's and slog's interfaces, as imp
// loads them.
func checkPackage(fset *token.FileSet, imp types.Importer, msg *types.Package, ifaces printInterfaces, path string, files []*ast.File) ([]Finding, error) {
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
	c := &checker{msgPkg: msgPkg, msg: dependency(pkg, msgPkg), ifaces: ifaces, info: info, fset: fset}
	if c.msg == nil {
		c.msg = msg
	}
	return c.check(files), nil
}

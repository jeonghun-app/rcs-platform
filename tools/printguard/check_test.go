package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeImporter imports testdata/src/<path> from source, for the fake sip
// package, and the standard library through std, so the test needs neither
// the go command nor export data.
type fakeImporter struct {
	fset *token.FileSet
	std  types.Importer
	pkgs map[string]*types.Package
}

func (i *fakeImporter) Import(path string) (*types.Package, error) {
	if p, ok := i.pkgs[path]; ok {
		return p, nil
	}
	dir := filepath.Join("testdata", "src", path)
	if _, err := os.Stat(dir); err != nil {
		return i.std.Import(path)
	}
	files, err := parseDir(i.fset, dir)
	if err != nil {
		return nil, err
	}
	p, err := (&types.Config{Importer: i}).Check(path, i.fset, files, nil)
	if err != nil {
		return nil, err
	}
	i.pkgs[path] = p
	return p, nil
}

func parseDir(fset *token.FileSet, dir string) ([]*ast.File, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

var want = regexp.MustCompile(`// want "(.*)"$`)

// std imports the standard library from source, once for every test.
var std = importer.ForCompiler(token.NewFileSet(), "source", nil)

// printguard finds every shape the security review of #595 and the reviews
// of #613 named, and only those: each refused call in testdata/src/shapes
// and testdata/src/nosip has a want comment that the finding on its line
// holds, and no other line has a finding (#599).
func TestTheShapesAreFound(t *testing.T) {
	for _, name := range []string{"shapes", "nosip"} {
		t.Run(name, func(t *testing.T) {
			fset := token.NewFileSet()
			imp := &fakeImporter{fset: fset, std: std, pkgs: map[string]*types.Package{}}
			files, err := parseDir(fset, filepath.Join("testdata", "src", name))
			if err != nil {
				t.Fatal(err)
			}
			info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
			pkg, err := (&types.Config{Importer: imp}).Check(name, fset, files, info)
			if err != nil {
				t.Fatal(err)
			}
			msg := dependency(pkg, "sip")
			if dependent := msg != nil; dependent != (name != "nosip") {
				t.Fatalf("%s depends on sip: %v", name, dependent)
			}
			if msg == nil {
				if msg, err = imp.Import("sip"); err != nil {
					t.Fatal(err)
				}
			}
			ifaces, err := loadPrintInterfaces(imp)
			if err != nil {
				t.Fatal(err)
			}
			c := &checker{msgPkg: "sip", msg: msg, ifaces: ifaces, info: info, fset: fset}
			found := map[int]string{}
			for _, f := range c.check(files) {
				if prev, dup := found[f.Pos.Line]; dup {
					t.Errorf("line %d: two findings, %q and %q", f.Pos.Line, prev, f.Shape)
				}
				found[f.Pos.Line] = f.Shape
			}
			wants := map[int]string{}
			for _, f := range files {
				for _, cg := range f.Comments {
					for _, cm := range cg.List {
						if m := want.FindStringSubmatch(cm.Text); m != nil {
							wants[fset.Position(cm.Pos()).Line] = m[1]
						}
					}
				}
			}
			if len(wants) == 0 {
				t.Fatal("no want comments")
			}
			for line, w := range wants {
				if got, ok := found[line]; !ok || !strings.Contains(got, w) {
					t.Errorf("line %d: found %q, want %q", line, got, w)
				}
			}
			for line, got := range found {
				if _, ok := wants[line]; !ok {
					t.Errorf("line %d: unexpected finding %q", line, got)
				}
			}
		})
	}
}

// Every function printFuncs lists is one of the standard library's, under
// the name funcKey gives it, with a printed argument, any or ...any, at
// first and a format string before it if formatted: a misspelt key would
// leave its function unchecked.
func TestThePrintFuncsExist(t *testing.T) {
	for key, pf := range printFuncs {
		slash := strings.LastIndexByte(key, '/')
		dot := slash + 1 + strings.IndexByte(key[slash+1:], '.')
		pkg, err := std.Import(key[:dot])
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		var obj types.Object
		switch name := strings.Split(key[dot+1:], "."); len(name) {
		case 1:
			obj = pkg.Scope().Lookup(name[0])
		case 2:
			if tn, ok := pkg.Scope().Lookup(name[0]).(*types.TypeName); ok {
				obj, _, _ = types.LookupFieldOrMethod(tn.Type(), true, pkg, name[1])
			}
		}
		f, ok := obj.(*types.Func)
		if !ok {
			t.Errorf("%s: no such function", key)
			continue
		}
		if got := funcKey(f); got != key {
			t.Errorf("%s: funcKey names it %s", key, got)
		}
		params := f.Type().(*types.Signature).Params()
		if pf.first >= params.Len() {
			t.Errorf("%s: %d parameters, first printed %d", key, params.Len(), pf.first)
			continue
		}
		printed := params.At(pf.first).Type()
		if s, ok := printed.(*types.Slice); ok && f.Type().(*types.Signature).Variadic() && pf.first == params.Len()-1 {
			printed = s.Elem()
		}
		if i, ok := printed.Underlying().(*types.Interface); !ok || !i.Empty() {
			t.Errorf("%s: parameter %d is %s, not any", key, pf.first, params.At(pf.first).Type())
		}
		if pf.formatted {
			if b, ok := params.At(pf.first - 1).Type().(*types.Basic); !ok || b.Kind() != types.String {
				t.Errorf("%s: parameter %d is not a format", key, pf.first-1)
			}
		}
	}
}

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
// package, and the standard library from source too, so the test needs
// neither the go command nor export data.
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

// printguard finds every shape the security review of #595 named, and only
// those: each refused call in testdata/src/shapes has a want comment that
// the finding on its line holds, and no other line has a finding (#599).
func TestTheShapesAreFound(t *testing.T) {
	fset := token.NewFileSet()
	imp := &fakeImporter{fset: fset, std: importer.ForCompiler(fset, "source", nil), pkgs: map[string]*types.Package{}}
	files, err := parseDir(fset, filepath.Join("testdata", "src", "shapes"))
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	pkg, err := (&types.Config{Importer: imp}).Check("shapes", fset, files, info)
	if err != nil {
		t.Fatal(err)
	}
	c := &checker{msgPkg: "sip", msg: dependency(pkg, "sip"), info: info, fset: fset}
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
}

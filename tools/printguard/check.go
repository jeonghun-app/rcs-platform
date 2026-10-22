package main

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// A Finding is a print call that can show a SIP message's content: its
// position and the shape of the argument that reaches the message.
type Finding struct {
	Pos   token.Position
	Shape string
}

func (f Finding) String() string { return f.Pos.String() + ": " + f.Shape }

// checker finds the print calls of one package.
type checker struct {
	// msgPkg is the import path of the package whose Request, Response
	// and Body hold content (internal/sip).
	msgPkg string
	// msg is msgPkg as the package being checked sees it, nil if the
	// package does not depend on it.
	msg   *types.Package
	info  *types.Info
	fset  *token.FileSet
	found []Finding
}

// dependency finds the package of path among pkg's imports, at any depth.
func dependency(pkg *types.Package, path string) *types.Package {
	seen := map[*types.Package]bool{}
	var find func(*types.Package) *types.Package
	find = func(p *types.Package) *types.Package {
		if p.Path() == path {
			return p
		}
		if seen[p] {
			return nil
		}
		seen[p] = true
		for _, imp := range p.Imports() {
			if found := find(imp); found != nil {
				return found
			}
		}
		return nil
	}
	return find(pkg)
}

// heldTypes are the types of msgPkg whose values hold content.
var heldTypes = map[string]bool{"Request": true, "Response": true, "Body": true}

// check walks every call in files.
func (c *checker) check(files []*ast.File) []Finding {
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				c.call(call)
			}
			return true
		})
	}
	sort.Slice(c.found, func(i, j int) bool {
		a, b := c.found[i].Pos, c.found[j].Pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Line < b.Line
	})
	return c.found
}

// printFunc describes how a function prints its arguments: from which
// argument on, and whether the argument before those is a format.
type printFunc struct {
	first     int  // index of the first printed argument
	formatted bool // the argument at first-1 is a format
}

// printFuncs are the functions that print their arguments with fmt's rules,
// by package path and name; methods are under the receiver's type name.
var printFuncs = map[string]printFunc{
	"fmt.Print": {0, false}, "fmt.Println": {0, false}, "fmt.Printf": {1, true},
	"fmt.Sprint": {0, false}, "fmt.Sprintln": {0, false}, "fmt.Sprintf": {1, true},
	"fmt.Fprint": {1, false}, "fmt.Fprintln": {1, false}, "fmt.Fprintf": {2, true},
	"fmt.Errorf": {1, true},
	"fmt.Append": {1, false}, "fmt.Appendln": {1, false}, "fmt.Appendf": {2, true},

	"log.Print": {0, false}, "log.Println": {0, false}, "log.Printf": {1, true},
	"log.Fatal": {0, false}, "log.Fatalln": {0, false}, "log.Fatalf": {1, true},
	"log.Panic": {0, false}, "log.Panicln": {0, false}, "log.Panicf": {1, true},
	"log.Logger.Print": {0, false}, "log.Logger.Println": {0, false}, "log.Logger.Printf": {1, true},
	"log.Logger.Fatal": {0, false}, "log.Logger.Fatalln": {0, false}, "log.Logger.Fatalf": {1, true},
	"log.Logger.Panic": {0, false}, "log.Logger.Panicln": {0, false}, "log.Logger.Panicf": {1, true},

	// slog's text handler prints an argument it has no LogValuer for with
	// %+v; its JSON handler uses encoding/json, which skips unexported
	// fields, so the text handler is the one to guard against.
	"log/slog.Any": {1, false}, "log/slog.Group": {1, false},
	"log/slog.Debug": {1, false}, "log/slog.Info": {1, false}, "log/slog.Warn": {1, false}, "log/slog.Error": {1, false},
	"log/slog.DebugContext": {2, false}, "log/slog.InfoContext": {2, false},
	"log/slog.WarnContext": {2, false}, "log/slog.ErrorContext": {2, false},
	"log/slog.Log":          {3, false},
	"log/slog.Logger.Debug": {1, false}, "log/slog.Logger.Info": {1, false},
	"log/slog.Logger.Warn": {1, false}, "log/slog.Logger.Error": {1, false},
	"log/slog.Logger.DebugContext": {2, false}, "log/slog.Logger.InfoContext": {2, false},
	"log/slog.Logger.WarnContext": {2, false}, "log/slog.Logger.ErrorContext": {2, false},
	"log/slog.Logger.Log": {3, false}, "log/slog.Logger.With": {0, false},

	// testing's helpers, which the module's non-test helper packages
	// (storetest, contenttest, ...) call too.
	"testing.common.Log": {0, false}, "testing.common.Logf": {1, true},
	"testing.common.Error": {0, false}, "testing.common.Errorf": {1, true},
	"testing.common.Fatal": {0, false}, "testing.common.Fatalf": {1, true},
	"testing.common.Skip": {0, false}, "testing.common.Skipf": {1, true},
	"testing.TB.Log": {0, false}, "testing.TB.Logf": {1, true},
	"testing.TB.Error": {0, false}, "testing.TB.Errorf": {1, true},
	"testing.TB.Fatal": {0, false}, "testing.TB.Fatalf": {1, true},
	"testing.TB.Skip": {0, false}, "testing.TB.Skipf": {1, true},
}

// funcKey names the function a call calls, as printFuncs does, or "".
func (c *checker) funcKey(call *ast.CallExpr) string {
	var id *ast.Ident
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fn
	case *ast.SelectorExpr:
		id = fn.Sel
	default:
		return ""
	}
	f, ok := c.info.Uses[id].(*types.Func)
	if !ok || f.Pkg() == nil {
		return ""
	}
	sig, _ := f.Type().(*types.Signature)
	if sig != nil && sig.Recv() != nil {
		t := sig.Recv().Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if n, ok := t.(*types.Named); ok {
			return f.Pkg().Path() + "." + n.Obj().Name() + "." + f.Name()
		}
		return ""
	}
	return f.Pkg().Path() + "." + f.Name()
}

func (c *checker) call(call *ast.CallExpr) {
	pf, ok := printFuncs[c.funcKey(call)]
	if !ok || call.Ellipsis.IsValid() {
		// A spread []any holds interfaces, which show nothing statically.
		return
	}
	constantFormat := true
	if pf.formatted && pf.first > 0 && pf.first-1 < len(call.Args) {
		tv := c.info.Types[call.Args[pf.first-1]]
		constantFormat = tv.Value != nil && tv.Value.Kind() == constant.String
	}
	for _, arg := range call.Args[min(pf.first, len(call.Args)):] {
		t := c.info.TypeOf(arg)
		if t == nil {
			continue
		}
		w := walk{c: c, constantFormat: constantFormat || !pf.formatted, seen: map[seenKey]bool{}}
		if shape := w.reach(t, false, ""); shape != "" {
			c.found = append(c.found, Finding{Pos: c.fset.Position(arg.Pos()), Shape: shape})
		}
	}
}

type seenKey struct {
	t          types.Type
	unexported bool
}

// walk follows one argument's type down to the values fmt reaches.
type walk struct {
	c              *checker
	constantFormat bool
	seen           map[seenKey]bool
}

// reach reports how fmt, printing a value of type t, can show a message's
// content, or "" if it cannot. unexported says the path so far went
// through an unexported field, below which fmt calls no method; path names
// that path for the finding.
func (w *walk) reach(t types.Type, unexported bool, path string) string {
	k := seenKey{t, unexported}
	if w.seen[k] {
		return ""
	}
	w.seen[k] = true
	if name, pointer, ok := w.held(t); ok {
		switch {
		case unexported:
			return "a " + kind(name, pointer) + " in an unexported field" + at(path)
		case !pointer && name != "Body" && !w.constantFormat:
			// String serves only %v, %s, %q, %x and %X of a value, and a
			// format vet cannot read may ask for any other.
			return "a " + kind(name, pointer) + " value with a format that is not a constant" + at(path)
		}
		// Format or String, called on it, prints it as it logs.
		return ""
	}
	if !unexported && w.formats(t) {
		return ""
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return w.reach(u.Elem(), unexported, path)
	case *types.Slice:
		return w.reach(u.Elem(), unexported, path+"[]")
	case *types.Array:
		return w.reach(u.Elem(), unexported, path+"[]")
	case *types.Map:
		if s := w.reach(u.Key(), unexported, path+"[key]"); s != "" {
			return s
		}
		return w.reach(u.Elem(), unexported, path+"[]")
	case *types.Struct:
		for i := range u.NumFields() {
			f := u.Field(i)
			if s := w.reach(f.Type(), unexported || !f.Exported(), path+"."+f.Name()); s != "" {
				return s
			}
		}
	case *types.Interface:
		if unexported && w.mayHold(u) {
			return "an interface that may hold a message in an unexported field" + at(path)
		}
	}
	return ""
}

// held reports whether t is one of msgPkg's held types, or a pointer to
// one.
func (w *walk) held(t types.Type) (name string, pointer, ok bool) {
	if p, isPtr := t.(*types.Pointer); isPtr {
		t, pointer = p.Elem(), true
	}
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != w.c.msgPkg || !heldTypes[n.Obj().Name()] {
		return "", false, false
	}
	return n.Obj().Name(), pointer, true
}

// formats reports whether fmt calls a method of t's own instead of
// printing its fields: Format for any verb, String for the verbs a
// constant format can ask for, which go vet checks.
func (w *walk) formats(t types.Type) bool {
	ms := types.NewMethodSet(t)
	if ms.Lookup(nil, "Format") != nil {
		return true
	}
	return w.constantFormat && ms.Lookup(nil, "String") != nil
}

// mayHold reports whether a value of interface type i may be a message.
// A package that does not depend on msgPkg can still be handed one in an
// empty interface.
func (w *walk) mayHold(i *types.Interface) bool {
	if w.c.msg == nil {
		return i.Empty()
	}
	for _, name := range []string{"Request", "Response"} {
		if obj, ok := w.c.msg.Scope().Lookup(name).(*types.TypeName); ok {
			if types.Implements(types.NewPointer(obj.Type()), i) {
				return true
			}
		}
	}
	return false
}

func kind(name string, pointer bool) string {
	if pointer {
		return "*sip." + name
	}
	return "sip." + name
}

func at(path string) string {
	if path == "" {
		return ""
	}
	return " (" + strings.TrimPrefix(path, ".") + ")"
}

package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
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
	// msg is msgPkg as the package being checked sees it, or as the
	// importer loads it if the package does not depend on it.
	msg *types.Package
	// ifaces are fmt's and slog's interfaces, as the importer loads them.
	ifaces printInterfaces
	info   *types.Info
	fset   *token.FileSet
	found  []Finding
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
	"log/slog.Any": {1, false}, "log/slog.AnyValue": {0, false}, "log/slog.Group": {1, false},
	"log/slog.With": {0, false}, "log/slog.Record.Add": {0, false},
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
	if !ok {
		return ""
	}
	return funcKey(f)
}

// funcKey names f as printFuncs does, or "".
func funcKey(f *types.Func) string {
	if f.Pkg() == nil {
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
	key := c.funcKey(call)
	pf, ok := printFuncs[key]
	if !ok || call.Ellipsis.IsValid() {
		// A spread []any holds interfaces, which show nothing statically.
		return
	}
	args := call.Args[min(pf.first, len(call.Args)):]
	verbs := make([][]verb, len(args))
	for i := range verbs {
		verbs[i] = []verb{{r: 'v'}}
	}
	formatted := pf.formatted && pf.first > 0 && pf.first-1 < len(call.Args)
	if formatted {
		verbs = nil
		tv := c.info.Types[call.Args[pf.first-1]]
		if tv.Value != nil && tv.Value.Kind() == constant.String {
			verbs = argVerbs(constant.StringVal(tv.Value), len(args))
		}
	}
	for i, arg := range args {
		t := c.info.TypeOf(arg)
		if t == nil {
			continue
		}
		if _, isIface := t.Underlying().(*types.Interface); isIface {
			// Its dynamic type is unknown.
			continue
		}
		vs, desc := anyVerb, "a format that is not a constant"
		if verbs != nil {
			vs, desc = verbs[i], ""
		}
		for _, v := range vs {
			if v.r == 'T' {
				continue // the type's name only
			}
			d := desc
			if d == "" {
				d = v.String()
			}
			w := walk{c: c, verb: v, desc: d, wrapErrs: key == "fmt.Errorf", slog: strings.HasPrefix(key, "log/slog."), seen: map[seenKey]bool{}}
			if shape := w.reach(t, state{top: true}, ""); shape != "" {
				c.found = append(c.found, Finding{Pos: c.fset.Position(arg.Pos()), Shape: shape})
				break
			}
		}
	}
}

// A verb is a printf verb and whether it has the # flag, which matters to
// fmt only for %v and %w.
type verb struct {
	r     rune
	sharp bool
}

func (v verb) String() string {
	if v.sharp {
		return "%#" + string(v.r)
	}
	return "%" + string(v.r)
}

// anyVerb stands for a format that is not a constant: a verb of each kind
// fmt treats apart. %v, %x and %X call String and print a pointer as its
// address; %s and %q call String but refuse a pointer; %d, %b and %o print
// a pointer but call no String; %t and the rest do neither; %#v calls only
// GoString; %p prints only what is a pointer; %w prints only an error and
// only in fmt.Errorf.
var anyVerb = []verb{{r: 'v'}, {r: 's'}, {r: 'd'}, {r: 't'}, {r: 'v', sharp: true}, {r: 'p'}, {r: 'w'}, {r: 'w', sharp: true}}

// argVerbs reads format as fmt's Printf does and returns, for each of n
// arguments, the verbs that print it; one that no verb names prints with
// %v, after the output. It returns nil, to be read as any format, if fmt
// would refuse an argument index in format.
func argVerbs(format string, n int) [][]verb {
	verbs := make([][]verb, n)
	argNum := 0
	for i := 0; i < len(format); {
		if format[i] != '%' {
			i++
			continue
		}
		i++
		sharp := false
	flags:
		for ; i < len(format); i++ {
			switch format[i] {
			case '#':
				sharp = true
			case '0', '+', '-', ' ':
			default:
				break flags
			}
		}
		ok, afterIndex := true, false
		argNum, i, afterIndex, ok = argIndex(format, i, argNum, n, ok)
		if i < len(format) && format[i] == '*' {
			i, argNum, afterIndex = i+1, min(argNum+1, n), false
		} else if j := digits(format, i); j > i {
			i, ok = j, ok && !afterIndex
		}
		if i+1 < len(format) && format[i] == '.' {
			i, ok = i+1, ok && !afterIndex
			argNum, i, afterIndex, ok = argIndex(format, i, argNum, n, ok)
			if i < len(format) && format[i] == '*' {
				i, argNum, afterIndex = i+1, min(argNum+1, n), false
			} else {
				i = digits(format, i)
			}
		}
		if !afterIndex {
			argNum, i, _, ok = argIndex(format, i, argNum, n, ok)
		}
		if !ok {
			return nil
		}
		if i >= len(format) {
			break
		}
		r, size := utf8.DecodeRuneInString(format[i:])
		i += size
		if r == '%' || argNum >= n {
			continue
		}
		v := verb{r: r, sharp: sharp && (r == 'v' || r == 'w')}
		if !slices.Contains(verbs[argNum], v) {
			verbs[argNum] = append(verbs[argNum], v)
		}
		argNum++
	}
	for i := range verbs {
		if len(verbs[i]) == 0 {
			verbs[i] = []verb{{r: 'v'}}
		}
	}
	return verbs
}

// argIndex reads an explicit argument index, [n], at format[i:], as fmt's
// argNumber does; ok turns false, and stays so, for one fmt refuses.
func argIndex(format string, i, argNum, n int, ok bool) (int, int, bool, bool) {
	if i >= len(format) || format[i] != '[' {
		return argNum, i, false, ok
	}
	end := strings.IndexByte(format[i:], ']')
	if end < 0 {
		return argNum, i + 1, false, false
	}
	index, err := strconv.Atoi(format[i+1 : i+end])
	if err != nil || index < 1 || index > n {
		return argNum, i + end + 1, false, false
	}
	return index - 1, i + end + 1, true, ok
}

func digits(format string, i int) int {
	for i < len(format) && '0' <= format[i] && format[i] <= '9' {
		i++
	}
	return i
}

// state is where fmt is in printing an argument.
type state struct {
	// top is the argument itself, which fmt handles apart: %p and its
	// methods first, and a pointer to a struct, array, slice or map
	// followed, once.
	top bool
	// unexported says the path went through an unexported field, below
	// which fmt calls no method.
	unexported bool
	// erroring is fmt printing a value a verb does not suit, as
	// %!t(type=value): with %v and without calling any method, at any
	// depth.
	erroring bool
}

// walk follows one argument's type down to the values fmt reaches when it
// prints the argument with one verb.
type walk struct {
	c        *checker
	verb     verb
	desc     string // the verb, as findings name it
	wrapErrs bool   // fmt.Errorf, where %w prints an error
	slog     bool   // slog, which calls an argument's LogValue first
	seen     map[seenKey]bool
}

type seenKey struct {
	t types.Type
	s state
}

// stops is what fmt does with a value's own methods.
type stops int

const (
	printsFields stops = iota // calls none, and prints the value
	callsMethod               // calls one, which prints the value
	refusesVerb               // prints it as erroring
)

// reach reports how fmt, printing a value of type t in state s, can show a
// message's content, or "" if it cannot; path names the fields on the way
// for the finding.
func (w *walk) reach(t types.Type, s state, path string) string {
	t = types.Unalias(t)
	k := seenKey{t, s}
	if w.seen[k] {
		return ""
	}
	w.seen[k] = true
	if s.top && !s.erroring && w.verb.r == 'p' {
		if pointerLike(t) {
			return "" // its address
		}
		return w.reach(t, state{top: true, erroring: true}, path)
	}
	if name, pointer, ok := w.held(t); ok {
		what := kind(name, pointer)
		switch {
		case s.unexported:
			return "a " + what + " in an unexported field" + at(path)
		case s.erroring:
			if pointer && !s.top {
				return "" // its address
			}
		default:
			switch w.methods(t, s) {
			case callsMethod:
				return "" // it prints as redacted, or as it logs
			case refusesVerb:
				return w.reach(t, state{top: true, erroring: true}, path)
			}
		}
		if !pointer {
			what += " value"
		}
		return "a " + what + " with " + w.desc + at(path)
	}
	_, isIface := t.Underlying().(*types.Interface)
	if !s.erroring && (s.top || !s.unexported) && !isIface {
		// An interface's methods are its dynamic value's, which the
		// interface case below tries.
		switch w.methods(t, s) {
		case callsMethod:
			return ""
		case refusesVerb:
			return w.reach(t, state{top: true, erroring: true}, path)
		}
	}
	below := state{unexported: s.unexported, erroring: s.erroring}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		switch {
		case s.top:
			// fmt follows it to a struct, array, slice or map.
		case s.erroring:
			return "" // its address
		case !strings.ContainsRune("vbodxX", w.verb.r):
			// fmt refuses the verb on a pointer, and prints the pointer
			// as erroring, which follows it once.
			return w.reach(u.Elem(), state{unexported: s.unexported, erroring: true}, path)
		}
		// Below the top fmt prints only its address for these verbs;
		// following it anyway errs on the side of a finding.
		return w.reach(u.Elem(), below, path)
	case *types.Slice:
		return w.reach(u.Elem(), below, path+"[]")
	case *types.Array:
		return w.reach(u.Elem(), below, path+"[]")
	case *types.Map:
		if r := w.reach(u.Key(), below, path+"[key]"); r != "" {
			return r
		}
		return w.reach(u.Elem(), below, path+"[]")
	case *types.Struct:
		for i := range u.NumFields() {
			f := u.Field(i)
			fs := below
			fs.unexported = s.unexported || !f.Exported()
			if r := w.reach(f.Type(), fs, path+"."+f.Name()); r != "" {
				return r
			}
		}
	case *types.Interface:
		// fmt prints its dynamic value as the field's: try each message
		// type the interface can hold.
		for _, m := range w.c.held(u) {
			if r := w.reach(m, below, path); r != "" {
				return "an interface that may hold " + r
			}
		}
	}
	return ""
}

// methods reports what fmt does with t's own methods when it prints a
// value of t with w's verb: handleMethods in fmt's print.go.
func (w *walk) methods(t types.Type, s state) stops {
	is := func(i *types.Interface) bool { return types.Implements(t, i) }
	ifs := w.c.ifaces
	if w.slog && s.top && is(ifs.logValuer) {
		// slog resolves a LogValuer before it prints.
		return callsMethod
	}
	v := w.verb
	if v.r == 'w' {
		if !w.wrapErrs || !is(ifs.err) {
			return refusesVerb
		}
		v.r = 'v'
	}
	switch {
	case is(ifs.formatter):
		return callsMethod
	case v.sharp && v.r == 'v':
		if is(ifs.goStringer) {
			return callsMethod
		}
	case strings.ContainsRune("vsxXq", v.r):
		if is(ifs.err) || is(ifs.stringer) {
			return callsMethod
		}
	}
	return printsFields
}

// printInterfaces are the interfaces whose methods fmt and slog call:
// a method of the same name but another signature is not called.
type printInterfaces struct {
	formatter, stringer, goStringer, err, logValuer *types.Interface
}

// loadPrintInterfaces reads them from fmt and log/slog as imp loads them,
// so that a checked package's fmt.State is the same type.
func loadPrintInterfaces(imp types.Importer) (printInterfaces, error) {
	lookup := func(path, name string) (*types.Interface, error) {
		pkg, err := imp.Import(path)
		if err != nil {
			return nil, err
		}
		if tn, ok := pkg.Scope().Lookup(name).(*types.TypeName); ok {
			if i, ok := tn.Type().Underlying().(*types.Interface); ok {
				return i, nil
			}
		}
		return nil, fmt.Errorf("%s has no interface %s", path, name)
	}
	var p printInterfaces
	var err error
	for _, x := range []struct {
		dst        **types.Interface
		path, name string
	}{
		{&p.formatter, "fmt", "Formatter"}, {&p.stringer, "fmt", "Stringer"},
		{&p.goStringer, "fmt", "GoStringer"}, {&p.logValuer, "log/slog", "LogValuer"},
	} {
		if *x.dst, err = lookup(x.path, x.name); err != nil {
			return printInterfaces{}, err
		}
	}
	p.err = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	return p, nil
}

// pointerLike reports whether %p prints a value of t as an address.
func pointerLike(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature:
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	}
	return false
}

// held reports whether t is one of msgPkg's held types, or a pointer to
// one.
func (w *walk) held(t types.Type) (name string, pointer, ok bool) {
	if p, isPtr := t.(*types.Pointer); isPtr {
		t, pointer = types.Unalias(p.Elem()), true
	}
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != w.c.msgPkg || !heldTypes[n.Obj().Name()] {
		return "", false, false
	}
	return n.Obj().Name(), pointer, true
}

// held returns the held types, by value and behind a pointer, that a value
// of interface type i may be. A package that does not depend on msgPkg can
// still be handed one.
func (c *checker) held(i *types.Interface) []types.Type {
	var out []types.Type
	for _, name := range []string{"Request", "Response", "Body"} {
		obj, ok := c.msg.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		for _, t := range []types.Type{obj.Type(), types.NewPointer(obj.Type())} {
			if types.Implements(t, i) {
				out = append(out, t)
			}
		}
	}
	return out
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

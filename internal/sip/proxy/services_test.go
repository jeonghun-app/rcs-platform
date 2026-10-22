package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every service that builds a proxy or a transport gives it its metrics, so
// that MetricHookPanics and transport.MetricCallbackPanics, which the
// service docs say to alarm on, are written (QA of #436, #445): each
// proxy.Config and transport.Config literal outside tests sets Metrics.
func TestEveryServiceGivesItsProxyMetrics(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	found := map[string]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Config" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "proxy" && pkg.Name != "transport" {
				return true
			}
			found[pkg.Name]++
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Metrics" {
						return true
					}
				}
			}
			t.Errorf("%s: a %s.Config without Metrics", fset.Position(lit.Pos()), pkg.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found["proxy"] < 3 || found["transport"] < 3 {
		t.Fatalf("found %v Config literals, want pcscf's, icscf's and rcs-as's of each at least", found)
	}
}

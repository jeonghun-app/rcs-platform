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

// Every service that builds a proxy gives it its metrics, so that
// MetricHookPanics, which the service docs say to alarm on, is written (QA
// of #436): each proxy.Config literal outside tests sets Metrics.
func TestEveryServiceGivesItsProxyMetrics(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	found := 0
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
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "proxy" {
				return true
			}
			found++
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Metrics" {
						return true
					}
				}
			}
			t.Errorf("%s: a proxy.Config without Metrics", fset.Position(lit.Pos()))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 3 {
		t.Fatalf("found %d proxy.Config literals, want pcscf's, icscf's and rcs-as's at least", found)
	}
}

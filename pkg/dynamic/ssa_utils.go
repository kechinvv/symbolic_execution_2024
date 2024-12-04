package dynamic

import (
	"container/list"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	_ "os"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func GetSsaFromProg(dir string) *ssa.Program {
	cfg := packages.Config{
		Mode: packages.LoadAllSyntax,
	}

	initial, _ := packages.Load(&cfg, dir)

	prog, _ := ssautil.AllPackages(initial, 0)

	prog.Build()
	return prog
}

func GetSsaFromFile(file string) (*ssa.Package, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		fmt.Print(err)
		panic(err)
	}
	files := []*ast.File{f}

	pkg := types.NewPackage("tmp", "")

	prg_file, _, err := ssautil.BuildPackage(
		&types.Config{Importer: importer.Default()}, fset, pkg, files, 0)
	if err != nil {
		fmt.Print(err)
		panic(err)
	}
	return prg_file, err
}

func isPred(index int, preds []*ssa.BasicBlock) bool {
	var stack list.List
	visited := make(map[int]bool)
	for _, pred := range preds {
		stack.PushBack(pred)
	}

	for stack.Len() != 0 {
		el := stack.Front()
		v := el.Value.(*ssa.BasicBlock)
		if v.Index == index {
			return true
		}
		visited[v.Index] = true
		for _, pred := range v.Preds {
			if _, ok := visited[pred.Index]; !ok {
				stack.PushBack(pred)
			}
		}
		stack.Remove(el)
	}
	return false
}

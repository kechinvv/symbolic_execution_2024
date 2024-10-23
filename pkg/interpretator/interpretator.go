package interpretator

import (
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

func RunStatSymbolExecForFile(file_path string) {
	pkg, _ := GetSsaFromFile(file_path)
	v := NewVisitorSsa()
	v.visitPackage(pkg)
}

func RunStatSymbolExecForProgram(prg_path string) {
	prg := GetSsaFromProg(prg_path)
	v := NewVisitorSsa()
	v.visitProgram(prg)
}
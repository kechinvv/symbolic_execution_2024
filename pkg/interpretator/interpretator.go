package interpretator

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"fmt"
	

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func GetSsaFromProg(dir string) {
	cfg := packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir: dir,
	}

	initial, _ := packages.Load(&cfg, "./")

	// Create SSA packages for well-typed packages and their dependencies.
	prog, _ := ssautil.AllPackages(initial, 0)

	// Build SSA code for the whole program.
	prog.Build()

	//callGraph := cha.CallGraph(prog)

	/*
	for f, _ := range callGraph.Nodes{
		// f is of ssa.Function 
		fmt.Println("func:", f, f.Name(), f.Syntax(), f.Params)
	}*/
	for _, pkg := range prog.AllPackages() {
		pkg.Build()
		println(pkg.Pkg.Name(), " ", len(pkg.Members))
		for _, f := range pkg.Members {
			 v, ok := f.(*ssa.Function)
			 if ok {
				println(v.Name())
			}
		}
	}

}


func GetSsaFromFile(file string) {
	// Parse the source files.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		fmt.Print("ERR") // parse error
		return
	}
	files := []*ast.File{f}

	// Create the type-checker's package.
	pkg := types.NewPackage("tmp", "")

	// Type-check the package, load dependencies.
	// Create and build the SSA program.
	prg_file, _, _ := ssautil.BuildPackage(
		&types.Config{Importer: importer.Default()}, fset, pkg, files, 0)
	/* 	if err != nil {
		fmt.Print(err) // type error in some package
		return
	} */

	// Print out the package.
	prg_file.WriteTo(os.Stdout)

	v := VisitorSsa{}
	v.visitPackage(prg_file)
}



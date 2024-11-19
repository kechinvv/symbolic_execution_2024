package lab2

import (
	"fmt"
	"testing"

	_ "github.com/kechinvv/go-z3/z3"
	"github.com/kechinvv/symbolic_execution_2024/pkg/interpretator"
)

func TestGetSsaFromProg(t *testing.T) {
	interpretator.RunStatSymbolExecForFile("/home/valera/symbolic_execution_2024/...")
}

func TestGetSsaFromFile(t *testing.T) {
	interpretator.RunStatSymbolExecForFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/arrays.go")
}

func TestArrays(t *testing.T) {
	pkg, _ := interpretator.GetSsaFromFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/arrays.go")
	v := interpretator.NewIntraVisitorSsa()
	funcs := v.GetFunctions(pkg)
	for n, f := range funcs {
		println("Func:", n)
		println()
		cond, _ := v.VisitFunction(f)
		println(cond.String())
		println()
		v.S.Assert(cond)

		if sat, _ := v.S.Check(); !sat {
			fmt.Println("Unsolveable")
		} else {
			m := v.S.Model()
			println(m.String())
		}
		println("---------------")
	}

}

func TestComplex(t *testing.T) {
	pkg, _ := interpretator.GetSsaFromFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/complex.go")
	v := interpretator.NewIntraVisitorSsa()
	funcs := v.GetFunctions(pkg)
	for n, f := range funcs {
		println("Func:", n)
		println()
		cond, _ := v.VisitFunction(f)
		println(cond.String())
		println()
		v.S.Assert(cond)

		if sat, _ := v.S.Check(); !sat {
			fmt.Println("Unsolveable")
		} else {
			m := v.S.Model()
			println(m.String())
		}
		println("---------------")
	}

}

func TestNumbers(t *testing.T) {
	pkg, _ := interpretator.GetSsaFromFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/numbers.go")
	v := interpretator.NewIntraVisitorSsa()
	funcs := v.GetFunctions(pkg)
	for n, f := range funcs {
		println("Func:", n)
		println()
		cond, _ := v.VisitFunction(f)
		println(cond.String())
		println()
		v.S.Assert(cond)

		if sat, _ := v.S.Check(); !sat {
			fmt.Println("Unsolveable")
		} else {
			m := v.S.Model()
			println(m.String())
		}
		println("---------------")
	}
}


func TestPushPop(t *testing.T) {
	pkg, _ := interpretator.GetSsaFromFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/push_pop.go")
	v := interpretator.NewIntraVisitorSsa()
	funcs := v.GetFunctions(pkg)
	for n, f := range funcs {
		println("Func:", n)
		println()
		cond, _ := v.VisitFunction(f)
		println(cond.String())
		println()
		v.S.Assert(cond)

		if sat, _ := v.S.Check(); !sat {
			fmt.Println("Unsolveable")
		} else {
			m := v.S.Model()
			println(m.String())
		}
		println("---------------")
	}
}
package lab2

import (
	"fmt"
	"testing"

	"github.com/kechinvv/go-z3/z3"
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
	cond, _ := v.VisitFunction(funcs["compareElement"])
	println(cond.String())
	println()
	v.S.Assert(cond)

	if sat, _ := v.S.Check(); !sat {
		fmt.Println("Unsolveable")
	} else {
		m := v.S.Model()
		println(m.String())
		//println(m.Eval(v.Mem.Variables["index"].GetValue().(z3.BV).SGT(v.Ctx.FromInt(int64(0), v.Ctx.BVSort(64)).(z3.BV)), true).String())
		//println(m.Eval(v.Mem.Variables["t0"].GetValue().(z3.Bool).Eq(v.Ctx.FromBool(false)), true).String())

	}
	v.S.Reset()

}

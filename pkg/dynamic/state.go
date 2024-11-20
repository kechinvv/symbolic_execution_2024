package dynamic

import (
	"github.com/kechinvv/go-z3/z3"
	sym_mem "github.com/kechinvv/symbolic_execution_2024/pkg"
)

type State struct {
	S   *z3.Solver
	Ctx *z3.Context
	Mem *sym_mem.SymbolicMem

	//CallStack []...
}

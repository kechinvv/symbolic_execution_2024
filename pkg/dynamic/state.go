package dynamic

import (
	"container/list"

	"github.com/kechinvv/go-z3/z3"
	"golang.org/x/tools/go/ssa"
)

type State struct {
	//Mem *sym_mem.SymbolicMem

	Asserts    []z3.Bool
	BLockStack *list.List
}

type BlockFrame struct {
	Block      *ssa.BasicBlock
	InstrIndex int
}

func (fr *BlockFrame) IsExhausted() bool {
	return fr.InstrIndex >= len(fr.Block.Instrs)
}

func (state *State) copyState() *State {
	new_state := &State{}
	new_state.Asserts = append(make([]z3.Bool, 0, len(state.Asserts)), state.Asserts...)
	new_state.BLockStack = list.New()
	for l := state.BLockStack.Front(); l != nil; l = l.Next() {
		new_state.BLockStack.PushBack(l.Value)
	}
	return new_state
}

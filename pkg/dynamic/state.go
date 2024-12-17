package dynamic

import (
	"container/list"

	"github.com/kechinvv/go-z3/z3"
	sym_mem "github.com/kechinvv/symbolic_execution_2024/pkg"
	"golang.org/x/tools/go/ssa"
)

type State struct {
	Mem *sym_mem.SymbolicMem

	Asserts             []z3.Bool
	BLockStack          *list.List
	CurrentDepth        int
	TotalLoopIteration int
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
	new_state.TotalLoopIteration = state.TotalLoopIteration
	new_state.CurrentDepth = state.CurrentDepth

	//todo: copy mem
	new_state.Mem = state.Mem

	for l := state.BLockStack.Front(); l != nil; l = l.Next() {
		block_frame := *l.Value.(*BlockFrame)
		new_state.BLockStack.PushBack(&block_frame)
	}
	return new_state
}

func (state *State) getLastFrame() *BlockFrame {
	return state.BLockStack.Back().Value.(*BlockFrame)
}

func (state *State) dropLastFrame() {
	state.BLockStack.Remove(state.BLockStack.Back())
}

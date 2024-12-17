package dynamic

import (
	"container/list"

	"github.com/kechinvv/go-z3/z3"
	sym_mem "github.com/kechinvv/symbolic_execution_2024/pkg"
)

type Machine struct {
	Scheduler Scheduler
	States    []*State

	S   *z3.Solver
	Ctx *z3.Context
	V   *InterVisitorSsa
	ResStates    []*State
	/* 	V         Visitor */
}

func CreateMachine(scheduler_type SCH_TYPE) *Machine {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)
	s := z3.NewSolver(ctx)

	switch scheduler_type {
	case ROUND_ROBIN:
		return &Machine{&RoundRobbinScheduler{0}, []*State{}, s, ctx, &InterVisitorSsa{}, []*State{}}
	default:
		panic("not implemented")
	}
}

func (m *Machine) RunForFileFunc(file string, fun string) {
	m.States = []*State{}
	pkg, _ := GetSsaFromFile(file)

	funcs := m.V.GetFunctions(pkg)

	f, _ := funcs[fun]

	state := &State{sym_mem.NewSymbolicMemP(), []z3.Bool{}, list.New()}
	m.States = append(m.States, state)

	block_frame, _ := m.V.VisitFunction(f, m.Ctx, state.Mem)

	state.BLockStack.PushBack(block_frame)
}

func (m *Machine) HasNext() bool {
	return len(m.States) != 0
}

func (m *Machine) NextStep() {

	selected_state, i_s := m.Scheduler.GetExecuteCandidate(m.States)
	frame := selected_state.BLockStack.Back().Value.(*BlockFrame)


	assert, branches, code := m.V.visitBlock(frame, m.Ctx, selected_state.Mem)
	frame.InstrIndex++

	if frame.IsExhausted() {
		selected_state.BLockStack.Remove(selected_state.BLockStack.Back())
	}

	switch code {
	case DEFAULT:
		selected_state.Asserts = append(selected_state.Asserts, assert)
	case IF_ELSE:
		new_state := selected_state.copyState()
		m.States = append(m.States, new_state)

		selected_state.Asserts = append(selected_state.Asserts, assert)
		new_state.Asserts = append(new_state.Asserts, assert.Not())

		if branches[0].Block != nil {
			selected_state.BLockStack.PushBack(branches[0])
		}
		if branches[1].Block != nil {
			new_state.BLockStack.PushBack(branches[1])
		}
	case JUMP:
		selected_state.BLockStack.PushBack(branches[0])
	}

	//todo: if not empty
	frame = selected_state.BLockStack.Back().Value.(*BlockFrame)

	if frame.IsExhausted() {
		m.ResStates = append(m.ResStates, selected_state)
		m.States = append(m.States[:i_s], m.States[i_s+1:]...)
		return
	}

	//m.cleanAndFillSolver(selected_state.Asserts)
}

func (m *Machine) cleanAndFillSolver(asserts []z3.Bool) {
	m.S.Reset()
	for _, assert := range asserts {
		m.S.Assert(assert)
	}
}

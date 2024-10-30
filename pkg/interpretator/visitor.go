package interpretator

import (
	"container/list"
	"strconv"

	"github.com/kechinvv/go-z3/z3"
	"golang.org/x/tools/go/ssa"
)

type Visitor interface {
	visitProgram(*ssa.Program)
	visitPackage(*ssa.Package)
	visitFunction(*ssa.Function)
	visitBlock(*ssa.BasicBlock)
	visitInstruction(ssa.Instruction)

	visitAlloc(*ssa.Alloc)
	visitCall(*ssa.Call)
	visitBinOp(*ssa.BinOp)
	visitUnOp(*ssa.UnOp)
	visitChangeType(*ssa.ChangeType)
	visitConvert(*ssa.Convert)
	visitMultiConvert(*ssa.MultiConvert)
	visitChangeInterface(*ssa.ChangeInterface)
	visitSliceToArrayPointer(*ssa.SliceToArrayPointer)
	visitMakeInterface(*ssa.MakeInterface)
	visitMakeClosure(*ssa.MakeClosure)
	visitMakeMap(*ssa.MakeMap)
	visitMakeChan(*ssa.MakeChan)
	visitMakeSlice(*ssa.MakeSlice)
	visitSlice(*ssa.Slice)
	visitFieldAddr(*ssa.FieldAddr)
	visitField(*ssa.Field)
	visitIndexAddr(*ssa.IndexAddr)
	visitIndex(*ssa.Index)
	visitLookup(*ssa.Lookup)
	visitSelect(*ssa.Select)
	visitRange(*ssa.Range)
	visitNext(*ssa.Next)
	visitTypeAssert(*ssa.TypeAssert)
	visitExtract(*ssa.Extract)
	visitJump(*ssa.Jump)
	visitIf(*ssa.If)
	visitReturn(*ssa.Return)
	visitRunDefers(*ssa.RunDefers)
	visitPanic(*ssa.Panic)
	visitGo(*ssa.Go)
	visitDefer(*ssa.Defer)
	visitSend(*ssa.Send)
	visitStore(*ssa.Store)
	visitMapUpdate(*ssa.MapUpdate)
	visitDebugRef(*ssa.DebugRef)
	visitPhi(*ssa.Phi)
}

type IntraVisitorSsa struct {
	visited_blocks      map[int]bool
	ctx                 *z3.Context
	s                   *z3.Solver
	reg_aliases         map[string]string
	general_block_stack list.List
}

func NewIntraVisitorSsa() *IntraVisitorSsa {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)
	s := z3.NewSolver(ctx)
	return &IntraVisitorSsa{map[int]bool{}, ctx, s, map[string]string{}, list.List{}}
}

func (v *IntraVisitorSsa) visitProgram(pkg *ssa.Program) {
	for _, el := range pkg.AllPackages() {
		v.visitPackage(el)
	}
}

func (v *IntraVisitorSsa) visitPackage(pkg *ssa.Package) {
	for _, el := range pkg.Members {
		f, ok := el.(*ssa.Function)
		if ok {
			v.visitFunction(f)
		}
	}
}

func (v *IntraVisitorSsa) visitFunction(fn *ssa.Function) {
	println(fn.Name())
	if fn.Blocks == nil {
		println("external func")
	} else {
		v.visitBlock(fn.Blocks[0])
	}
	v.reg_aliases = make(map[string]string)
	v.visited_blocks = make(map[int]bool)
}

func (v *IntraVisitorSsa) visitBlock(block *ssa.BasicBlock) {
	if v.general_block_stack.Back() != nil && block.Index == v.general_block_stack.Back().Value.(*ssa.BasicBlock).Index {
		println("next block is general")
		return
	}
	v.visited_blocks[block.Index] = true
	for _, instr := range block.Instrs {
		v.visitInstruction(instr)
	}
	delete(v.visited_blocks, block.Index)
}

func (v *IntraVisitorSsa) visitInstruction(instr ssa.Instruction) {
	switch val_instr := instr.(type) {
	case *ssa.Alloc:
		v.visitAlloc(val_instr)
	case *ssa.Call:
		v.visitCall(val_instr)
	case *ssa.BinOp:
		v.visitBinOp(val_instr)
	case *ssa.UnOp:
		v.visitUnOp(val_instr)
	case *ssa.ChangeType:
		v.visitChangeType(val_instr)
	case *ssa.Convert:
		v.visitConvert(val_instr)
	case *ssa.MultiConvert:
		v.visitMultiConvert(val_instr)
	case *ssa.ChangeInterface:
		v.visitChangeInterface(val_instr)
	case *ssa.SliceToArrayPointer:
		v.visitSliceToArrayPointer(val_instr)
	case *ssa.MakeInterface:
		v.visitMakeInterface(val_instr)
	case *ssa.MakeClosure:
		v.visitMakeClosure(val_instr)
	case *ssa.MakeMap:
		v.visitMakeMap(val_instr)
	case *ssa.MakeChan:
		v.visitMakeChan(val_instr)
	case *ssa.MakeSlice:
		v.visitMakeSlice(val_instr)
	case *ssa.Slice:
		v.visitSlice(val_instr)
	case *ssa.FieldAddr:
		v.visitFieldAddr(val_instr)
	case *ssa.Field:
		v.visitField(val_instr)
	case *ssa.IndexAddr:
		v.visitIndexAddr(val_instr)
	case *ssa.Index:
		v.visitIndex(val_instr)
	case *ssa.Lookup:
		v.visitLookup(val_instr)
	case *ssa.Select:
		v.visitSelect(val_instr)
	case *ssa.Range:
		v.visitRange(val_instr)
	case *ssa.Next:
		v.visitNext(val_instr)
	case *ssa.TypeAssert:
		v.visitTypeAssert(val_instr)
	case *ssa.Extract:
		v.visitExtract(val_instr)
	case *ssa.Jump:
		v.visitJump(val_instr)
	case *ssa.If:
		v.visitIf(val_instr)
	case *ssa.Return:
		v.visitReturn(val_instr)
	case *ssa.RunDefers:
		v.visitRunDefers(val_instr)
	case *ssa.Panic:
		v.visitPanic(val_instr)
	case *ssa.Go:
		v.visitGo(val_instr)
	case *ssa.Defer:
		v.visitDefer(val_instr)
	case *ssa.Send:
		v.visitSend(val_instr)
	case *ssa.Store:
		v.visitStore(val_instr)
	case *ssa.MapUpdate:
		v.visitMapUpdate(val_instr)
	case *ssa.DebugRef:
		v.visitDebugRef(val_instr)
	case *ssa.Phi:
		v.visitPhi(val_instr)
	default:
		println(val_instr.String())
		panic("visit not implemented node")
	}
}

func (v *IntraVisitorSsa) visitAlloc(alloc *ssa.Alloc) {
	println(alloc.Name(), "<---", alloc.String())
}

func (v *IntraVisitorSsa) visitCall(call *ssa.Call) {
	println(call.Name(), "<---", call.String())
}

func (v *IntraVisitorSsa) visitBinOp(binop *ssa.BinOp) {
	println(binop.Name(), "<---", binop.String())
}

func (v *IntraVisitorSsa) visitUnOp(unop *ssa.UnOp) {
	println(unop.Name(), "<---", unop.String())
}

func (v *IntraVisitorSsa) visitChangeType(changeType *ssa.ChangeType) {
	println(changeType.Name(), "<---", changeType.String())
}

func (v *IntraVisitorSsa) visitConvert(convert *ssa.Convert) {
	println(convert.Name(), "<---", convert.String())
}

func (v *IntraVisitorSsa) visitMultiConvert(mconvert *ssa.MultiConvert) {
	println(mconvert.Name(), "<---", mconvert.String())
}

func (v *IntraVisitorSsa) visitChangeInterface(changeInterface *ssa.ChangeInterface) {
	println(changeInterface.String())
}

func (v *IntraVisitorSsa) visitSliceToArrayPointer(sliceAr *ssa.SliceToArrayPointer) {
	println(sliceAr.String())
}

func (v *IntraVisitorSsa) visitMakeInterface(makeInterface *ssa.MakeInterface) {
	println(makeInterface.String())
}

func (v *IntraVisitorSsa) visitMakeClosure(makeClosure *ssa.MakeClosure) {
	println(makeClosure.String())
}

func (v *IntraVisitorSsa) visitMakeMap(makeMap *ssa.MakeMap) {
	println(makeMap.String())
}

func (v *IntraVisitorSsa) visitMakeChan(makeChan *ssa.MakeChan) {
	println(makeChan.String())
}

func (v *IntraVisitorSsa) visitMakeSlice(makeSlice *ssa.MakeSlice) {
	println(makeSlice.String())
}

func (v *IntraVisitorSsa) visitSlice(slice *ssa.Slice) {
	println(slice.String())
}

func (v *IntraVisitorSsa) visitFieldAddr(fieldAddr *ssa.FieldAddr) {
	println(fieldAddr.String())
}

func (v *IntraVisitorSsa) visitField(field *ssa.Field) {
	println(field.String())
}

func (v *IntraVisitorSsa) visitIndexAddr(indexAddr *ssa.IndexAddr) {
	println(indexAddr.String())
}

func (v *IntraVisitorSsa) visitIndex(index *ssa.Index) {
	println(index.String())
}

func (v *IntraVisitorSsa) visitLookup(lookup *ssa.Lookup) {
	println(lookup.String())
}

func (v *IntraVisitorSsa) visitSelect(slct *ssa.Select) {
	println(slct.String())
}

func (v *IntraVisitorSsa) visitRange(rng *ssa.Range) {
	println(rng.String())
}

func (v *IntraVisitorSsa) visitNext(next *ssa.Next) {
	println(next.String())
}

func (v *IntraVisitorSsa) visitTypeAssert(typeAssert *ssa.TypeAssert) {
	println(typeAssert.String())
}

func (v *IntraVisitorSsa) visitExtract(extract *ssa.Extract) {
	println(extract.String())
}

func (v *IntraVisitorSsa) visitJump(jump *ssa.Jump) {
	println(jump.String(), " ", jump.Block().Index)
	jump_to := jump.Block().Succs[0].Index
	/* 	if isPred(jump_to, jump.Block().Preds) {
		println("loop")
	} else  */
	if _, ok := v.visited_blocks[jump_to]; ok { //Faster than computing
		println("loop")
	} else {
		v.visitBlock(jump.Block().Succs[0])
	}
}

func (v *IntraVisitorSsa) visitIf(if_cond *ssa.If) {
	println(if_cond.String())
	if if_cond.Block() != nil && len(if_cond.Block().Succs) == 2 {

		tblock := if_cond.Block().Succs[0]
		fblock := if_cond.Block().Succs[1]
		next := getGeneralSuccBlock(tblock, fblock)
		if next != nil {
			v.general_block_stack.PushBack(next)
		}
		v.visitBlock(tblock)
		v.visitBlock(fblock)
		//todo: fomula concatination with || for if results
		if next != nil {
			v.general_block_stack.Remove(v.general_block_stack.Back())
			println("general block:", next.Index)
			v.visitBlock(next)
		} else {
			println("nil general block")
		}
	}
}

func (v *IntraVisitorSsa) visitReturn(return_stmnt *ssa.Return) {
	println(return_stmnt.String())
}

func (v *IntraVisitorSsa) visitRunDefers(runDefers *ssa.RunDefers) {
	println(runDefers.String())
}

func (v *IntraVisitorSsa) visitPanic(panic_stmnt *ssa.Panic) {
	println(panic_stmnt.String())
}

func (v *IntraVisitorSsa) visitGo(go_stmnt *ssa.Go) {
	println(go_stmnt.String())
}

func (v *IntraVisitorSsa) visitDefer(defer_stmnt *ssa.Defer) {
	println(defer_stmnt.String())
}

func (v *IntraVisitorSsa) visitSend(send *ssa.Send) {
	println(send.String())
}

func (v *IntraVisitorSsa) visitStore(store *ssa.Store) {
	println(store.String())
}

func (v *IntraVisitorSsa) visitMapUpdate(mapUpdate *ssa.MapUpdate) {
	println(mapUpdate.String())
}

func (v *IntraVisitorSsa) visitDebugRef(debugRef *ssa.DebugRef) {
	println(debugRef.String())
}

func (v *IntraVisitorSsa) visitPhi(phi *ssa.Phi) {
	println(phi.String())
	for _, edge := range phi.Edges {
		v.reg_aliases[edge.Name()] = phi.Comment + "_" + strconv.Itoa(phi.Block().Index)
	}
}

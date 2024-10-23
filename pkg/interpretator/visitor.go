package interpretator

import (
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

type VisitorSsa struct {
	visited_blocks map[int]bool
	ctx            *z3.Context
	s              *z3.Solver
}

func NewVisitorSsa() *VisitorSsa {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)
	s := z3.NewSolver(ctx)
	return &VisitorSsa{map[int]bool{}, ctx, s}
}

func (v *VisitorSsa) visitProgram(pkg *ssa.Program) {
	for _, el := range pkg.AllPackages() {
		v.visitPackage(el)
	}
}

func (v *VisitorSsa) visitPackage(pkg *ssa.Package) {
	for _, el := range pkg.Members {
		f, ok := el.(*ssa.Function)
		if ok {
			v.visitFunction(f)
		}
	}
}

func (v *VisitorSsa) visitFunction(fn *ssa.Function) {
	println(fn.Name())
	if fn.Blocks == nil {
		println("external func")
	} else {
		v.visitBlock(fn.Blocks[0])
	}
}

func (v *VisitorSsa) visitBlock(block *ssa.BasicBlock) {
	v.visited_blocks[block.Index] = true
	for _, instr := range block.Instrs {
		v.visitInstruction(instr)
	}
	delete(v.visited_blocks, block.Index)
}

func (v *VisitorSsa) visitInstruction(instr ssa.Instruction) {
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

func (v *VisitorSsa) visitAlloc(alloc *ssa.Alloc) {
	println(alloc.Name(), "<---", alloc.String())
}

func (v *VisitorSsa) visitCall(call *ssa.Call) {
	println(call.Name(), "<---", call.String())
}

func (v *VisitorSsa) visitBinOp(binop *ssa.BinOp) {
	println(binop.Name(), "<---", binop.String())
}

func (v *VisitorSsa) visitUnOp(unop *ssa.UnOp) {
	println(unop.Name(), "<---", unop.String())
}

func (v *VisitorSsa) visitChangeType(changeType *ssa.ChangeType) {
	println(changeType.Name(), "<---", changeType.String())
}

func (v *VisitorSsa) visitConvert(convert *ssa.Convert) {
	println(convert.Name(), "<---", convert.String())
}

func (v *VisitorSsa) visitMultiConvert(mconvert *ssa.MultiConvert) {
	println(mconvert.Name(), "<---", mconvert.String())
}

func (v *VisitorSsa) visitChangeInterface(changeInterface *ssa.ChangeInterface) {
	println(changeInterface.String())
}

func (v *VisitorSsa) visitSliceToArrayPointer(sliceAr *ssa.SliceToArrayPointer) {
	println(sliceAr.String())
}

func (v *VisitorSsa) visitMakeInterface(makeInterface *ssa.MakeInterface) {
	println(makeInterface.String())
}

func (v *VisitorSsa) visitMakeClosure(makeClosure *ssa.MakeClosure) {
	println(makeClosure.String())
}

func (v *VisitorSsa) visitMakeMap(makeMap *ssa.MakeMap) {
	println(makeMap.String())
}

func (v *VisitorSsa) visitMakeChan(makeChan *ssa.MakeChan) {
	println(makeChan.String())
}

func (v *VisitorSsa) visitMakeSlice(makeSlice *ssa.MakeSlice) {
	println(makeSlice.String())
}

func (v *VisitorSsa) visitSlice(slice *ssa.Slice) {
	println(slice.String())
}

func (v *VisitorSsa) visitFieldAddr(fieldAddr *ssa.FieldAddr) {
	println(fieldAddr.String())
}

func (v *VisitorSsa) visitField(field *ssa.Field) {
	println(field.String())
}

func (v *VisitorSsa) visitIndexAddr(indexAddr *ssa.IndexAddr) {
	println(indexAddr.String())
}

func (v *VisitorSsa) visitIndex(index *ssa.Index) {
	println(index.String())
}

func (v *VisitorSsa) visitLookup(lookup *ssa.Lookup) {
	println(lookup.String())
}

func (v *VisitorSsa) visitSelect(slct *ssa.Select) {
	println(slct.String())
}

func (v *VisitorSsa) visitRange(rng *ssa.Range) {
	println(rng.String())
}

func (v *VisitorSsa) visitNext(next *ssa.Next) {
	println(next.String())
}

func (v *VisitorSsa) visitTypeAssert(typeAssert *ssa.TypeAssert) {
	println(typeAssert.String())
}

func (v *VisitorSsa) visitExtract(extract *ssa.Extract) {
	println(extract.String())
}

func (v *VisitorSsa) visitJump(jump *ssa.Jump) {
	println(jump.String())
	if _, ok := v.visited_blocks[jump.Block().Succs[0].Index]; ok {
		println("loop")
	} else {
		v.visitBlock(jump.Block().Succs[0])
	}
}

func (v *VisitorSsa) visitIf(if_cond *ssa.If) {
	println(if_cond.String())
	if if_cond.Block() != nil && len(if_cond.Block().Succs) == 2 {
		tblock := if_cond.Block().Succs[0]
		fblock := if_cond.Block().Succs[1]
		v.visitBlock(tblock)
		v.visitBlock(fblock)
	}
}

func (v *VisitorSsa) visitReturn(return_stmnt *ssa.Return) {
	println(return_stmnt.String())
}

func (v *VisitorSsa) visitRunDefers(runDefers *ssa.RunDefers) {
	println(runDefers.String())
}

func (v *VisitorSsa) visitPanic(panic_stmnt *ssa.Panic) {
	println(panic_stmnt.String())
}

func (v *VisitorSsa) visitGo(go_stmnt *ssa.Go) {
	println(go_stmnt.String())
}

func (v *VisitorSsa) visitDefer(defer_stmnt *ssa.Defer) {
	println(defer_stmnt.String())
}

func (v *VisitorSsa) visitSend(send *ssa.Send) {
	println(send.String())
}

func (v *VisitorSsa) visitStore(store *ssa.Store) {
	println(store.String())
}

func (v *VisitorSsa) visitMapUpdate(mapUpdate *ssa.MapUpdate) {
	println(mapUpdate.String())
}

func (v *VisitorSsa) visitDebugRef(debugRef *ssa.DebugRef) {
	println(debugRef.String())
}

func (v *VisitorSsa) visitPhi(phi *ssa.Phi) {
	println(phi.String())
}

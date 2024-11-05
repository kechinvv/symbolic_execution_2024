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
	visitFunction(*ssa.Function) z3.Bool
	visitBlock(*ssa.BasicBlock) z3.Bool
	visitInstruction(ssa.Instruction) z3.Bool

	visitAlloc(*ssa.Alloc) z3.Bool
	visitCall(*ssa.Call) z3.Bool
	visitBinOp(*ssa.BinOp) z3.Bool
	visitUnOp(*ssa.UnOp) z3.Bool
	visitChangeType(*ssa.ChangeType) z3.Bool
	visitConvert(*ssa.Convert) z3.Bool
	visitMultiConvert(*ssa.MultiConvert) z3.Bool
	visitChangeInterface(*ssa.ChangeInterface) z3.Bool
	visitSliceToArrayPointer(*ssa.SliceToArrayPointer) z3.Bool
	visitMakeInterface(*ssa.MakeInterface) z3.Bool
	visitMakeClosure(*ssa.MakeClosure) z3.Bool
	visitMakeMap(*ssa.MakeMap) z3.Bool
	visitMakeChan(*ssa.MakeChan) z3.Bool
	visitMakeSlice(*ssa.MakeSlice) z3.Bool
	visitSlice(*ssa.Slice) z3.Bool
	visitFieldAddr(*ssa.FieldAddr) z3.Bool
	visitField(*ssa.Field) z3.Bool
	visitIndexAddr(*ssa.IndexAddr) z3.Bool
	visitIndex(*ssa.Index) z3.Bool
	visitLookup(*ssa.Lookup) z3.Bool
	visitSelect(*ssa.Select) z3.Bool
	visitRange(*ssa.Range) z3.Bool
	visitNext(*ssa.Next) z3.Bool
	visitTypeAssert(*ssa.TypeAssert) z3.Bool
	visitExtract(*ssa.Extract) z3.Bool
	visitJump(*ssa.Jump) z3.Bool
	visitIf(*ssa.If) z3.Bool
	visitReturn(*ssa.Return) z3.Bool
	visitRunDefers(*ssa.RunDefers) z3.Bool
	visitPanic(*ssa.Panic) z3.Bool
	visitGo(*ssa.Go) z3.Bool
	visitDefer(*ssa.Defer) z3.Bool
	visitSend(*ssa.Send) z3.Bool
	visitStore(*ssa.Store) z3.Bool
	visitMapUpdate(*ssa.MapUpdate) z3.Bool
	visitDebugRef(*ssa.DebugRef) z3.Bool
	visitPhi(*ssa.Phi) z3.Bool
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

func (v *IntraVisitorSsa) visitFunction(fn *ssa.Function) z3.Bool {
	println(fn.Name())
	for _, param := range fn.Params {
		println(param.Name(), param.Type().String())
	}
	var res z3.Bool
	if fn.Blocks == nil {
		println("external func")
		res = v.ctx.BoolConst("__!stub!__")
	} else {
		res = v.visitBlock(fn.Blocks[0])
	}
	v.reg_aliases = make(map[string]string)
	v.visited_blocks = make(map[int]bool)
	return res
}

func (v *IntraVisitorSsa) visitBlock(block *ssa.BasicBlock) z3.Bool {
	if v.general_block_stack.Back() != nil && block.Index == v.general_block_stack.Back().Value.(*ssa.BasicBlock).Index {
		println("next block is general")
	}
	v.visited_blocks[block.Index] = true
	res := v.ctx.BoolConst("__!stub!__")
	for _, instr := range block.Instrs {
		res = res.And(v.visitInstruction(instr))
	}
	delete(v.visited_blocks, block.Index)
	return res
}

func (v *IntraVisitorSsa) visitInstruction(instr ssa.Instruction) z3.Bool {
	switch val_instr := instr.(type) {
	case *ssa.Alloc:
		return v.visitAlloc(val_instr)
	case *ssa.Call:
		return v.visitCall(val_instr)
	case *ssa.BinOp:
		return v.visitBinOp(val_instr)
	case *ssa.UnOp:
		return v.visitUnOp(val_instr)
	case *ssa.ChangeType:
		return v.visitChangeType(val_instr)
	case *ssa.Convert:
		return v.visitConvert(val_instr)
	case *ssa.MultiConvert:
		return v.visitMultiConvert(val_instr)
	case *ssa.ChangeInterface:
		return v.visitChangeInterface(val_instr)
	case *ssa.SliceToArrayPointer:
		return v.visitSliceToArrayPointer(val_instr)
	case *ssa.MakeInterface:
		return v.visitMakeInterface(val_instr)
	case *ssa.MakeClosure:
		return v.visitMakeClosure(val_instr)
	case *ssa.MakeMap:
		return v.visitMakeMap(val_instr)
	case *ssa.MakeChan:
		return v.visitMakeChan(val_instr)
	case *ssa.MakeSlice:
		return v.visitMakeSlice(val_instr)
	case *ssa.Slice:
		return v.visitSlice(val_instr)
	case *ssa.FieldAddr:
		return v.visitFieldAddr(val_instr)
	case *ssa.Field:
		return v.visitField(val_instr)
	case *ssa.IndexAddr:
		return v.visitIndexAddr(val_instr)
	case *ssa.Index:
		return v.visitIndex(val_instr)
	case *ssa.Lookup:
		return v.visitLookup(val_instr)
	case *ssa.Select:
		return v.visitSelect(val_instr)
	case *ssa.Range:
		return v.visitRange(val_instr)
	case *ssa.Next:
		return v.visitNext(val_instr)
	case *ssa.TypeAssert:
		return v.visitTypeAssert(val_instr)
	case *ssa.Extract:
		return v.visitExtract(val_instr)
	case *ssa.Jump:
		return v.visitJump(val_instr)
	case *ssa.If:
		return v.visitIf(val_instr)
	case *ssa.Return:
		return v.visitReturn(val_instr)
	case *ssa.RunDefers:
		return v.visitRunDefers(val_instr)
	case *ssa.Panic:
		return v.visitPanic(val_instr)
	case *ssa.Go:
		return v.visitGo(val_instr)
	case *ssa.Defer:
		return v.visitDefer(val_instr)
	case *ssa.Send:
		return v.visitSend(val_instr)
	case *ssa.Store:
		return v.visitStore(val_instr)
	case *ssa.MapUpdate:
		return v.visitMapUpdate(val_instr)
	case *ssa.DebugRef:
		return v.visitDebugRef(val_instr)
	case *ssa.Phi:
		return v.visitPhi(val_instr)
	default:
		println(val_instr.String())
		panic("visit not implemented node")
	}
}

func (v *IntraVisitorSsa) visitAlloc(alloc *ssa.Alloc) z3.Bool {
	println(alloc.Name(), "<---", alloc.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitCall(call *ssa.Call) z3.Bool {
	println(call.Name(), "<---", call.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitBinOp(binop *ssa.BinOp) z3.Bool {
	println(binop.Name(), "<---", binop.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitUnOp(unop *ssa.UnOp) z3.Bool {
	println(unop.Name(), "<---", unop.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitChangeType(changeType *ssa.ChangeType) z3.Bool {
	println(changeType.Name(), "<---", changeType.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitConvert(convert *ssa.Convert) z3.Bool {
	println(convert.Name(), "<---", convert.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMultiConvert(mconvert *ssa.MultiConvert) z3.Bool {
	println(mconvert.Name(), "<---", mconvert.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitChangeInterface(changeInterface *ssa.ChangeInterface) z3.Bool {
	println(changeInterface.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitSliceToArrayPointer(sliceAr *ssa.SliceToArrayPointer) z3.Bool {
	println(sliceAr.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMakeInterface(makeInterface *ssa.MakeInterface) z3.Bool {
	println(makeInterface.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMakeClosure(makeClosure *ssa.MakeClosure) z3.Bool {
	println(makeClosure.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMakeMap(makeMap *ssa.MakeMap) z3.Bool {
	println(makeMap.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMakeChan(makeChan *ssa.MakeChan) z3.Bool {
	println(makeChan.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMakeSlice(makeSlice *ssa.MakeSlice) z3.Bool {
	println(makeSlice.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitSlice(slice *ssa.Slice) z3.Bool {
	println(slice.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitFieldAddr(fieldAddr *ssa.FieldAddr) z3.Bool {
	println(fieldAddr.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitField(field *ssa.Field) z3.Bool {
	println(field.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitIndexAddr(indexAddr *ssa.IndexAddr) z3.Bool {
	println(indexAddr.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitIndex(index *ssa.Index) z3.Bool {
	println(index.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitLookup(lookup *ssa.Lookup) z3.Bool {
	println(lookup.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitSelect(slct *ssa.Select) z3.Bool {
	println(slct.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitRange(rng *ssa.Range) z3.Bool {
	println(rng.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitNext(next *ssa.Next) z3.Bool {
	println(next.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitTypeAssert(typeAssert *ssa.TypeAssert) z3.Bool {
	println(typeAssert.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitExtract(extract *ssa.Extract) z3.Bool {
	println(extract.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitJump(jump *ssa.Jump) z3.Bool {
	println(jump.String(), " ", jump.Block().Index)
	jump_to := jump.Block().Succs[0].Index
	/* 	if isPred(jump_to, jump.Block().Preds) {
		println("loop")
	} else  */
	if _, ok := v.visited_blocks[jump_to]; ok { //Faster than computing
		println("loop")
		return v.ctx.BoolConst("__!stub!__")
	} else {
		return v.visitBlock(jump.Block().Succs[0])
	}
}

func (v *IntraVisitorSsa) visitIf(if_cond *ssa.If) z3.Bool {
	println(if_cond.String())
	if if_cond.Block() != nil && len(if_cond.Block().Succs) == 2 {

		tblock := if_cond.Block().Succs[0]
		fblock := if_cond.Block().Succs[1]
		next := getGeneralSuccBlock(tblock, fblock)
		if next != nil {
			v.general_block_stack.PushBack(next)
		}
		if_res := v.visitBlock(tblock)
		els := v.visitBlock(fblock)

		if next != nil {
			v.general_block_stack.Remove(v.general_block_stack.Back())
			println("general block:", next.Index)
			v.visitBlock(next)
		} else {
			println("nil general block")
		}
		return if_res.Or(els)
	} else {
		println("SUCCS LEN != 2  IN COND")
		return v.ctx.BoolConst("__!stub!__")
	}
}

func (v *IntraVisitorSsa) visitReturn(return_stmnt *ssa.Return) z3.Bool {
	println(return_stmnt.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitRunDefers(runDefers *ssa.RunDefers) z3.Bool {
	println(runDefers.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitPanic(panic_stmnt *ssa.Panic) z3.Bool {
	println(panic_stmnt.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitGo(go_stmnt *ssa.Go) z3.Bool {
	println(go_stmnt.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitDefer(defer_stmnt *ssa.Defer) z3.Bool {
	println(defer_stmnt.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitSend(send *ssa.Send) z3.Bool {
	println(send.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitStore(store *ssa.Store) z3.Bool {
	println(store.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitMapUpdate(mapUpdate *ssa.MapUpdate) z3.Bool {
	println(mapUpdate.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitDebugRef(debugRef *ssa.DebugRef) z3.Bool {
	println(debugRef.String())
	return v.ctx.BoolConst("__!stub!__")
}

func (v *IntraVisitorSsa) visitPhi(phi *ssa.Phi) z3.Bool {
	println(phi.String())
	for _, edge := range phi.Edges {
		v.reg_aliases[edge.Name()] = phi.Comment + "_" + strconv.Itoa(phi.Block().Index)
	}
	return v.ctx.BoolConst("__!stub!__")
}

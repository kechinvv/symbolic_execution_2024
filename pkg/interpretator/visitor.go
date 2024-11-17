package interpretator

import (
	"container/list"
	"go/token"
	"math/bits"
	"reflect"
	"strconv"

	"github.com/kechinvv/go-z3/z3"
	sym_mem "github.com/kechinvv/symbolic_execution_2024/pkg"
	"golang.org/x/tools/go/ssa"
)

type Visitor interface {
	visitProgram(*ssa.Program)
	visitPackage(*ssa.Package)
	visitFunction(*ssa.Function) z3.Bool
	visitParameter(*ssa.Parameter)
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

	stub z3.Bool // anchor for chaining formula
	mem  sym_mem.SymbolicMem
}

func NewIntraVisitorSsa() *IntraVisitorSsa {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)
	s := z3.NewSolver(ctx)
	return &IntraVisitorSsa{map[int]bool{},
		ctx,
		s,
		map[string]string{},
		list.List{},
		ctx.BoolConst("__!stub!__"),
		sym_mem.NewSymbolicMem(),
	}
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

	//remove this
	if fn.Name() == "init" {
		return v.stub
	}

	v.mem.Variables = make(map[string]*sym_mem.SymbolicVar)
	for _, param := range fn.Params {
		v.visitParameter(param)
	}
	var res z3.Bool
	if fn.Blocks == nil {
		println("external func")
		res = v.stub
	} else {
		res = v.visitBlock(fn.Blocks[0])
	}
	v.reg_aliases = make(map[string]string)
	v.visited_blocks = make(map[int]bool)
	return res
}

func (v *IntraVisitorSsa) visitBlock(block *ssa.BasicBlock) z3.Bool {
	res := v.stub

	if v.general_block_stack.Back() != nil && block.Index == v.general_block_stack.Back().Value.(*ssa.BasicBlock).Index {
		println("next block is general")
		return res
	}
	v.visited_blocks[block.Index] = true

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

func (v *IntraVisitorSsa) parseValue(value ssa.Value) *sym_mem.SymbolicVar {
	res, ok := v.mem.Variables[value.Name()]
	if ok {
		return res
	} else {
		return v.visitValue(value)
	}
}

func (v *IntraVisitorSsa) visitValue(value ssa.Value) *sym_mem.SymbolicVar {
	switch tvalue := value.(type) {
	case *ssa.Const:
		return v.visitConst(tvalue)
	default:
		panic("todo: other value " + tvalue.String() + " " + reflect.TypeOf(tvalue).String())
	}
}

func (v *IntraVisitorSsa) visitParameter(param *ssa.Parameter) {
	println(param.Name(), param.Type().Underlying().String())
	v.mem.AddVariable(param.Name(), param.Type().String(), v.ctx)
}

func (v *IntraVisitorSsa) visitConst(const_value *ssa.Const) *sym_mem.SymbolicVar {
	str_const := const_value.Value.ExactString()
	switch const_value.Type().String() {
	case sym_mem.SORT_BOOL:
		b, err := strconv.ParseBool(str_const)
		if err != nil {
			panic("error parse bool")
		}
		return &sym_mem.SymbolicVar{v.ctx.FromBool(b), nil, false, false, false}
	case sym_mem.SORT_INT:
		b, err := strconv.Atoi(str_const)
		if err != nil {
			panic("error parse int")
		}
		return &sym_mem.SymbolicVar{v.ctx.FromInt(int64(b), v.ctx.BVSort(64)), nil, false, false, false}
	case sym_mem.SORT_UINT:
		b, err := strconv.ParseUint(str_const, 10, 64)
		if err != nil {
			panic("error parse int")
		}
		return &sym_mem.SymbolicVar{v.ctx.FromInt(int64(b), v.ctx.BVSort(bits.UintSize)), nil, false, false, false}
	case sym_mem.SORT_FLOAT32:
		b, err := strconv.ParseFloat(str_const, 32)
		if err != nil {
			panic("error parse float32")
		}
		return &sym_mem.SymbolicVar{v.ctx.FromFloat32(float32(b), v.ctx.FloatSort(8, 24)), nil, false, false, false}
	case sym_mem.SORT_FLOAT64:
		b, err := strconv.ParseFloat(str_const, 64)
		if err != nil {
			panic("error parse float64")
		}
		return &sym_mem.SymbolicVar{v.ctx.FromFloat64(b, v.ctx.FloatSort(11, 53)), nil, false, false, false}
	default:
		panic("unsupported type " + const_value.Type().String())
	}
}

func (v *IntraVisitorSsa) visitAlloc(alloc *ssa.Alloc) z3.Bool {
	println(alloc.Name(), "<---", alloc.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitCall(call *ssa.Call) z3.Bool {
	println(call.Name(), "<---", call.String())

	res := v.mem.AddVariable(call.Name(), call.Type().String(), v.ctx)

	args_len := len(call.Call.Args)
	args_types := make([]string, args_len)
	args := make([]z3.Value, args_len)
	for i, a := range call.Call.Args {
		args_types[i] = a.Type().String()
		args[i] = v.parseValue(a).GetValue()
	}

	func_decl := v.mem.GetFuncOrCreate(call.Call.Value.Name(), args_types, call.Type().String(), v.ctx)

	switch tres := res.GetValue().(type) {
	case z3.BV:
		return tres.Eq(func_decl.Apply(args...).(z3.BV))
	case z3.Float:
		return tres.Eq(func_decl.Apply(args...).(z3.Float))
	case z3.Bool:
		return tres.Eq(func_decl.Apply(args...).(z3.Bool))
	case z3.Uninterpreted:
		return tres.Eq(func_decl.Apply(args...).(z3.Uninterpreted))
	case z3.Int:
		return tres.Eq(func_decl.Apply(args...).(z3.Int))
	default:
		panic("unknown type")
	}
}

func (v *IntraVisitorSsa) visitBinOp(binop *ssa.BinOp) z3.Bool {
	println(binop.Name(), "<---", binop.String())
	x := v.parseValue(binop.X).GetValue()
	y := v.parseValue(binop.Y).GetValue()
	res := v.mem.AddVariable(binop.Name(), binop.Type().String(), v.ctx)
	res_v := res.GetValue()

	if x.Sort().Kind() != y.Sort().Kind() {
		panic("dif types in one bin op " + x.Sort().Kind().String() + " " + y.Sort().Kind().String())
	}
	switch binop.Op {
	case token.ADD:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Add(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Add(y.(z3.Float)))
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.ctx)
				imag_func := v.mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Add(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Add(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum))
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.SUB:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Sub(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Sub(y.(z3.Float)))
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.ctx)
				imag_func := v.mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Sub(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Sub(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum))
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.MUL:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Mul(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Mul(y.(z3.Float)))
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.ctx)
				imag_func := v.mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Mul(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Mul(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum))
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.QUO:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.SDiv(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Div(y.(z3.Float)))
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.ctx)
				imag_func := v.mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Div(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Div(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum))
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.REM:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).SRem(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Float).Eq(x.(z3.Float).Rem(y.(z3.Float)))
		default:
			panic("impossible op for this type")
		}
	case token.AND:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).And(y.(z3.BV)))
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).And(y.(z3.Bool)))
		default:
			panic("impossible op for this type")
		}
	case token.OR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Or(y.(z3.BV)))
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Or(y.(z3.Bool)))
		default:
			panic("impossible op for this type")
		}
	case token.XOR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Xor(y.(z3.BV)))
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Xor(y.(z3.Bool)))
		default:
			panic("impossible op for this type")
		}
	case token.SHL:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Lsh(y.(z3.BV)))
		default:
			panic("impossible op for this type")
		}
	case token.SHR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).URsh(y.(z3.BV)))
		default:
			panic("impossible op for this type")
		}
	case token.AND_NOT:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).And(y.(z3.BV).Not()))
		default:
			panic("impossible op for this type")
		}
	case token.EQL:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).Eq(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).Eq(y.(z3.Float)))
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Eq(y.(z3.Bool)))
		default:
			panic("impossible op for this type")
		}
	case token.NEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).Eq(y.(z3.BV))).Not())
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).Eq(y.(z3.Float))).Not())
		case z3.Bool:
			return res_v.(z3.Bool).Eq((x.(z3.Bool).Eq(y.(z3.Bool))).Not())
		default:
			panic("impossible op for this type")
		}
	case token.LSS:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).SLT(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).LT(y.(z3.Float)))
		default:
			panic("impossible op for this type")
		}
	case token.LEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).SLT(y.(z3.BV))).Or(x.(z3.BV).Eq(y.(z3.BV))))
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).LT(y.(z3.Float))).Or(x.(z3.Float).Eq(y.(z3.Float))))
		default:
			panic("impossible op for this type")
		}
	case token.GTR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).SGT(y.(z3.BV)))
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).GT(y.(z3.Float)))
		default:
			panic("impossible op for this type")
		}
	case token.GEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).SGT(y.(z3.BV))).Or(x.(z3.BV).Eq(y.(z3.BV))))
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).GT(y.(z3.Float))).Or(x.(z3.Float).Eq(y.(z3.Float))))
		default:
			panic("impossible op for this type")
		}
	default:
		panic("wrong bin op")
	}
}

func (v *IntraVisitorSsa) visitUnOp(unop *ssa.UnOp) z3.Bool {
	println("unop")
	println(unop.Name(), "<---", unop.String())
	x := v.parseValue(unop.X)
	res := v.mem.AddVariable(unop.Name(), unop.Type().String(), v.ctx)
	res_v := res.GetValue()
	switch unop.Op {
	case token.MUL:
		if x.IsGoPointer {
			switch res_v_t := res_v.(type) {
			case z3.BV:
				return res_v_t.Eq(x.GetValue().(z3.BV))
			case z3.Float:
				return res_v_t.Eq(x.GetValue().(z3.Float))
			case z3.Bool:
				return res_v_t.Eq(x.GetValue().(z3.Bool))
			case z3.Int:
				return res_v_t.Eq(x.GetValue().(z3.Int))
			default:
				panic("impossible op for this type")
			}
		} else {
			panic("it is not pointer")
		}
	default:
		panic("unknown op")
	}
}

func (v *IntraVisitorSsa) visitChangeType(changeType *ssa.ChangeType) z3.Bool {
	println(changeType.Name(), "<---", changeType.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitConvert(convert *ssa.Convert) z3.Bool {
	println(convert.Name(), "<---", convert.String())
	res := v.mem.AddVariable(convert.Name(), convert.Type().String(), v.ctx).GetValue()
	x := v.parseValue(convert.X).GetValue()
	switch convert.Type().String() {
	case sym_mem.SORT_FLOAT64:
		switch tval := x.(type) {
		case z3.BV:
			return res.(z3.Float).Eq(tval.IEEEToFloat(v.ctx.FloatSort(11, 53)))
		default:
			panic("unsopprted cast")
		}
	default:
		panic("unsopprted cast")
	}
}

func (v *IntraVisitorSsa) visitMultiConvert(mconvert *ssa.MultiConvert) z3.Bool {
	println(mconvert.Name(), "<---", mconvert.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitChangeInterface(changeInterface *ssa.ChangeInterface) z3.Bool {
	println(changeInterface.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitSliceToArrayPointer(sliceAr *ssa.SliceToArrayPointer) z3.Bool {
	println(sliceAr.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitMakeInterface(makeInterface *ssa.MakeInterface) z3.Bool {
	println(makeInterface.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitMakeClosure(makeClosure *ssa.MakeClosure) z3.Bool {
	println(makeClosure.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitMakeMap(makeMap *ssa.MakeMap) z3.Bool {
	println(makeMap.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitMakeChan(makeChan *ssa.MakeChan) z3.Bool {
	println(makeChan.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitMakeSlice(makeSlice *ssa.MakeSlice) z3.Bool {
	println(makeSlice.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitSlice(slice *ssa.Slice) z3.Bool {
	println(slice.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitFieldAddr(fieldAddr *ssa.FieldAddr) z3.Bool {
	println("fieldAddr", fieldAddr.Name(), "<---", fieldAddr.String())

	res := v.mem.AddVariable(fieldAddr.Name(), fieldAddr.Type().String(), v.ctx)
	x := v.parseValue(fieldAddr.X)

	res_v := res.GetValue()

	field, ok := x.Sort.Fields[fieldAddr.Field]
	if !ok {
		field = x.Sort.AddField(fieldAddr.Field, fieldAddr.Type().String()[1:], v.ctx)
	}

	field_value := field.Array.Select(x.Value)

	switch arr_el_t := field_value.(type) {
	case z3.BV:
		return res_v.(z3.BV).Eq(arr_el_t)
	case z3.Float:
		return res_v.(z3.Float).Eq(arr_el_t)
	case z3.Bool:
		return res_v.(z3.Bool).Eq(arr_el_t)
	case z3.Int:
		return res_v.(z3.Int).Eq(arr_el_t)
	default:
		panic("unsupported op " + reflect.TypeOf(arr_el_t).String())
	}
}

func (v *IntraVisitorSsa) visitField(field *ssa.Field) z3.Bool {
	println("field", field.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitIndexAddr(indexAddr *ssa.IndexAddr) z3.Bool {
	println(indexAddr.Name(), "<---", indexAddr.String())

	index := v.parseValue(indexAddr.Index).GetValue()
	array := v.parseValue(indexAddr.X)

	res := v.mem.AddVariable(indexAddr.Name(), indexAddr.Type().String(), v.ctx)
	res_v := res.GetValue()
	arr_el := array.Sort.Values.Select(array.Value).(z3.Array).Select(index)
	switch arr_el_t := arr_el.(type) {
	case z3.BV:
		return res_v.(z3.BV).Eq(arr_el_t)
	case z3.Float:
		return res_v.(z3.Float).Eq(arr_el_t)
	case z3.Bool:
		return res_v.(z3.Bool).Eq(arr_el_t)
	case z3.Int:
		return res_v.(z3.Int).Eq(arr_el_t)
	default:
		panic("unsupported op " + reflect.TypeOf(arr_el_t).String())
	}
}

func (v *IntraVisitorSsa) visitIndex(index *ssa.Index) z3.Bool {
	println("index", index.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitLookup(lookup *ssa.Lookup) z3.Bool {
	println("lookup", lookup.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitSelect(slct *ssa.Select) z3.Bool {
	println("select", slct.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitRange(rng *ssa.Range) z3.Bool {
	println(rng.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitNext(next *ssa.Next) z3.Bool {
	println(next.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitTypeAssert(typeAssert *ssa.TypeAssert) z3.Bool {
	println(typeAssert.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitExtract(extract *ssa.Extract) z3.Bool {
	println("extract", extract.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitJump(jump *ssa.Jump) z3.Bool {
	println(jump.String(), " ", jump.Block().Index)
	jump_to := jump.Block().Succs[0].Index
	/* 	if isPred(jump_to, jump.Block().Preds) {
		println("loop")
	} else  */
	if _, ok := v.visited_blocks[jump_to]; ok { //Faster than computing
		println("loop")
		return v.stub
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
		return v.stub
	}
}

func (v *IntraVisitorSsa) visitReturn(return_stmnt *ssa.Return) z3.Bool {
	println(return_stmnt.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitRunDefers(runDefers *ssa.RunDefers) z3.Bool {
	println(runDefers.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitPanic(panic_stmnt *ssa.Panic) z3.Bool {
	println(panic_stmnt.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitGo(go_stmnt *ssa.Go) z3.Bool {
	println(go_stmnt.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitDefer(defer_stmnt *ssa.Defer) z3.Bool {
	println(defer_stmnt.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitSend(send *ssa.Send) z3.Bool {
	println(send.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitStore(store *ssa.Store) z3.Bool {
	println("store", store.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitMapUpdate(mapUpdate *ssa.MapUpdate) z3.Bool {
	println(mapUpdate.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitDebugRef(debugRef *ssa.DebugRef) z3.Bool {
	println(debugRef.String())
	return v.stub
}

func (v *IntraVisitorSsa) visitPhi(phi *ssa.Phi) z3.Bool {
	println(phi.Name())
	println(phi.Type().String())
	println(phi.String())

	res := v.mem.AddVariable(phi.Name(), phi.Type().String(), v.ctx).GetValue()

	constr := v.stub

	switch tres := res.(type) {
	case z3.Float:
		if len(phi.Edges) != 0 {
			constr = tres.Eq(v.mem.Variables[phi.Edges[0].Name()].GetValue().(z3.Float))
			for i, edge := range phi.Edges {
				if i == 0 {
					continue
				}
				constr = constr.Or(tres.Eq(v.mem.Variables[edge.Name()].GetValue().(z3.Float)))
			}
		}

	case z3.BV:
		if len(phi.Edges) != 0 {
			constr = tres.Eq(v.mem.Variables[phi.Edges[0].Name()].GetValue().(z3.BV))
		}
		for i, edge := range phi.Edges {
			if i == 0 {
				continue
			}
			constr = constr.Or(tres.Eq(v.mem.Variables[edge.Name()].GetValue().(z3.BV)))
		}
	case z3.Bool:
		if len(phi.Edges) != 0 {
			constr = tres.Eq(v.mem.Variables[phi.Edges[0].Name()].GetValue().(z3.Bool))
		}
		for i, edge := range phi.Edges {
			if i == 0 {
				continue
			}
			constr = constr.Or(tres.Eq(v.mem.Variables[edge.Name()].GetValue().(z3.Bool)))
		}
	default:
		panic("unsupported phi type " + tres.String())
	}

	return constr
}

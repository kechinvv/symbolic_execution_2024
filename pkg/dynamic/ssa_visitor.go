package dynamic

import (
	"errors"
	"go/token"
	"math/bits"
	"reflect"
	"strconv"

	"github.com/kechinvv/go-z3/z3"
	sym_mem "github.com/kechinvv/symbolic_execution_2024/pkg"
	"golang.org/x/tools/go/ssa"
)

/* type Visitor interface {
	GetFunctions(*ssa.Package) map[string]*ssa.Function

	visitProgram(*ssa.Program)
	visitPackage(*ssa.Package)
	VisitFunction(*ssa.Function) (z3.Bool, error)
	visitParameter(*ssa.Parameter)
	visitBlock(*ssa.BasicBlock) (z3.Bool, error)
	visitInstruction(ssa.Instruction) (z3.Bool, error)

	visitAlloc(*ssa.Alloc) (z3.Bool, error)
	visitCall(*ssa.Call) (z3.Bool, error)
	visitBinOp(*ssa.BinOp) (z3.Bool, error)
	visitUnOp(*ssa.UnOp) (z3.Bool, error)
	visitChangeType(*ssa.ChangeType) (z3.Bool, error)
	visitConvert(*ssa.Convert) (z3.Bool, error)
	visitMultiConvert(*ssa.MultiConvert) (z3.Bool, error)
	visitChangeInterface(*ssa.ChangeInterface) (z3.Bool, error)
	visitSliceToArrayPointer(*ssa.SliceToArrayPointer) (z3.Bool, error)
	visitMakeInterface(*ssa.MakeInterface) (z3.Bool, error)
	visitMakeClosure(*ssa.MakeClosure) (z3.Bool, error)
	visitMakeMap(*ssa.MakeMap) (z3.Bool, error)
	visitMakeChan(*ssa.MakeChan) (z3.Bool, error)
	visitMakeSlice(*ssa.MakeSlice) (z3.Bool, error)
	visitSlice(*ssa.Slice) (z3.Bool, error)
	visitFieldAddr(*ssa.FieldAddr) (z3.Bool, error)
	visitField(*ssa.Field) (z3.Bool, error)
	visitIndexAddr(*ssa.IndexAddr) (z3.Bool, error)
	visitIndex(*ssa.Index) (z3.Bool, error)
	visitLookup(*ssa.Lookup) (z3.Bool, error)
	visitSelect(*ssa.Select) (z3.Bool, error)
	visitRange(*ssa.Range) (z3.Bool, error)
	visitNext(*ssa.Next) (z3.Bool, error)
	visitTypeAssert(*ssa.TypeAssert) (z3.Bool, error)
	visitExtract(*ssa.Extract) (z3.Bool, error)
	visitJump(*ssa.Jump) (z3.Bool, error)
	visitIf(*ssa.If) (z3.Bool, error)
	visitReturn(*ssa.Return) (z3.Bool, error)
	visitRunDefers(*ssa.RunDefers) (z3.Bool, error)
	visitPanic(*ssa.Panic) (z3.Bool, error)
	visitGo(*ssa.Go) (z3.Bool, error)
	visitDefer(*ssa.Defer) (z3.Bool, error)
	visitSend(*ssa.Send) (z3.Bool, error)
	visitStore(*ssa.Store) (z3.Bool, error)
	visitMapUpdate(*ssa.MapUpdate) (z3.Bool, error)
	visitDebugRef(*ssa.DebugRef) (z3.Bool, error)
	visitPhi(*ssa.Phi) (z3.Bool, error)
} */

type InterVisitorSsa struct {
	stub z3.Bool
}

func NewIntraVisitorSsa() *InterVisitorSsa {

	return &InterVisitorSsa{}
}

func (v *InterVisitorSsa) visitProgram(pkg *ssa.Program) {
	for _, el := range pkg.AllPackages() {
		v.visitPackage(el)
	}
}

func (v *InterVisitorSsa) visitPackage(pkg *ssa.Package) {
	/*
		 	for _, el := range pkg.Members {
				f, ok := el.(*ssa.Function)
				if ok {
					v.VisitFunction(f)
				}
			}
	*/
}

func (v *InterVisitorSsa) GetFunctions(pkg *ssa.Package) map[string]*ssa.Function {
	res := make(map[string]*ssa.Function)
	for _, el := range pkg.Members {
		f, ok := el.(*ssa.Function)
		if ok {
			res[f.Name()] = f
		}
	}
	return res
}

func (v *InterVisitorSsa) VisitFunction(fn *ssa.Function, ctx *z3.Context, mem *sym_mem.SymbolicMem) (*BlockFrame, VISITOR_CODE) {
	println(fn.Name())

	if fn.Name() == "init" {
		return nil, INIT_FUNC
	}

	if fn.Blocks == nil {
		println("external func")
		return nil, EXTERNAL_FUNC
	}

	if len(fn.Blocks) == 0 {
		println("empty func")
		return nil, EMPTY_FUNC
	}

	for _, param := range fn.Params {
		v.visitParameter(param, ctx, mem)
	}

	return &BlockFrame{fn.Blocks[0], 0}, DEFAULT
}

func (v *InterVisitorSsa) visitBlock(block_frame *BlockFrame, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	return v.visitInstruction(block_frame.Block.Instrs[block_frame.InstrIndex], ctx, mem)
}

func (v *InterVisitorSsa) visitInstruction(instr ssa.Instruction, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	switch val_instr := instr.(type) {
	case *ssa.Alloc:
		return v.visitAlloc(val_instr, ctx, mem)
	case *ssa.Call:
		return v.visitCall(val_instr, ctx, mem)
	case *ssa.BinOp:
		return v.visitBinOp(val_instr, ctx, mem)
	case *ssa.UnOp:
		return v.visitUnOp(val_instr, ctx, mem)
	case *ssa.ChangeType:
		return v.visitChangeType(val_instr, ctx, mem)
	case *ssa.Convert:
		return v.visitConvert(val_instr, ctx, mem)
	case *ssa.MultiConvert:
		return v.visitMultiConvert(val_instr, ctx, mem)
	case *ssa.ChangeInterface:
		return v.visitChangeInterface(val_instr, ctx, mem)
	case *ssa.SliceToArrayPointer:
		return v.visitSliceToArrayPointer(val_instr, ctx, mem)
	case *ssa.MakeInterface:
		return v.visitMakeInterface(val_instr, ctx, mem)
	case *ssa.MakeClosure:
		return v.visitMakeClosure(val_instr, ctx, mem)
	case *ssa.MakeMap:
		return v.visitMakeMap(val_instr, ctx, mem)
	case *ssa.MakeChan:
		return v.visitMakeChan(val_instr, ctx, mem)
	case *ssa.MakeSlice:
		return v.visitMakeSlice(val_instr, ctx, mem)
	case *ssa.Slice:
		return v.visitSlice(val_instr, ctx, mem)
	case *ssa.FieldAddr:
		return v.visitFieldAddr(val_instr, ctx, mem)
	case *ssa.Field:
		return v.visitField(val_instr, ctx, mem)
	case *ssa.IndexAddr:
		return v.visitIndexAddr(val_instr, ctx, mem)
	case *ssa.Index:
		return v.visitIndex(val_instr, ctx, mem)
	case *ssa.Lookup:
		return v.visitLookup(val_instr, ctx, mem)
	case *ssa.Select:
		return v.visitSelect(val_instr, ctx, mem)
	case *ssa.Range:
		return v.visitRange(val_instr, ctx, mem)
	case *ssa.Next:
		return v.visitNext(val_instr, ctx, mem)
	case *ssa.TypeAssert:
		return v.visitTypeAssert(val_instr, ctx, mem)
	case *ssa.Extract:
		return v.visitExtract(val_instr, ctx, mem)
	case *ssa.Jump:
		return v.visitJump(val_instr, ctx, mem)
	case *ssa.If:
		return v.visitIf(val_instr, ctx, mem)
	case *ssa.Return:
		return v.visitReturn(val_instr, ctx, mem)
	case *ssa.RunDefers:
		return v.visitRunDefers(val_instr, ctx, mem)
	case *ssa.Panic:
		return v.visitPanic(val_instr, ctx, mem)
	case *ssa.Go:
		return v.visitGo(val_instr, ctx, mem)
	case *ssa.Defer:
		return v.visitDefer(val_instr, ctx, mem)
	case *ssa.Send:
		return v.visitSend(val_instr, ctx, mem)
	case *ssa.Store:
		return v.visitStore(val_instr, ctx, mem)
	case *ssa.MapUpdate:
		return v.visitMapUpdate(val_instr, ctx, mem)
	case *ssa.DebugRef:
		return v.visitDebugRef(val_instr, ctx, mem)
	case *ssa.Phi:
		return v.visitPhi(val_instr, ctx, mem)
	default:
		println(val_instr.String())
		panic("visit not implemented node")
	}
}

func (v *InterVisitorSsa) parseValue(value ssa.Value, ctx *z3.Context, mem *sym_mem.SymbolicMem) (*sym_mem.SymbolicVar, error) {
	res, ok := mem.Variables[value.Name()]
	if ok {
		return res, nil
	} else {
		return v.visitValue(value, ctx, mem)
	}
}

func (v *InterVisitorSsa) visitValue(value ssa.Value, ctx *z3.Context, mem *sym_mem.SymbolicMem) (*sym_mem.SymbolicVar, error) {
	switch tvalue := value.(type) {
	case *ssa.Const:
		return v.visitConst(tvalue, ctx, mem), nil
	default:
		return nil, errors.New("undeclared value or not implemented case")
	}
}

func (v *InterVisitorSsa) visitParameter(param *ssa.Parameter, ctx *z3.Context, mem *sym_mem.SymbolicMem) {
	println(param.Name(), param.Type().Underlying().String())
	mem.AddVariable(param.Name(), param.Type().String(), ctx)
}

func (v *InterVisitorSsa) visitConst(const_value *ssa.Const, ctx *z3.Context, mem *sym_mem.SymbolicMem) *sym_mem.SymbolicVar {
	str_const := const_value.Value.ExactString()
	switch const_value.Type().String() {
	case sym_mem.SORT_BOOL:
		b, err := strconv.ParseBool(str_const)
		if err != nil {
			panic("error parse bool")
		}
		return &sym_mem.SymbolicVar{ctx.FromBool(b), nil, false, false, false}
	case sym_mem.SORT_INT:
		b, err := strconv.Atoi(str_const)
		if err != nil {
			panic("error parse int")
		}
		return &sym_mem.SymbolicVar{ctx.FromInt(int64(b), ctx.BVSort(64)), nil, false, false, false}
	case sym_mem.SORT_UINT:
		b, err := strconv.ParseUint(str_const, 10, 64)
		if err != nil {
			panic("error parse int")
		}
		return &sym_mem.SymbolicVar{ctx.FromInt(int64(b), ctx.BVSort(bits.UintSize)), nil, false, false, false}
	case sym_mem.SORT_FLOAT32:
		b, err := strconv.ParseFloat(str_const, 32)
		if err != nil {
			panic("error parse float32")
		}
		return &sym_mem.SymbolicVar{ctx.FromFloat32(float32(b), ctx.FloatSort(8, 24)), nil, false, false, false}
	case sym_mem.SORT_FLOAT64:
		b, err := strconv.ParseFloat(str_const, 64)
		if err != nil {
			panic("error parse float64")
		}
		return &sym_mem.SymbolicVar{ctx.FromFloat64(b, ctx.FloatSort(11, 53)), nil, false, false, false}
	default:
		panic("unsupported type " + const_value.Type().String())
	}
}

func (v *InterVisitorSsa) visitAlloc(alloc *ssa.Alloc, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(alloc.Name(), "<---", alloc.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitCall(call *ssa.Call, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	//todo: fork to inter procedure call and uninterpr func
	println(call.Name(), "<---", call.String())

	res := mem.AddVariable(call.Name(), call.Type().String(), ctx)

	args_len := len(call.Call.Args)
	args_types := make([]string, args_len)
	args := make([]z3.Value, args_len)
	for i, a := range call.Call.Args {
		args_types[i] = a.Type().String()
		parse_value, err := v.parseValue(a, ctx, mem)
		if err == nil {
			args[i] = parse_value.GetValue()
		} else {
			panic(err.Error())
		}
	}

	func_decl := mem.GetFuncOrCreate(call.Call.Value.Name(), args_types, call.Type().String(), ctx)

	switch tres := res.GetValue().(type) {
	case z3.BV:
		return tres.Eq(func_decl.Apply(args...).(z3.BV)), nil, DEFAULT
	case z3.Float:
		return tres.Eq(func_decl.Apply(args...).(z3.Float)), nil, DEFAULT
	case z3.Bool:
		return tres.Eq(func_decl.Apply(args...).(z3.Bool)), nil, DEFAULT
	case z3.Uninterpreted:
		return tres.Eq(func_decl.Apply(args...).(z3.Uninterpreted)), nil, DEFAULT
	case z3.Int:
		return tres.Eq(func_decl.Apply(args...).(z3.Int)), nil, DEFAULT
	default:
		panic("unknown type")
	}
}

func (v *InterVisitorSsa) visitBinOp(binop *ssa.BinOp, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(binop.Name(), "<---", binop.String())
	var x, y z3.Value
	parse_value_x, errx := v.parseValue(binop.X, ctx, mem)
	parse_value_y, erry := v.parseValue(binop.X, ctx, mem)
	if errx == nil && erry == nil {
		x = parse_value_x.GetValue()
		y = parse_value_y.GetValue()
	} else {
		panic("undeclared var")
	}
	res := mem.AddVariable(binop.Name(), binop.Type().String(), ctx)
	res_v := res.GetValue()

	if x.Sort().Kind() != y.Sort().Kind() {
		panic("dif types in one bin op " + x.Sort().Kind().String() + " " + y.Sort().Kind().String())
	}
	switch binop.Op {
	case token.ADD:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Add(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Add(y.(z3.Float))), nil, DEFAULT
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", ctx)
				imag_func := mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Add(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Add(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil, DEFAULT
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.SUB:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Sub(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Sub(y.(z3.Float))), nil, DEFAULT
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", ctx)
				imag_func := mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Sub(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Sub(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil, DEFAULT
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.MUL:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Mul(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Mul(y.(z3.Float))), nil, DEFAULT
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", ctx)
				imag_func := mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Mul(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Mul(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil, DEFAULT
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.QUO:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.SDiv(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Div(y.(z3.Float))), nil, DEFAULT
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", ctx)
				imag_func := mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Div(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Div(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil, DEFAULT
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.REM:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).SRem(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Float).Eq(x.(z3.Float).Rem(y.(z3.Float))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.AND:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).And(y.(z3.BV))), nil, DEFAULT
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).And(y.(z3.Bool))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.OR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Or(y.(z3.BV))), nil, DEFAULT
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Or(y.(z3.Bool))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.XOR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Xor(y.(z3.BV))), nil, DEFAULT
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Xor(y.(z3.Bool))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.SHL:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Lsh(y.(z3.BV))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.SHR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).URsh(y.(z3.BV))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.AND_NOT:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).And(y.(z3.BV).Not())), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.EQL:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).Eq(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).Eq(y.(z3.Float))), nil, DEFAULT
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Eq(y.(z3.Bool))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.NEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).Eq(y.(z3.BV))).Not()), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).Eq(y.(z3.Float))).Not()), nil, DEFAULT
		case z3.Bool:
			return res_v.(z3.Bool).Eq((x.(z3.Bool).Eq(y.(z3.Bool))).Not()), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.LSS:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).SLT(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).LT(y.(z3.Float))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.LEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).SLT(y.(z3.BV))).Or(x.(z3.BV).Eq(y.(z3.BV)))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).LT(y.(z3.Float))).Or(x.(z3.Float).Eq(y.(z3.Float)))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.GTR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).SGT(y.(z3.BV))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).GT(y.(z3.Float))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	case token.GEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).SGT(y.(z3.BV))).Or(x.(z3.BV).Eq(y.(z3.BV)))), nil, DEFAULT
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).GT(y.(z3.Float))).Or(x.(z3.Float).Eq(y.(z3.Float)))), nil, DEFAULT
		default:
			panic("impossible op for this type")
		}
	default:
		panic("wrong bin op")
	}
}

func (v *InterVisitorSsa) visitUnOp(unop *ssa.UnOp, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("unop")
	println(unop.Name(), "<---", unop.String())
	x, errx := v.parseValue(unop.X, ctx, mem)
	if errx != nil {
		panic("undeclared var")
	}
	res := mem.AddVariable(unop.Name(), unop.Type().String(), ctx)
	res_v := res.GetValue()
	switch unop.Op {
	case token.MUL:
		if x.IsGoPointer {
			switch res_v_t := res_v.(type) {
			case z3.BV:
				return res_v_t.Eq(x.GetValue().(z3.BV)), nil, DEFAULT
			case z3.Float:
				return res_v_t.Eq(x.GetValue().(z3.Float)), nil, DEFAULT
			case z3.Bool:
				return res_v_t.Eq(x.GetValue().(z3.Bool)), nil, DEFAULT
			case z3.Int:
				return res_v_t.Eq(x.GetValue().(z3.Int)), nil, DEFAULT
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

func (v *InterVisitorSsa) visitChangeType(changeType *ssa.ChangeType, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(changeType.Name(), "<---", changeType.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitConvert(convert *ssa.Convert, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(convert.Name(), "<---", convert.String())
	res := mem.AddVariable(convert.Name(), convert.Type().String(), ctx).GetValue()
	var x z3.Value
	parse_value_x, errx := v.parseValue(convert.X, ctx, mem)
	if errx == nil {
		x = parse_value_x.GetValue()
	} else {
		panic("undeclared var")
	}
	switch convert.Type().String() {
	case sym_mem.SORT_FLOAT64:
		switch tval := x.(type) {
		case z3.BV:
			return res.(z3.Float).Eq(tval.IEEEToFloat(ctx.FloatSort(11, 53))), nil, DEFAULT
		default:
			panic("unsopprted cast")
		}
	default:
		panic("unsopprted cast")
	}
}

func (v *InterVisitorSsa) visitMultiConvert(mconvert *ssa.MultiConvert, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(mconvert.Name(), "<---", mconvert.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitChangeInterface(changeInterface *ssa.ChangeInterface, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(changeInterface.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitSliceToArrayPointer(sliceAr *ssa.SliceToArrayPointer, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(sliceAr.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitMakeInterface(makeInterface *ssa.MakeInterface, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(makeInterface.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitMakeClosure(makeClosure *ssa.MakeClosure, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(makeClosure.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitMakeMap(makeMap *ssa.MakeMap, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(makeMap.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitMakeChan(makeChan *ssa.MakeChan, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(makeChan.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitMakeSlice(makeSlice *ssa.MakeSlice, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(makeSlice.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitSlice(slice *ssa.Slice, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(slice.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitFieldAddr(fieldAddr *ssa.FieldAddr, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("fieldAddr", fieldAddr.Name(), "<---", fieldAddr.String())

	res := mem.AddVariable(fieldAddr.Name(), fieldAddr.Type().String(), ctx)
	x, err := v.parseValue(fieldAddr.X, ctx, mem)
	if err != nil {
		panic("undeclared var")
	}

	res_v := res.GetValue()

	field, ok := x.Sort.Fields[fieldAddr.Field]
	if !ok {
		field = x.Sort.AddField(fieldAddr.Field, fieldAddr.Type().String()[1:], ctx)
	}

	field_value := field.Array.Select(x.Value)

	switch arr_el_t := field_value.(type) {
	case z3.BV:
		return res_v.(z3.BV).Eq(arr_el_t), nil, DEFAULT
	case z3.Float:
		return res_v.(z3.Float).Eq(arr_el_t), nil, DEFAULT
	case z3.Bool:
		return res_v.(z3.Bool).Eq(arr_el_t), nil, DEFAULT
	case z3.Int:
		return res_v.(z3.Int).Eq(arr_el_t), nil, DEFAULT
	default:
		panic("unsupported op " + reflect.TypeOf(arr_el_t).String())
	}
}

func (v *InterVisitorSsa) visitField(field *ssa.Field, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("field", field.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitIndexAddr(indexAddr *ssa.IndexAddr, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(indexAddr.Name(), "<---", indexAddr.String())

	index_var, err1 := v.parseValue(indexAddr.Index, ctx, mem)
	array, err2 := v.parseValue(indexAddr.X, ctx, mem)
	if err1 != nil || err2 != nil {
		panic("undeclared var")
	}
	index := index_var.GetValue()

	res := mem.AddVariable(indexAddr.Name(), indexAddr.Type().String(), ctx)
	res_v := res.GetValue()
	arr_el := array.Sort.Values.Select(array.Value).(z3.Array).Select(index)
	switch arr_el_t := arr_el.(type) {
	case z3.BV:
		return res_v.(z3.BV).Eq(arr_el_t), nil, DEFAULT
	case z3.Float:
		return res_v.(z3.Float).Eq(arr_el_t), nil, DEFAULT
	case z3.Bool:
		return res_v.(z3.Bool).Eq(arr_el_t), nil, DEFAULT
	case z3.Int:
		return res_v.(z3.Int).Eq(arr_el_t), nil, DEFAULT
	default:
		panic("unsupported op " + reflect.TypeOf(arr_el_t).String())
	}
}

func (v *InterVisitorSsa) visitIndex(index *ssa.Index, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("index", index.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitLookup(lookup *ssa.Lookup, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("lookup", lookup.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitSelect(slct *ssa.Select, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("select", slct.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitRange(rng *ssa.Range, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(rng.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitNext(next *ssa.Next, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(next.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitTypeAssert(typeAssert *ssa.TypeAssert, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(typeAssert.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitExtract(extract *ssa.Extract, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("extract", extract.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitJump(jump *ssa.Jump, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(jump.String(), " ", jump.Block().Index)
	jump_to := jump.Block().Succs[0].Index
	//todo: change loop detect, fork on loop
	if isPred(jump_to, jump.Block().Preds) {
		println("loop")
		/* 	if _, ok := v.visited_blocks[jump_to]; ok { //Faster than computing
		println("loop")
		println("stub") */
		return v.stub, nil, STUB
	} else {
		return v.stub, []*BlockFrame{&BlockFrame{jump.Block().Succs[0], 1}}, DEFAULT
	}
}

func (v *InterVisitorSsa) visitIf(if_cond *ssa.If, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(if_cond.String())
	if if_cond.Block() != nil && len(if_cond.Block().Succs) == 2 {

		var x z3.Bool
		parse_value_x, errx := v.parseValue(if_cond.Cond, ctx, mem)
		if errx == nil {
			x = parse_value_x.GetValue().(z3.Bool)
		} else {
			panic("undeclared var")
		}

		if_block := if_cond.Block().Succs[0]
		else_block := if_cond.Block().Succs[1]

		return x, []*BlockFrame{{if_block, 0}, {else_block, 0}}, IF_ELSE
	}
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitReturn(return_stmnt *ssa.Return, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(return_stmnt.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitRunDefers(runDefers *ssa.RunDefers, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(runDefers.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitPanic(panic_stmnt *ssa.Panic, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(panic_stmnt.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitGo(go_stmnt *ssa.Go, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(go_stmnt.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitDefer(defer_stmnt *ssa.Defer, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(defer_stmnt.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitSend(send *ssa.Send, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(send.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitStore(store *ssa.Store, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println("store", store.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitMapUpdate(mapUpdate *ssa.MapUpdate, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(mapUpdate.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitDebugRef(debugRef *ssa.DebugRef, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	println(debugRef.String())
	println("stub")
	return v.stub, nil, STUB
}

func (v *InterVisitorSsa) visitPhi(phi *ssa.Phi, ctx *z3.Context, mem *sym_mem.SymbolicMem) (z3.Bool, []*BlockFrame, VISITOR_CODE) {
	//todo: update for dynamic, concrete equal without OR
	println(phi.Name())
	println(phi.Type().String())
	println(phi.String())

	res := mem.AddVariable(phi.Name(), phi.Type().String(), ctx).GetValue()

	switch tres := res.(type) {
	case z3.Float:
		var constr z3.Bool
		//init constr for chain
		for i, edge := range phi.Edges {
			alias, err := v.parseValue(edge, ctx, mem)
			if err == nil {
				constr = tres.Eq(alias.GetValue().(z3.Float))
				break
			} else if i == len(phi.Edges)-1 {
				panic("no aliases")
			}
		}
		for i := 1; i < len(phi.Edges); i++ {
			alias, ok := mem.Variables[phi.Edges[i].Name()]
			if ok {
				constr = constr.Or(tres.Eq(alias.GetValue().(z3.Float)))
			}
		}
		return constr, nil, DEFAULT

	case z3.BV:
		var constr z3.Bool
		//init constr for chain
		for i, edge := range phi.Edges {
			alias, err := v.parseValue(edge, ctx, mem)
			if err == nil {
				constr = tres.Eq(alias.GetValue().(z3.BV))
				break
			} else if i == len(phi.Edges)-1 {
				panic("no aliases")
			}
		}
		for i := 1; i < len(phi.Edges); i++ {
			alias, ok := mem.Variables[phi.Edges[i].Name()]
			if ok {
				constr = constr.Or(tres.Eq(alias.GetValue().(z3.BV)))
			}
		}
		return constr, nil, DEFAULT

	case z3.Bool:
		var constr z3.Bool
		//init constr for chain
		for i, edge := range phi.Edges {
			alias, err := v.parseValue(edge, ctx, mem)
			if err == nil {
				constr = tres.Eq(alias.GetValue().(z3.Bool))
				break
			} else if i == len(phi.Edges)-1 {
				panic("no aliases")
			}
		}
		for i := 1; i < len(phi.Edges); i++ {
			alias, ok := mem.Variables[phi.Edges[i].Name()]
			if ok {
				constr = constr.Or(tres.Eq(alias.GetValue().(z3.Bool)))
			}
		}
		return constr, nil, DEFAULT
	default:
		panic("unsupported phi type " + tres.String())
	}

}

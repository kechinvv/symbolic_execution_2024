package interpretator

import (
	"container/list"
	"errors"
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
}

type IntraVisitorSsa struct {
	visited_blocks      map[int]bool
	Ctx                 *z3.Context
	S                   *z3.Solver
	general_block_stack list.List

	stub z3.Bool // anchor for chaining formula
	Mem  sym_mem.SymbolicMem
}

func NewIntraVisitorSsa() *IntraVisitorSsa {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)
	s := z3.NewSolver(ctx)
	return &IntraVisitorSsa{map[int]bool{},
		ctx,
		s,
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
			v.VisitFunction(f)
		}
	}
}

func (v *IntraVisitorSsa) GetFunctions(pkg *ssa.Package) map[string]*ssa.Function {
	res := make(map[string]*ssa.Function)
	for _, el := range pkg.Members {
		f, ok := el.(*ssa.Function)
		if ok {
			res[f.Name()] = f
		}
	}
	return res
}

func (v *IntraVisitorSsa) VisitFunction(fn *ssa.Function) (z3.Bool, error) {
	println(fn.Name())

	if fn.Name() == "init" {
		return v.stub, errors.New("stub")
	}

	v.Mem.Variables = make(map[string]*sym_mem.SymbolicVar)
	v.S.Reset()

	for _, param := range fn.Params {
		v.visitParameter(param)
	}
	var res z3.Bool
	var er error
	if fn.Blocks == nil {
		println("external func")
		res, er = v.stub, errors.New("stub")
	} else {
		res, er = v.visitBlock(fn.Blocks[0])
	}
	v.visited_blocks = make(map[int]bool)
	return res, er
}

func (v *IntraVisitorSsa) visitBlock(block *ssa.BasicBlock) (z3.Bool, error) {
	var res z3.Bool

	if v.general_block_stack.Back() != nil && block.Index == v.general_block_stack.Back().Value.(*ssa.BasicBlock).Index {
		println("next block is general")
		return v.stub, errors.New("stub")
	}
	v.visited_blocks[block.Index] = true

	res_uninit := true
	i := 0

	//init res for chaining
	for res_uninit {
		if i < len(block.Instrs) {
			instr_res, er := v.visitInstruction(block.Instrs[i])
			i++
			if er == nil {
				res = instr_res
				res_uninit = false
				break
			}
		} else {
			return v.stub, errors.New("stub")
		}
	}

	//chaining
	for i < len(block.Instrs) {
		instr_res, er := v.visitInstruction(block.Instrs[i])
		i++
		if er == nil {
			res = res.And(instr_res)
		}
	}

	delete(v.visited_blocks, block.Index)
	return res, nil
}

func (v *IntraVisitorSsa) visitInstruction(instr ssa.Instruction) (z3.Bool, error) {
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

func (v *IntraVisitorSsa) parseValue(value ssa.Value) (*sym_mem.SymbolicVar, error) {
	res, ok := v.Mem.Variables[value.Name()]
	if ok {
		return res, nil
	} else {
		return v.visitValue(value)
	}
}

func (v *IntraVisitorSsa) visitValue(value ssa.Value) (*sym_mem.SymbolicVar, error) {
	switch tvalue := value.(type) {
	case *ssa.Const:
		return v.visitConst(tvalue), nil
	default:
		return nil, errors.New("undeclared value or not implemented case")
	}
}

func (v *IntraVisitorSsa) visitParameter(param *ssa.Parameter) {
	println(param.Name(), param.Type().Underlying().String())
	v.Mem.AddVariable(param.Name(), param.Type().String(), v.Ctx)
}

func (v *IntraVisitorSsa) visitConst(const_value *ssa.Const) *sym_mem.SymbolicVar {
	str_const := const_value.Value.ExactString()
	switch const_value.Type().String() {
	case sym_mem.SORT_BOOL:
		b, err := strconv.ParseBool(str_const)
		if err != nil {
			panic("error parse bool")
		}
		return &sym_mem.SymbolicVar{v.Ctx.FromBool(b), nil, false, false, false}
	case sym_mem.SORT_INT:
		b, err := strconv.Atoi(str_const)
		if err != nil {
			panic("error parse int")
		}
		return &sym_mem.SymbolicVar{v.Ctx.FromInt(int64(b), v.Ctx.BVSort(64)), nil, false, false, false}
	case sym_mem.SORT_UINT:
		b, err := strconv.ParseUint(str_const, 10, 64)
		if err != nil {
			panic("error parse int")
		}
		return &sym_mem.SymbolicVar{v.Ctx.FromInt(int64(b), v.Ctx.BVSort(bits.UintSize)), nil, false, false, false}
	case sym_mem.SORT_FLOAT32:
		b, err := strconv.ParseFloat(str_const, 32)
		if err != nil {
			panic("error parse float32")
		}
		return &sym_mem.SymbolicVar{v.Ctx.FromFloat32(float32(b), v.Ctx.FloatSort(8, 24)), nil, false, false, false}
	case sym_mem.SORT_FLOAT64:
		b, err := strconv.ParseFloat(str_const, 64)
		if err != nil {
			panic("error parse float64")
		}
		return &sym_mem.SymbolicVar{v.Ctx.FromFloat64(b, v.Ctx.FloatSort(11, 53)), nil, false, false, false}
	default:
		panic("unsupported type " + const_value.Type().String())
	}
}

func (v *IntraVisitorSsa) visitAlloc(alloc *ssa.Alloc) (z3.Bool, error) {
	println(alloc.Name(), "<---", alloc.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitCall(call *ssa.Call) (z3.Bool, error) {
	println(call.Name(), "<---", call.String())

	res := v.Mem.AddVariable(call.Name(), call.Type().String(), v.Ctx)

	args_len := len(call.Call.Args)
	args_types := make([]string, args_len)
	args := make([]z3.Value, args_len)
	for i, a := range call.Call.Args {
		args_types[i] = a.Type().String()
		parse_value, err := v.parseValue(a)
		if err == nil {
			args[i] = parse_value.GetValue()
		} else {
			panic(err.Error())
		}
	}

	func_decl := v.Mem.GetFuncOrCreate(call.Call.Value.Name(), args_types, call.Type().String(), v.Ctx)

	switch tres := res.GetValue().(type) {
	case z3.BV:
		return tres.Eq(func_decl.Apply(args...).(z3.BV)), nil
	case z3.Float:
		return tres.Eq(func_decl.Apply(args...).(z3.Float)), nil
	case z3.Bool:
		return tres.Eq(func_decl.Apply(args...).(z3.Bool)), nil
	case z3.Uninterpreted:
		return tres.Eq(func_decl.Apply(args...).(z3.Uninterpreted)), nil
	case z3.Int:
		return tres.Eq(func_decl.Apply(args...).(z3.Int)), nil
	default:
		panic("unknown type")
	}
}

func (v *IntraVisitorSsa) visitBinOp(binop *ssa.BinOp) (z3.Bool, error) {
	println(binop.Name(), "<---", binop.String())
	var x, y z3.Value
	parse_value_x, errx := v.parseValue(binop.X)
	parse_value_y, erry := v.parseValue(binop.X)
	if errx == nil && erry == nil {
		x = parse_value_x.GetValue()
		y = parse_value_y.GetValue()
	} else {
		panic("undeclared var")
	}
	res := v.Mem.AddVariable(binop.Name(), binop.Type().String(), v.Ctx)
	res_v := res.GetValue()

	if x.Sort().Kind() != y.Sort().Kind() {
		panic("dif types in one bin op " + x.Sort().Kind().String() + " " + y.Sort().Kind().String())
	}
	switch binop.Op {
	case token.ADD:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Add(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Add(y.(z3.Float))), nil
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.Mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.Ctx)
				imag_func := v.Mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.Ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Add(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Add(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.SUB:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Sub(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Sub(y.(z3.Float))), nil
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.Mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.Ctx)
				imag_func := v.Mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.Ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Sub(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Sub(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.MUL:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.Mul(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Mul(y.(z3.Float))), nil
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.Mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.Ctx)
				imag_func := v.Mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.Ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Mul(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Mul(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.QUO:
		switch tx := x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(tx.SDiv(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Float).Eq(tx.Div(y.(z3.Float))), nil
		case z3.Uninterpreted:
			switch binop.Type().String() {
			case "complex128":
				real_func := v.Mem.GetFuncOrCreate("real", []string{"complex128"}, "float64", v.Ctx)
				imag_func := v.Mem.GetFuncOrCreate("imag", []string{"complex128"}, "float64", v.Ctx)
				real_sum := real_func.Apply(tx).(z3.Float).Div(real_func.Apply(y).(z3.Float))
				imag_sum := imag_func.Apply(tx).(z3.Float).Div(imag_func.Apply(y).(z3.Float))
				return real_func.Apply(res_v).(z3.Float).Eq(real_sum).And(imag_func.Apply(res_v).(z3.Float).Eq(imag_sum)), nil
			default:
				panic("impossible op for this type")
			}
		default:
			panic("impossible op for this type")
		}
	case token.REM:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).SRem(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Float).Eq(x.(z3.Float).Rem(y.(z3.Float))), nil
		default:
			panic("impossible op for this type")
		}
	case token.AND:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).And(y.(z3.BV))), nil
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).And(y.(z3.Bool))), nil
		default:
			panic("impossible op for this type")
		}
	case token.OR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Or(y.(z3.BV))), nil
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Or(y.(z3.Bool))), nil
		default:
			panic("impossible op for this type")
		}
	case token.XOR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Xor(y.(z3.BV))), nil
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Xor(y.(z3.Bool))), nil
		default:
			panic("impossible op for this type")
		}
	case token.SHL:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).Lsh(y.(z3.BV))), nil
		default:
			panic("impossible op for this type")
		}
	case token.SHR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).URsh(y.(z3.BV))), nil
		default:
			panic("impossible op for this type")
		}
	case token.AND_NOT:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.BV).Eq(x.(z3.BV).And(y.(z3.BV).Not())), nil
		default:
			panic("impossible op for this type")
		}
	case token.EQL:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).Eq(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).Eq(y.(z3.Float))), nil
		case z3.Bool:
			return res_v.(z3.Bool).Eq(x.(z3.Bool).Eq(y.(z3.Bool))), nil
		default:
			panic("impossible op for this type")
		}
	case token.NEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).Eq(y.(z3.BV))).Not()), nil
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).Eq(y.(z3.Float))).Not()), nil
		case z3.Bool:
			return res_v.(z3.Bool).Eq((x.(z3.Bool).Eq(y.(z3.Bool))).Not()), nil
		default:
			panic("impossible op for this type")
		}
	case token.LSS:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).SLT(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).LT(y.(z3.Float))), nil
		default:
			panic("impossible op for this type")
		}
	case token.LEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).SLT(y.(z3.BV))).Or(x.(z3.BV).Eq(y.(z3.BV)))), nil
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).LT(y.(z3.Float))).Or(x.(z3.Float).Eq(y.(z3.Float)))), nil
		default:
			panic("impossible op for this type")
		}
	case token.GTR:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq(x.(z3.BV).SGT(y.(z3.BV))), nil
		case z3.Float:
			return res_v.(z3.Bool).Eq(x.(z3.Float).GT(y.(z3.Float))), nil
		default:
			panic("impossible op for this type")
		}
	case token.GEQ:
		switch x.(type) {
		case z3.BV:
			return res_v.(z3.Bool).Eq((x.(z3.BV).SGT(y.(z3.BV))).Or(x.(z3.BV).Eq(y.(z3.BV)))), nil
		case z3.Float:
			return res_v.(z3.Bool).Eq((x.(z3.Float).GT(y.(z3.Float))).Or(x.(z3.Float).Eq(y.(z3.Float)))), nil
		default:
			panic("impossible op for this type")
		}
	default:
		panic("wrong bin op")
	}
}

func (v *IntraVisitorSsa) visitUnOp(unop *ssa.UnOp) (z3.Bool, error) {
	println("unop")
	println(unop.Name(), "<---", unop.String())
	x, errx := v.parseValue(unop.X)
	if errx != nil {
		panic("undeclared var")
	}
	res := v.Mem.AddVariable(unop.Name(), unop.Type().String(), v.Ctx)
	res_v := res.GetValue()
	switch unop.Op {
	case token.MUL:
		if x.IsGoPointer {
			switch res_v_t := res_v.(type) {
			case z3.BV:
				return res_v_t.Eq(x.GetValue().(z3.BV)), nil
			case z3.Float:
				return res_v_t.Eq(x.GetValue().(z3.Float)), nil
			case z3.Bool:
				return res_v_t.Eq(x.GetValue().(z3.Bool)), nil
			case z3.Int:
				return res_v_t.Eq(x.GetValue().(z3.Int)), nil
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

func (v *IntraVisitorSsa) visitChangeType(changeType *ssa.ChangeType) (z3.Bool, error) {
	println(changeType.Name(), "<---", changeType.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitConvert(convert *ssa.Convert) (z3.Bool, error) {
	println(convert.Name(), "<---", convert.String())
	res := v.Mem.AddVariable(convert.Name(), convert.Type().String(), v.Ctx).GetValue()
	var x z3.Value
	parse_value_x, errx := v.parseValue(convert.X)
	if errx == nil {
		x = parse_value_x.GetValue()
	} else {
		panic("undeclared var")
	}
	switch convert.Type().String() {
	case sym_mem.SORT_FLOAT64:
		switch tval := x.(type) {
		case z3.BV:
			return res.(z3.Float).Eq(tval.IEEEToFloat(v.Ctx.FloatSort(11, 53))), nil
		default:
			panic("unsopprted cast")
		}
	default:
		panic("unsopprted cast")
	}
}

func (v *IntraVisitorSsa) visitMultiConvert(mconvert *ssa.MultiConvert) (z3.Bool, error) {
	println(mconvert.Name(), "<---", mconvert.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitChangeInterface(changeInterface *ssa.ChangeInterface) (z3.Bool, error) {
	println(changeInterface.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitSliceToArrayPointer(sliceAr *ssa.SliceToArrayPointer) (z3.Bool, error) {
	println(sliceAr.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitMakeInterface(makeInterface *ssa.MakeInterface) (z3.Bool, error) {
	println(makeInterface.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitMakeClosure(makeClosure *ssa.MakeClosure) (z3.Bool, error) {
	println(makeClosure.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitMakeMap(makeMap *ssa.MakeMap) (z3.Bool, error) {
	println(makeMap.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitMakeChan(makeChan *ssa.MakeChan) (z3.Bool, error) {
	println(makeChan.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitMakeSlice(makeSlice *ssa.MakeSlice) (z3.Bool, error) {
	println(makeSlice.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitSlice(slice *ssa.Slice) (z3.Bool, error) {
	println(slice.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitFieldAddr(fieldAddr *ssa.FieldAddr) (z3.Bool, error) {
	println("fieldAddr", fieldAddr.Name(), "<---", fieldAddr.String())

	res := v.Mem.AddVariable(fieldAddr.Name(), fieldAddr.Type().String(), v.Ctx)
	x, err := v.parseValue(fieldAddr.X)
	if err != nil {
		panic("undeclared var")
	}

	res_v := res.GetValue()

	field, ok := x.Sort.Fields[fieldAddr.Field]
	if !ok {
		field = x.Sort.AddField(fieldAddr.Field, fieldAddr.Type().String()[1:], v.Ctx)
	}

	field_value := field.Array.Select(x.Value)

	switch arr_el_t := field_value.(type) {
	case z3.BV:
		return res_v.(z3.BV).Eq(arr_el_t), nil
	case z3.Float:
		return res_v.(z3.Float).Eq(arr_el_t), nil
	case z3.Bool:
		return res_v.(z3.Bool).Eq(arr_el_t), nil
	case z3.Int:
		return res_v.(z3.Int).Eq(arr_el_t), nil
	default:
		panic("unsupported op " + reflect.TypeOf(arr_el_t).String())
	}
}

func (v *IntraVisitorSsa) visitField(field *ssa.Field) (z3.Bool, error) {
	println("field", field.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitIndexAddr(indexAddr *ssa.IndexAddr) (z3.Bool, error) {
	println(indexAddr.Name(), "<---", indexAddr.String())

	index_var, err1 := v.parseValue(indexAddr.Index)
	array, err2 := v.parseValue(indexAddr.X)
	if err1 != nil || err2 != nil {
		panic("undeclared var")
	}
	index := index_var.GetValue()

	res := v.Mem.AddVariable(indexAddr.Name(), indexAddr.Type().String(), v.Ctx)
	res_v := res.GetValue()
	arr_el := array.Sort.Values.Select(array.Value).(z3.Array).Select(index)
	switch arr_el_t := arr_el.(type) {
	case z3.BV:
		return res_v.(z3.BV).Eq(arr_el_t), nil
	case z3.Float:
		return res_v.(z3.Float).Eq(arr_el_t), nil
	case z3.Bool:
		return res_v.(z3.Bool).Eq(arr_el_t), nil
	case z3.Int:
		return res_v.(z3.Int).Eq(arr_el_t), nil
	default:
		panic("unsupported op " + reflect.TypeOf(arr_el_t).String())
	}
}

func (v *IntraVisitorSsa) visitIndex(index *ssa.Index) (z3.Bool, error) {
	println("index", index.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitLookup(lookup *ssa.Lookup) (z3.Bool, error) {
	println("lookup", lookup.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitSelect(slct *ssa.Select) (z3.Bool, error) {
	println("select", slct.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitRange(rng *ssa.Range) (z3.Bool, error) {
	println(rng.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitNext(next *ssa.Next) (z3.Bool, error) {
	println(next.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitTypeAssert(typeAssert *ssa.TypeAssert) (z3.Bool, error) {
	println(typeAssert.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitExtract(extract *ssa.Extract) (z3.Bool, error) {
	println("extract", extract.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitJump(jump *ssa.Jump) (z3.Bool, error) {
	println(jump.String(), " ", jump.Block().Index)
	jump_to := jump.Block().Succs[0].Index
	/* 	if isPred(jump_to, jump.Block().Preds) {
		println("loop")
	} else  */
	if _, ok := v.visited_blocks[jump_to]; ok { //Faster than computing
		println("loop")
		println("stub")
		return v.stub, errors.New("stub")
	} else {
		return v.visitBlock(jump.Block().Succs[0])
	}
}

func (v *IntraVisitorSsa) visitIf(if_cond *ssa.If) (z3.Bool, error) {
	println(if_cond.String())
	if if_cond.Block() != nil && len(if_cond.Block().Succs) == 2 {

		var x z3.Bool
		parse_value_x, errx := v.parseValue(if_cond.Cond)
		if errx == nil {
			x = parse_value_x.GetValue().(z3.Bool)
		} else {
			panic("undeclared var")
		}

		tblock := if_cond.Block().Succs[0]
		fblock := if_cond.Block().Succs[1]
		next := getGeneralSuccBlock(tblock, fblock)
		if next != nil {
			v.general_block_stack.PushBack(next)
		}
		if_res, e1 := v.visitBlock(tblock)
		els, e2 := v.visitBlock(fblock)

		if next != nil {
			v.general_block_stack.Remove(v.general_block_stack.Back())
			println("general block:", next.Index)
			v.visitBlock(next)
		} else {
			println("nil general block")
		}
		if e1 == nil && e2 == nil {
			return x.And(if_res).Or(x.Not().And(els)), nil
		} else if e1 == nil {
			return x.And(if_res).Or(x.Not()), nil
		} else if e2 == nil {
			return x.Or(x.Not().And(els)), nil
		} else {
			return x.Or(x.Not()), nil
		}

	} else {
		println("SUCCS LEN != 2  IN COND")
		println("stub")
		return v.stub, errors.New("stub")
	}
}

func (v *IntraVisitorSsa) visitReturn(return_stmnt *ssa.Return) (z3.Bool, error) {
	println(return_stmnt.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitRunDefers(runDefers *ssa.RunDefers) (z3.Bool, error) {
	println(runDefers.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitPanic(panic_stmnt *ssa.Panic) (z3.Bool, error) {
	println(panic_stmnt.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitGo(go_stmnt *ssa.Go) (z3.Bool, error) {
	println(go_stmnt.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitDefer(defer_stmnt *ssa.Defer) (z3.Bool, error) {
	println(defer_stmnt.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitSend(send *ssa.Send) (z3.Bool, error) {
	println(send.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitStore(store *ssa.Store) (z3.Bool, error) {
	println("store", store.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitMapUpdate(mapUpdate *ssa.MapUpdate) (z3.Bool, error) {
	println(mapUpdate.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitDebugRef(debugRef *ssa.DebugRef) (z3.Bool, error) {
	println(debugRef.String())
	println("stub")
	return v.stub, errors.New("stub")
}

func (v *IntraVisitorSsa) visitPhi(phi *ssa.Phi) (z3.Bool, error) {
	println(phi.Name())
	println(phi.Type().String())
	println(phi.String())

	res := v.Mem.AddVariable(phi.Name(), phi.Type().String(), v.Ctx).GetValue()

	switch tres := res.(type) {
	case z3.Float:
		var constr z3.Bool
		//init constr for chain
		for i, edge := range phi.Edges {
			alias, err := v.parseValue(edge)
			if err == nil {
				constr = tres.Eq(alias.GetValue().(z3.Float))
				break
			} else if i == len(phi.Edges)-1 {
				panic("no aliases")
			}
		}
		for i := 1; i < len(phi.Edges); i++ {
			alias, ok := v.Mem.Variables[phi.Edges[i].Name()]
			if ok {
				constr = constr.Or(tres.Eq(alias.GetValue().(z3.Float)))
			}
		}
		return constr, nil

	case z3.BV:
		var constr z3.Bool
		//init constr for chain
		for i, edge := range phi.Edges {
			alias, err := v.parseValue(edge)
			if err == nil {
				constr = tres.Eq(alias.GetValue().(z3.BV))
				break
			} else if i == len(phi.Edges)-1 {
				panic("no aliases")
			}
		}
		for i := 1; i < len(phi.Edges); i++ {
			alias, ok := v.Mem.Variables[phi.Edges[i].Name()]
			if ok {
				constr = constr.Or(tres.Eq(alias.GetValue().(z3.BV)))
			}
		}
		return constr, nil

	case z3.Bool:
		var constr z3.Bool
		//init constr for chain
		for i, edge := range phi.Edges {
			alias, err := v.parseValue(edge)
			if err == nil {
				constr = tres.Eq(alias.GetValue().(z3.Bool))
				break
			} else if i == len(phi.Edges)-1 {
				panic("no aliases")
			}
		}
		for i := 1; i < len(phi.Edges); i++ {
			alias, ok := v.Mem.Variables[phi.Edges[i].Name()]
			if ok {
				constr = constr.Or(tres.Eq(alias.GetValue().(z3.Bool)))
			}
		}
		return constr, nil
	default:
		panic("unsupported phi type " + tres.String())
	}

	return v.stub, errors.New("stub")
}

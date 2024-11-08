package pkg

import (
	"github.com/kechinvv/go-z3/z3"
)

type SymbolicMem struct {
	Sorts     map[SORT_NAME]SymbolicType
	Variables map[string]z3.Value
	Functions map[string]z3.FuncDecl
}

type SymbolicType struct {
	Sort_name SORT_NAME
	Sort_obj  z3.Sort
	Fileds    map[SORT_NAME]SymbolicField
	SymMem    *SymbolicMem
}

type SymbolicField struct {
	Sort_name SORT_NAME
	Array     z3.Array
	SymMem    *SymbolicMem
}

type SymbolicArray struct {
	Array   z3.Array
	Len     z3.Int
	SymType *SymbolicType
}

type SymbolicObject struct {
	Pointer z3.Int
	Assert  z3.Bool
	SymType *SymbolicType
}

func NewSymbolicMem() SymbolicMem {
	return SymbolicMem{
		Sorts:     make(map[SORT_NAME]SymbolicType),
		Variables: make(map[string]z3.Value),
		Functions: make(map[string]z3.FuncDecl),
	}
}

func (mem *SymbolicMem) GetTypeOrCreate(type_name string, ctx *z3.Context) SymbolicType {
	res_sort, ok := mem.Sorts[type_name]
	if !ok {
		res_sort = mem.AddType(type_name, make(map[string]SORT_NAME), ctx)
	}
	return res_sort
}

func (mem *SymbolicMem) AddFunction(name string, arg_types []SORT_NAME, result_type SORT_NAME, ctx *z3.Context) z3.FuncDecl {
	res_sort := mem.GetTypeOrCreate(result_type, ctx).Sort_obj

	arg_sorts := make([]z3.Sort, len(arg_types))
	for i, typ := range arg_types {
		arg_sorts[i] = mem.GetTypeOrCreate(typ, ctx).Sort_obj
	}
	f_decl := ctx.FuncDecl(name, arg_sorts, res_sort)
	mem.Functions[name] = f_decl
	return f_decl
}

func (mem *SymbolicMem) AddVariable(name string, typ SORT_NAME, ctx *z3.Context) z3.Value {
	switch typ {
	case SORT_INT:
		mem.Variables[name] = ctx.Const(name, ctx.BVSort(64))
	case SORT_FLOAT32:
		mem.Variables[name] = ctx.Const(name, ctx.FloatSort(8, 24))
	case SORT_FLOAT64:
		mem.Variables[name] = ctx.Const(name, ctx.FloatSort(11, 53))
	case SORT_BOOL:
		mem.Variables[name] = ctx.Const(name, ctx.BoolSort())
	default:
		st := mem.GetTypeOrCreate(typ, ctx)
		mem.Variables[name] = ctx.Const(name, st.Sort_obj)
	}
	return mem.Variables[name]
}

func (s *SymbolicMem) AddType(name SORT_NAME, fields map[string]SORT_NAME, ctx *z3.Context) SymbolicType {
	sum_fields := make(map[string]SymbolicField)
	sym_type := SymbolicType{
		Sort_name: name,
		Sort_obj:  GetSortByName(ctx, name),
		Fileds:    sum_fields,
		SymMem:    s,
	}

	for f_name, f_sort_name := range fields {
		sym_type.addField(f_name, f_sort_name, ctx)
	}

	s.Sorts[name] = sym_type
	return sym_type
}

func (t *SymbolicType) addField(field_name string, field_sort SORT_NAME, ctx *z3.Context) SymbolicField {
	f_sort := t.SymMem.GetTypeOrCreate(field_sort, ctx).Sort_obj

	a_sort := ctx.ArraySort(ctx.IntSort(), f_sort)

	t.Fileds[field_name] = SymbolicField{
		Sort_name: field_sort,
		Array:     ctx.Const(t.Sort_name+":"+field_name+":mem", a_sort).(z3.Array),
		SymMem:    t.SymMem,
	}

	return t.Fileds[field_name]
}

func NewSymbolicArray(name string, sym_type *SymbolicType, ctx *z3.Context) SymbolicArray {
	sort := ctx.ArraySort(ctx.IntSort(), ctx.IntSort())
	array := ctx.Const(name, sort).(z3.Array)
	a_len := ctx.Const(name+"_len", ctx.IntSort()).(z3.Int)

	return SymbolicArray{
		Array:   array,
		Len:     a_len,
		SymType: sym_type,
	}
}

func (a *SymbolicArray) Get(index z3.Int, ctx *z3.Context) SymbolicObject {
	pointer := ctx.FreshConst("ptr_for_"+a.SymType.Sort_name, ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	return SymbolicObject{
		SymType: a.SymType,
		Pointer: pointer,
		Assert:  pointer.Eq(a.Array.Select(index).(z3.Int)).And(pointer.GE(zero_int)),
	}
}

func (t *SymbolicType) AllocObject(init_var_name string, ctx *z3.Context) SymbolicObject {
	pointer := ctx.FreshConst("ptr_for_"+t.Sort_name+"_from_"+init_var_name, ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	//todo: unique pointer?

	return SymbolicObject{
		SymType: t,
		Pointer: pointer,
		Assert:  pointer.GE(zero_int),
	}
}

func (o *SymbolicObject) assignFieldToValue(field_name string, field_sort SORT_NAME, variable z3.Value, ctx *z3.Context) SymbolicObject {
	field, ok := o.SymType.Fileds[field_name]
	if !ok {
		field = o.SymType.addField(field_name, field_sort, ctx)
	}

	sort_name := field.Sort_name
	var pointer z3.Int
	var assert z3.Bool
	//array := field.Array
	//zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	if sort_name != SORT_BOOL && sort_name != SORT_INT &&
		sort_name != SORT_FLOAT64 && sort_name != SORT_FLOAT32 {
		pointer = o.Pointer
		assert = variable.(z3.Uninterpreted).Eq(field.Array.Select(pointer).(z3.Uninterpreted))
	} else {
		pointer = ctx.FreshConst("ptr_for_"+field.Sort_name, ctx.IntSort()).(z3.Int)
		//assert = pointer.Eq(array.Select(pointer).(z3.Int)).And(pointer.GE(zero_int))
	}

	obj_type := field.SymMem.GetTypeOrCreate(field_sort, ctx)

	return SymbolicObject{
		SymType: &obj_type,
		Pointer: pointer,
		Assert:  o.Assert.And(assert),
	}
}

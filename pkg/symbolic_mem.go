package pkg

import (
	"strconv"

	"github.com/kechinvv/go-z3/z3"
)

type SymbolicMem struct {
	Sorts     map[SORT_NAME]*SymbolicType
	Variables map[string]*SymbolicVar
	Functions map[string]z3.FuncDecl
}

type SymbolicType struct {
	Sort_name SORT_NAME
	Sort_obj  z3.Sort
	Fields    map[int]*SymbolicField
	SymMem    *SymbolicMem
	Values    z3.Array
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
		Sorts:     make(map[SORT_NAME]*SymbolicType),
		Variables: make(map[string]*SymbolicVar),
		Functions: make(map[string]z3.FuncDecl),
	}
}

func (mem *SymbolicMem) GetFuncOrCreate(name string, arg_types []SORT_NAME, result_type SORT_NAME, ctx *z3.Context) z3.FuncDecl {
	func_decl, ok := mem.Functions[name]
	if !ok {
		func_decl = mem.AddFunction(name, arg_types, result_type, ctx)
	}
	return func_decl
}

func (mem *SymbolicMem) GetTypeOrCreate(type_name string, ctx *z3.Context) *SymbolicType {
	res_sort, ok := mem.Sorts[type_name]
	if !ok {
		res_sort = mem.AddType(type_name, make(map[int]SORT_NAME), ctx)
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

func (mem *SymbolicMem) AddVariable(name string, typ SORT_NAME, ctx *z3.Context) *SymbolicVar {
	sort := mem.GetTypeOrCreate(typ, ctx)
	switch typ {
	case SORT_INT:
		mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.BVSort(64)), sort, false, false, false}
	case SORT_FLOAT32:
		mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.FloatSort(8, 24)), sort, false, false, false}
	case SORT_FLOAT64:
		mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.FloatSort(11, 53)), sort, false, false, false}
	case SORT_BOOL:
		mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.BoolSort()), sort, false, false, false}
	case SORT_COMPLEX128:
		mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.UninterpretedSort(SORT_COMPLEX128)), sort, false, false, false}
	default:
		if len(typ) > 2 && string(typ[:2]) == "[]" {
			mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.IntSort()), sort, false, false, true}
		} else {
			mem.Variables[name] = &SymbolicVar{ctx.Const(name, ctx.IntSort()), sort, typ[0] == '*', true, false}
		}
	}
	return mem.Variables[name]
}

func (s *SymbolicMem) AddType(name SORT_NAME, fields map[int]SORT_NAME, ctx *z3.Context) *SymbolicType {
	sum_fields := make(map[int]*SymbolicField)

	var sort_object z3.Sort
	var a_sort z3.Sort

	if name[0] == '*' {
		sort_object = GetSortByName(ctx, name[1:])
	} else {
		sort_object = GetSortByName(ctx, name)
	}

	//todo: array/slice classify method
	if string(name[:2]) != "[]" {
		//type pointer or stub
		a_sort = ctx.ArraySort(ctx.IntSort(), sort_object)
	} else {
		array_value_sort := s.ResolveArraySort(ctx, name[2:])
		a_sort = ctx.ArraySort(ctx.IntSort(), ctx.ArraySort(ctx.BVSort(64), array_value_sort))
	}
	sym_type := SymbolicType{
		Sort_name: name,
		Sort_obj:  sort_object,
		Fields:    sum_fields,
		SymMem:    s,
		Values:    ctx.Const("array"+":"+name+":"+"mem", a_sort).(z3.Array),
	}

	for f_name, f_sort_name := range fields {
		sym_type.AddField(f_name, f_sort_name, ctx)
	}

	s.Sorts[name] = &sym_type
	return &sym_type
}

func (t *SymbolicType) AddField(field_num int, field_sort SORT_NAME, ctx *z3.Context) *SymbolicField {
	f_sort := t.SymMem.GetTypeOrCreate(field_sort, ctx).Sort_obj

	a_sort := ctx.ArraySort(ctx.IntSort(), f_sort)

	t.Fields[field_num] = &SymbolicField{
		Sort_name: field_sort,
		Array:     ctx.Const(t.Sort_name+":"+strconv.FormatInt(int64(field_num), 10)+":mem", a_sort).(z3.Array),
		SymMem:    t.SymMem,
	}

	return t.Fields[field_num]
}

type SymbolicVar struct {
	Value       z3.Value
	Sort        *SymbolicType
	IsGoPointer bool
	IsStruct    bool
	IsArray     bool
}

func (v SymbolicVar) GetValue() z3.Value {
	if v.IsGoPointer {
		return v.Sort.Values.Select(v.Value)
	} else {
		return v.Value
	}
}

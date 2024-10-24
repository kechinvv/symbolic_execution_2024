package pkg

import (
	"github.com/kechinvv/go-z3/z3"
)


type SymbolicMem struct {
	Sorts map[SORT_NAME]SymbolicType
}

type SymbolicType struct {
	Sort_name SORT_NAME
	Sort   z3.Sort
	Fileds map[SORT_NAME]SymbolicField
	SymMem *SymbolicMem
}

type SymbolicField struct {
	Sort_name SORT_NAME
	Sort  z3.Sort  
	Array z3.Array
	SymMem *SymbolicMem
}

type SymbolicArray struct {
	Array   z3.Array
	Len     z3.Int
	SymType *SymbolicType
}

type SymbolicObject struct {
	Pointer z3.Int
	Assert z3.Bool
	SymType *SymbolicType
}




func NewSymbolicMem() SymbolicMem {
	return SymbolicMem{
		Sorts: make(map[SORT_NAME]SymbolicType),
	}
}

func (s *SymbolicMem) AddType(name SORT_NAME, sort z3.Sort, fields map[string]SORT_NAME, ctx *z3.Context) SymbolicType {
	sum_fields := make(map[string]SymbolicField)
	for f_name, f_sort_name := range fields {
		f_sort := GetSortByName(ctx, f_sort_name)
		a_sort := ctx.ArraySort(ctx.IntSort(), f_sort)
		sum_fields[f_name] = SymbolicField{
			Sort_name: f_sort_name,
			Sort:  f_sort,
			Array: ctx.Const(name+":"+f_name+":mem", a_sort).(z3.Array),
			SymMem: s,
		}
	}
	sym_type := SymbolicType{
		Sort_name: name,
		Sort:   sort,
		Fileds: sum_fields,
		SymMem: s,
	}
	s.Sorts[name] = sym_type
	return sym_type
}


func NewSymbolicArray(name string, sym_type *SymbolicType, ctx *z3.Context) SymbolicArray {
	sort := ctx.ArraySort(ctx.IntSort(), ctx.IntSort())
	array := ctx.Const(name, sort).(z3.Array)
	a_len := ctx.Const(name+"_len", ctx.IntSort()).(z3.Int)

	return SymbolicArray{
		Array: array,
		Len: a_len,
		SymType: sym_type,
	}
}

func (a *SymbolicArray) Get(index z3.Int, ctx *z3.Context) SymbolicObject {
	pointer := ctx.FreshConst("ptr_for_"+a.SymType.Sort_name, ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	return SymbolicObject{
		SymType: a.SymType,
		Pointer: pointer,
		Assert: pointer.Eq(a.Array.Select(index).(z3.Int)).And(pointer.GE(zero_int)),
	}
}



func(o *SymbolicObject) getField(field_name string, ctx *z3.Context) SymbolicObject {
	field := o.SymType.Fileds[field_name]
	sort_name := field.Sort_name
	var pointer z3.Int
	var assert z3.Bool
	//array := field.Array
	//zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	if sort_name != SORT_BOOL && sort_name != SORT_INT && 
		sort_name != SORT_FLOAT64 && sort_name != SORT_FLOAT32 {
		pointer = o.Pointer
		//assert = 
	} else {
		pointer = ctx.FreshConst("ptr_for_"+field.Sort_name, ctx.IntSort()).(z3.Int)
		//assert = pointer.Eq(array.Select(pointer).(z3.Int)).And(pointer.GE(zero_int))
	}
	new_type := field.SymMem.Sorts[field.Sort_name]
	return SymbolicObject{
		SymType: &new_type,
		Pointer: pointer,
		Assert: o.Assert.And(assert),
	}
}



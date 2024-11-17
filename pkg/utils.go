package pkg

import "github.com/kechinvv/go-z3/z3"

type SORT_NAME = string

const (
	SORT_INT SORT_NAME = "int" 
	SORT_UINT SORT_NAME = "uint" 
	SORT_FLOAT32 SORT_NAME = "float32" 
	SORT_FLOAT64 SORT_NAME = "float64" 
	SORT_BOOL SORT_NAME = "bool" 
	SORT_COMPLEX128 SORT_NAME = "complex128"
)
var PrimitiveSorts = [...]SORT_NAME{SORT_INT, SORT_FLOAT32, SORT_FLOAT64, SORT_BOOL}

func GetSortByName(ctx *z3.Context, name SORT_NAME) z3.Sort {
	switch name{
	case SORT_INT:
		return ctx.BVSort(64)
	case SORT_BOOL:
		return ctx.BoolSort()
	case SORT_FLOAT32:
		return ctx.FloatSort(8, 24)
	case SORT_FLOAT64:
		return ctx.FloatSort(11, 53)
	case SORT_COMPLEX128:
		return ctx.UninterpretedSort(SORT_COMPLEX128)
	default:
		return ctx.IntSort()
	}
}



package pkg

import "github.com/kechinvv/go-z3/z3"

type ComplexZ3 struct {
	R, I z3.Float
}

func ConstComplex(name string, ctx *z3.Context, float_sort z3.Sort) ComplexZ3 {
	return ComplexZ3{ 
		R: ctx.Const(name+"_r", float_sort).(z3.Float),
		I: ctx.Const(name+"_i", float_sort).(z3.Float),
	}
}
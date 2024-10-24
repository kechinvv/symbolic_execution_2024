package lab1

import (
	"testing"

	"github.com/kechinvv/go-z3/z3"
	cmplx "github.com/kechinvv/symbolic_execution_2024/pkg"
)

func TestBasicComplexOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	fs64 := ctx.FloatSort(11, 53)

	var a cmplx.ComplexZ3 = cmplx.ConstComplex("a", ctx, fs64)
	var b cmplx.ComplexZ3 = cmplx.ConstComplex("b", ctx, fs64)

	s.Assert(a.R.GT(b.R))
	checkWithOutputAndReset(s)

	s.Assert(a.R.GT(b.R).Not())
	s.Assert(a.I.GT(b.I))
	checkWithOutputAndReset(s)

	s.Assert(a.R.GT(b.R).Not())
	s.Assert(a.I.GT(b.I).Not())
	checkWithOutputAndReset(s)
}

func TestComplexComparison(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	fs64 := ctx.FloatSort(11, 53)

	a := cmplx.ConstComplex("a", ctx, fs64)
	b := cmplx.ConstComplex("b", ctx, fs64)

	magA := ctx.Const("magA", fs64).(z3.Float)
	magB := ctx.Const("magB", fs64).(z3.Float)

	s.Assert(magA.Eq(a.R.Mul(a.R).Add(a.I.Mul(a.I))))
	s.Assert(magB.Eq(b.R.Mul(b.R).Add(b.I.Mul(b.I))))
	s.Assert(magA.GT(magB))
	checkWithOutputAndReset(s)

	s.Assert(magA.Eq(a.R.Mul(a.R).Add(a.I.Mul(a.I))))
	s.Assert(magB.Eq(b.R.Mul(b.R).Add(b.I.Mul(b.I))))
	s.Assert(magA.GT(magB).Not())
	s.Assert(magA.LT(magB))
	checkWithOutputAndReset(s)

	s.Assert(magA.Eq(a.R.Mul(a.R).Add(a.I.Mul(a.I))))
	s.Assert(magB.Eq(b.R.Mul(b.R).Add(b.I.Mul(b.I))))
	s.Assert(magA.GT(magB).Not())
	s.Assert(magA.LT(magB).Not())
	checkWithOutputAndReset(s)
}

func TestComplexOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	fs64 := ctx.FloatSort(11, 53)

	var a cmplx.ComplexZ3 = cmplx.ConstComplex("a", ctx, fs64)
	var b cmplx.ComplexZ3 = cmplx.ConstComplex("b", ctx, fs64)

	zero_float := ctx.FromInt(0, fs64).(z3.Float)

	s.Assert(a.R.Eq(zero_float).And(a.I.Eq(zero_float)))
	checkWithOutputAndReset(s)

	s.Assert(a.R.Eq(zero_float).And(a.I.Eq(zero_float)).Not())
	s.Assert(b.R.Eq(zero_float).And(b.I.Eq(zero_float)))
	checkWithOutputAndReset(s)

	s.Assert(a.R.Eq(zero_float).And(a.I.Eq(zero_float)).Not())
	s.Assert(b.R.Eq(zero_float).And(b.I.Eq(zero_float)).Not())
	s.Assert(a.R.GT(b.R))
	checkWithOutputAndReset(s)

	s.Assert(a.R.Eq(zero_float).And(a.I.Eq(zero_float)).Not())
	s.Assert(b.R.Eq(zero_float).And(b.I.Eq(zero_float)).Not())
	s.Assert(a.R.GT(b.R).Not())
	checkWithOutputAndReset(s)
}

func TestNestedComplexOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	fs64 := ctx.FloatSort(11, 53)

	var a cmplx.ComplexZ3 = cmplx.ConstComplex("a", ctx, fs64)
	var b cmplx.ComplexZ3 = cmplx.ConstComplex("b", ctx, fs64)

	zero_float := ctx.FromInt(0, fs64).(z3.Float)

	s.Assert(a.R.LT(zero_float))
	s.Assert(a.I.LT(zero_float))
	checkWithOutputAndReset(s)

	s.Assert(a.R.LT(zero_float))
	s.Assert(a.I.LT(zero_float).Not())
	checkWithOutputAndReset(s)

	s.Assert(a.R.LT(zero_float).Not())
	s.Assert(b.I.LT(zero_float))
	checkWithOutputAndReset(s)

	s.Assert(a.R.LT(zero_float).Not())
	s.Assert(b.I.LT(zero_float).Not())
	checkWithOutputAndReset(s)
}

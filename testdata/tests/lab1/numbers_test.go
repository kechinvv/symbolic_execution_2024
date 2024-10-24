package lab1

import (
	"testing"
	"github.com/kechinvv/go-z3/z3"
)

func TestIntegerOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a := ctx.Const("a", ctx.IntSort()).(z3.Int)
	b := ctx.Const("b", ctx.IntSort()).(z3.Int)

	s.Assert(a.GT(b))
	checkWithOutputAndReset(s)

	s.Assert(a.LT(b).And((a.GT(b)).Not()))
	checkWithOutputAndReset(s)

	s.Assert(a.LT(b).Not().And(a.GT(b).Not()))
	checkWithOutputAndReset(s)

}

func TestFloatOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	x := ctx.Const("x", ctx.FloatSort(11, 53)).(z3.Float)
	y := ctx.Const("y", ctx.FloatSort(11, 53)).(z3.Float)

	s.Assert(x.GT(y))
	checkWithOutputAndReset(s)

	s.Assert(x.LT(y).And((x.GT(y)).Not()))
	checkWithOutputAndReset(s)

	s.Assert(x.LT(y).Not().And(x.GT(y).Not()))
	checkWithOutputAndReset(s)
}

func TestMixedOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	fs64 := ctx.FloatSort(11, 53)

	a := ctx.BVConst("a", int_size)
	b := ctx.Const("b", fs64).(z3.Float)
	r := ctx.Const("r", fs64).(z3.Float)

	two_int := ctx.FromInt(2, ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)
	ten_float := ctx.FromInt(10, fs64).(z3.Float)

	s.Assert(a.SToInt().Mod(two_int).Eq(zero_int))
	s.Assert(r.Eq((a.SToFloat(fs64)).Sub(b)))
	s.Assert(r.LT(ten_float))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().Mod(two_int).Eq(zero_int))
	s.Assert(r.Eq((a.SToFloat(fs64)).Sub(b)))
	s.Assert(r.LT(ten_float).Not())
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().Mod(two_int).Eq(zero_int).Not())
	s.Assert(r.Eq((a.SToFloat(fs64)).Sub(b)))
	s.Assert(r.LT(ten_float))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().Mod(two_int).Eq(zero_int).Not())
	s.Assert(r.Eq((a.SToFloat(fs64)).Sub(b)))
	s.Assert(r.LT(ten_float).Not())
	checkWithOutputAndReset(s)
}

func TestNestedConditions(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	fs64 := ctx.FloatSort(11, 53)

	a := ctx.Const("a", ctx.IntSort()).(z3.Int)
	b := ctx.Const("b", fs64).(z3.Float)

	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)
	zero_float := ctx.FromInt(0, fs64).(z3.Float)

	s.Assert(a.LT(zero_int))
	s.Assert(b.LT(zero_float))
	checkWithOutputAndReset(s)

	s.Assert(a.LT(zero_int))
	s.Assert(b.LT(zero_float).Not())
	checkWithOutputAndReset(s)

	s.Assert(a.LT(zero_int).Not())
	checkWithOutputAndReset(s)
}

func TestBitwiseOperations(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a := ctx.BVConst("a", int_size)
	b := ctx.BVConst("b", int_size)

	zero_bv := ctx.FromInt(0, ctx.BVSort(int_size)).(z3.BV)
	one_bv := ctx.FromInt(1, ctx.BVSort(int_size)).(z3.BV)

	s.Assert(a.And(one_bv).Eq(zero_bv).And(b.And(one_bv).Eq(zero_bv)))
	checkWithOutputAndReset(s)

	s.Assert(a.And(one_bv).Eq(zero_bv).And(b.And(one_bv).Eq(zero_bv)).Not())
	s.Assert(a.And(one_bv).Eq(one_bv).And(b.And(one_bv).Eq(one_bv)))
	checkWithOutputAndReset(s)

	s.Assert(a.And(one_bv).Eq(zero_bv).And(b.And(one_bv).Eq(zero_bv)).Not())
	s.Assert(a.And(one_bv).Eq(one_bv).And(b.And(one_bv).Eq(one_bv)).Not())
	checkWithOutputAndReset(s)
}

func TestAdvancedBitwise(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a := ctx.BVConst("a", int_size)
	b := ctx.BVConst("b", int_size)

	s.Assert(a.SToInt().GT(b.SToInt()))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().GT(b.SToInt()).Not())
	s.Assert(a.SToInt().LT(b.SToInt()))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().GT(b.SToInt()).Not())
	s.Assert(a.SToInt().LT(b.SToInt()).Not())
	checkWithOutputAndReset(s)
}


func TestCombinedBitwise(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a := ctx.BVConst("a", int_size)
	b := ctx.BVConst("b", int_size)
	r := ctx.BVConst("r", int_size)

	zero_bv := ctx.FromInt(0, ctx.BVSort(int_size)).(z3.BV)
	ten_bv := ctx.FromInt(10, ctx.BVSort(int_size)).(z3.BV)

	s.Assert(a.And(b).Eq(zero_bv))
	checkWithOutputAndReset(s)

	s.Assert(a.And(b).Eq(zero_bv).Not())
	s.Assert(r.Eq(a.And(b)))
	s.Assert(r.SToInt().GT(ten_bv.SToInt()))
	checkWithOutputAndReset(s)

	s.Assert(a.And(b).Eq(zero_bv).Not())
	s.Assert(r.Eq(a.And(b)))
	s.Assert(r.SToInt().GT(ten_bv.SToInt()).Not())
	checkWithOutputAndReset(s)
}


func TestNestedBitwise(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a := ctx.BVConst("a", int_size)
	b := ctx.BVConst("b", int_size)

	zero_bv := ctx.FromInt(0, ctx.BVSort(int_size)).(z3.BV)

	s.Assert(a.SToInt().LT(zero_bv.SToInt()))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().LT(zero_bv.SToInt()).Not())
	s.Assert(b.SToInt().LT(zero_bv.SToInt()))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().LT(zero_bv.SToInt()).Not())
	s.Assert(b.SToInt().LT(zero_bv.SToInt()).Not())
	s.Assert(a.And(b).Eq(zero_bv))
	checkWithOutputAndReset(s)

	s.Assert(a.SToInt().LT(zero_bv.SToInt()).Not())
	s.Assert(b.SToInt().LT(zero_bv.SToInt()).Not())
	s.Assert(a.And(b).Eq(zero_bv).Not())
	checkWithOutputAndReset(s)
}




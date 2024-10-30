package lab1

import (
	"testing"
	"strconv"
	"github.com/kechinvv/go-z3/z3"
)

func TestPushPopIncrementality(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	j := ctx.Const("j", ctx.IntSort()).(z3.Int)
	r := ctx.Const("r0", ctx.IntSort()).(z3.Int)
	i := ctx.Const("i0", ctx.IntSort()).(z3.Int)


	two_int := ctx.FromInt(2, ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)
	one_int := ctx.FromInt(1, ctx.IntSort()).(z3.Int)
	var i1, r1 z3.Int
	
	s.Assert(r.Eq(j))
	s.Assert(i.Eq(one_int))

	checkWithOutput(s)

	for ii := 1; ii <= 10; ii++ {
		r1 = ctx.Const("r"+strconv.Itoa(ii), ctx.IntSort()).(z3.Int)
		i1 = ctx.Const("i"+strconv.Itoa(ii), ctx.IntSort()).(z3.Int)
		s.Assert(r1.Eq(r.Add(i)))
		s.Assert(i1.Eq(i.Add(one_int)))
		checkWithOutput(s)
		r=r1
		i=i1
    }

	s.Push()
	s.Assert(r.Mod(two_int).Eq(zero_int))
	checkWithOutput(s)
	s.Pop()

	s.Assert(r.Mod(two_int).Eq(zero_int).Not())
	checkWithOutputAndReset(s)

}
package lab1

import (
	"testing"

	"github.com/kechinvv/go-z3/z3"
)

func TestCompareElement(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a_sort := ctx.ArraySort(ctx.IntSort(), ctx.IntSort())
	a := ctx.Const("a", a_sort).(z3.Array)
	a_len := ctx.Const("a_len", ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	i := ctx.Const("i", ctx.IntSort()).(z3.Int)
	v := ctx.Const("v", ctx.IntSort()).(z3.Int)
	el := ctx.Const("el", ctx.IntSort()).(z3.Int)

	s.Assert(a_len.GE(zero_int))
	s.Assert(i.LT(zero_int).Or(i.GE(a_len)))
	checkWithOutputAndReset(s)

	s.Assert(a_len.GE(zero_int))
	s.Assert((i.LT(zero_int).Or(i.GE(a_len))).Not())
	s.Assert(el.Eq(a.Select(i).(z3.Int)))
	s.Assert(el.GT(v))
	checkWithOutputAndReset(s)

	s.Assert(a_len.GE(zero_int))
	s.Assert((i.LT(zero_int).Or(i.GE(a_len))).Not())
	s.Assert(el.Eq(a.Select(i).(z3.Int)))
	s.Assert(el.GT(v).Not())
	s.Assert(el.LT(v))
	checkWithOutputAndReset(s)

	s.Assert(a_len.GE(zero_int))
	s.Assert((i.LT(zero_int).Or(i.GE(a_len))).Not())
	s.Assert(el.Eq(a.Select(i).(z3.Int)))
	s.Assert(el.GT(v).Not())
	s.Assert(el.LT(v).Not())
	checkWithOutputAndReset(s)
}

func TestCompareAge(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	people_sort := ctx.ArraySort(ctx.IntSort(), ctx.IntSort())
	people := ctx.Const("people", people_sort).(z3.Array)
	p_len := ctx.Const("p_len", ctx.IntSort()).(z3.Int)
	zero_int := ctx.FromInt(0, ctx.IntSort()).(z3.Int)

	//names := ctx.ConstArray(ctx.IntSort(), ctx.)
	ages := ctx.ConstArray(ctx.IntSort(), ctx.FromInt(0, ctx.IntSort()).(z3.Int))
	addr_p := ctx.Const("addr_p", ctx.IntSort()).(z3.Int)

	i := ctx.Const("i", ctx.IntSort()).(z3.Int)
	v := ctx.Const("v", ctx.IntSort()).(z3.Int)
	age := ctx.Const("age", ctx.IntSort()).(z3.Int)

	s.Assert(p_len.GE(zero_int))
	s.Assert(i.LT(zero_int).Or(i.GE(p_len)))
	checkWithOutputAndReset(s)

	s.Assert(p_len.GE(zero_int))
	s.Assert(i.LT(zero_int).Or(i.GE(p_len)).Not())
	s.Assert(addr_p.Eq(people.Select(i).(z3.Int)).And(addr_p.GE(zero_int)))
	s.Assert(age.Eq(ages.Select(addr_p).(z3.Int)))
	s.Push()
	s.Assert(age.GT(v))
	checkWithOutput(s)
	s.Pop()
	s.Push()


	s.Assert(age.GT(v).Not())
	s.Assert(age.LT(v))
	checkWithOutput(s)
	s.Pop()

	s.Assert(age.GT(v).Not())
	s.Assert(age.LT(v).Not())
	checkWithOutputAndReset(s)

}

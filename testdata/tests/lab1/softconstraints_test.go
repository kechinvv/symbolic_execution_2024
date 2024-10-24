package lab1

import (
	"testing"

	"github.com/kechinvv/go-z3/z3"
	 pkg"github.com/kechinvv/symbolic_execution_2024/pkg"
)

func TestCompareAndIncrement(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)

	a := ctx.Const("a", ctx.IntSort()).(z3.Int)
	b := ctx.Const("b", ctx.IntSort()).(z3.Int)
	c := ctx.Const("c", ctx.IntSort()).(z3.Int)
	one_int := ctx.FromInt(1, ctx.IntSort()).(z3.Int)
	m_five_int := ctx.FromInt(-5, ctx.IntSort()).(z3.Int)
	five_int := ctx.FromInt(5, ctx.IntSort()).(z3.Int)
	three_int := ctx.FromInt(3, ctx.IntSort()).(z3.Int)
	m_three_int := ctx.FromInt(-3, ctx.IntSort()).(z3.Int)

	assumptions := []pkg.Assumption{
		pkg.Assumption{a.LT(five_int), ctx.BoolConst("a < 5")},
		pkg.Assumption{a.LT(m_five_int), ctx.BoolConst("a < -5")},
		pkg.Assumption{a.LT(m_three_int), ctx.BoolConst("a < -3")},
		pkg.Assumption{b.GT(one_int), ctx.BoolConst("b > 1")},
		pkg.Assumption{b.GT(three_int), ctx.BoolConst("b > 3")},
		pkg.Assumption{b.LE(five_int), ctx.BoolConst("b <= 5")},

	}

	f := func() {
		for _, constr := range assumptions {
			s.AssertAndTrack(constr.Expr, constr.Name)
		}
	}

	s.Assert(a.GT(b))
	s.Assert(c.Eq(a.Add(one_int)))
	s.Assert(c.GT(b))
	s.Push()
	f()
	CheckWithUnsatCoreV1(s, assumptions)
	s.Reset()

	s.Assert(a.GT(b))
	s.Assert(c.Eq(a.Add(one_int)))
	s.Assert(c.GT(b).Not())
	s.Push()
	f()
	CheckWithUnsatCoreV1(s, assumptions)
	s.Reset()

	s.Assert(a.GT(b).Not())
	s.Push()
	f()
	CheckWithUnsatCoreV1(s, assumptions)
}

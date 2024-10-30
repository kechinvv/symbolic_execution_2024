package lab1

import (
	"fmt"
	"strings"

	"github.com/kechinvv/go-z3/z3"
	"github.com/kechinvv/symbolic_execution_2024/pkg"
)

const int_size = 64

func checkWithOutputAndReset(s *z3.Solver) {
	println(s.AssertionsString())
	if v, _ := s.Check(); !v {
		fmt.Println("Unsolveable")
	} else {
		m := s.Model().String()
		println(m)
	}
	s.Reset()
}

func checkWithOutput(s *z3.Solver) {
	println(s.AssertionsString())
	if v, _ := s.Check(); !v {
		fmt.Println("Unsolveable")
	} else {
		m := s.Model().String()
		println(m)
	}
}

func CheckWithUnsatCoreV0(s *z3.Solver) {
	println(s.AssertionsString())
	if v, _ := s.Check(); !v {
		fmt.Println("unresolved")
		unsatCore := s.UnsatCore()
		for _, expr := range unsatCore {
			println(expr.String())
		}
		for len(unsatCore) > 0 && !v {
			soft_constraints := s.Assertions()
			s.Pop()
			s.Push()
			for _, constr := range soft_constraints {
				if !strings.HasPrefix(constr.String(),"(=> " + unsatCore[0].String()){
					s.Assert(constr)  //PROBLEM - LOST TRACKED CONSTR
				} 
			}
			println(s.AssertionsString())
			if v, _ := s.Check(); !v {
				println("unresolved")
				unsatCore = s.UnsatCore()
				for _, expr := range unsatCore {
					println(expr.String())
				}
			} else {
				m := s.Model().String()
				println(m)
				return
			}
		}
	} else {
		m := s.Model().String()
		println(m)
	}
}


func CheckWithUnsatCoreV1(s *z3.Solver, soft_constraints []pkg.Assumption) {
	println(s.AssertionsString())
	if v, _ := s.Check(); !v {
		fmt.Println("unresolved")
		unsatCore := s.UnsatCore()
		for _, expr := range unsatCore {
			println(expr.String())
		}
		for len(unsatCore) > 0 && !v {
			s.Pop()
			s.Push()
			var active_constraints []pkg.Assumption
			for _, constr := range soft_constraints {
				if constr.Name.String() != unsatCore[0].String() {
					s.AssertAndTrack(constr.Expr, constr.Name)
					active_constraints = append(active_constraints, constr)
				} 
			}
			soft_constraints = active_constraints
			println(s.AssertionsString())
			if v, _ := s.Check(); !v {
				println("unresolved")
				unsatCore = s.UnsatCore()
				for _, expr := range unsatCore {
					println(expr.String())
				}
			} else {
				m := s.Model().String()
				println(m)
				return
			}
		}
	} else {
		m := s.Model().String()
		println(m)
	}
}

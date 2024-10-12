package lab1

import (
	"fmt"
	"github.com/kechinvv/go-z3/z3"
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
package pkg

import "github.com/kechinvv/go-z3/z3"

type Assumption struct {
	Expr, Name z3.Bool
}
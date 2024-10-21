package lab2

import (
	"testing"

	"github.com/kechinvv/symbolic_execution_2024/pkg"
)

func TestGetSsaFromProg(t *testing.T) {
	pkg.GetSsaFromProg("/home/valera/symbolic_execution_2024/testdata/data/constraints")
}

func TestGetSsaFromFile(t *testing.T) {
	pkg.GetSsaFromFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/arrays.go")
}
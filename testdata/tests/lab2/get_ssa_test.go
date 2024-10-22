package lab2

import (
	"testing"

	"github.com/kechinvv/symbolic_execution_2024/pkg/interpretator"
)

func TestGetSsaFromProg(t *testing.T) {
	interpretator.GetSsaFromProg("/home/valera/symbolic_execution_2024/testdata/data/constraints")
}

func TestGetSsaFromFile(t *testing.T) {
	interpretator.GetSsaFromFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/arrays.go")
}
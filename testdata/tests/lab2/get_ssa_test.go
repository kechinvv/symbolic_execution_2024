package lab2

import (
	"testing"

	"github.com/kechinvv/symbolic_execution_2024/pkg/interpretator"
)

func TestGetSsaFromProg(t *testing.T) {
	interpretator.RunStatSymbolExecForFile("/home/valera/symbolic_execution_2024/...")
}

func TestGetSsaFromFile(t *testing.T) {
	interpretator.RunStatSymbolExecForFile("/home/valera/symbolic_execution_2024/testdata/data/constraints/complex.go")
}
package interpretator

import (
	"container/list"

	"golang.org/x/tools/go/ssa"
)

func getGeneralSuccBlock(succ1 *ssa.BasicBlock, succ2 *ssa.BasicBlock) int {
	for _, el := range succ1.Succs {
		print(el.Index, " ")
	}
	println()
	for _, el := range succ2.Succs {
		print(el.Index, " ")
	}
	println()
	return 0
}

func isPred(index int, preds []*ssa.BasicBlock) bool {
	var stack list.List
	visited := make(map[int]bool)
	for _, pred := range preds {
		stack.PushBack(pred)
	}

	for stack.Len() != 0 {
		el := stack.Front()
		v := el.Value.(*ssa.BasicBlock)
		if v.Index == index {
			return true
		}
		visited[v.Index] = true
		for _, pred := range v.Preds {
			if _, ok := visited[pred.Index]; !ok {
			stack.PushBack(pred)
			}
		}
		stack.Remove(el)
	}
	return false
}

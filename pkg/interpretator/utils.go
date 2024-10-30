package interpretator

import (
	"container/list"

	"golang.org/x/tools/go/ssa"
)

func getGeneralSuccBlock(succ1 *ssa.BasicBlock, succ2 *ssa.BasicBlock) *ssa.BasicBlock {
	var succs1 list.List
	var succs2 list.List
	succs1.PushBack(succ1)
	succs2.PushBack(succ2)

	ptr1 := succs1.Front()
	ptr2 := succs2.Front()

	unfoldSuccs(succ1, &succs1)
	unfoldSuccs(succ2, &succs2)

	for ptr1 != nil || ptr2 != nil {
		res := findGeneralBlock(&succs1, &succs2)
		if res != nil {
			return res
		}

		if ptr1 != nil {
			ptr1 = ptr1.Next()
		}
		if ptr2 != nil {
			ptr2 = ptr2.Next()
		}

		if ptr1 != nil {
			unfoldSuccs(ptr1.Value.(*ssa.BasicBlock), &succs1)
		}
		if ptr2 != nil {
			unfoldSuccs(ptr2.Value.(*ssa.BasicBlock), &succs2)
		}
	}
	return nil
}

func unfoldSuccs(succ *ssa.BasicBlock, to_list *list.List) {
	for _, s := range succ.Succs {
		to_list.PushBack(s)
	}
}

func findGeneralBlock(succs1 *list.List, succs2 *list.List) *ssa.BasicBlock {
	for e1 := succs1.Front(); e1 != nil; e1 = e1.Next() {
		for e2 := succs2.Front(); e2 != nil; e2 = e2.Next() {
			if e1.Value.(*ssa.BasicBlock) == e2.Value.(*ssa.BasicBlock) {
				return e1.Value.(*ssa.BasicBlock)
			}
		}
	}
	return nil
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

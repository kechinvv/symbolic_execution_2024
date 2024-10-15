package lab1

import (
	"slices"
	"testing"

	"github.com/kechinvv/go-z3/z3"
)

type LatticeElement struct {
	is_interface bool
	parent       *LatticeElement
	implemented  []*LatticeElement
	name         string
}

func (el *LatticeElement) isInterface() bool {
	return el.is_interface
}

func (el *LatticeElement) isSupertypeOf(other_elemnt *LatticeElement) bool {
	return other_elemnt.isSubtypeOf(el)
}

func (el *LatticeElement) isSubtypeOf(other_elemnt *LatticeElement) bool {
	if el.parent == nil && len(el.implemented) == 0  {
		return false
	}
	return el.parent == other_elemnt || slices.Contains(el.implemented, other_elemnt) || el.parent.isSubtypeOf(other_elemnt)
}

func (el *LatticeElement) isSuperclassOf(other_elemnt *LatticeElement) bool {
	return other_elemnt.parent == el
}

func (el *LatticeElement) isSubclassOf(other_elemnt *LatticeElement) bool {
	if el.parent == nil || other_elemnt.is_interface {
		return false
	}
	return el.parent == other_elemnt || el.parent.isSubclassOf(other_elemnt)
}

func createData() map[string]*LatticeElement {
	 object := LatticeElement{false, nil, []*LatticeElement{}, "Object"}
	 speakable := LatticeElement{true, nil, []*LatticeElement{}, "Speakable"}
	 flyable := LatticeElement{true, nil, []*LatticeElement{}, "Flyable"}

	 animal := LatticeElement{false, &object, []*LatticeElement{}, "Animal"}
	 human := LatticeElement{false, &animal, []*LatticeElement{&speakable}, "Human"}
	 parrot := LatticeElement{false, &animal, []*LatticeElement{&speakable, &flyable}, "Parrot"}
	 student := LatticeElement{false, &human, []*LatticeElement{}, "Student"}
	 taburetka := LatticeElement{false, &object, []*LatticeElement{}, "Taburet"}

	 return map[string]*LatticeElement{
		object.name: &object, 
		speakable.name: &speakable, 
		flyable.name: &flyable, 
		animal.name: &animal, 
		human.name: &human, 
		parrot.name: &parrot, 
		student.name: &student,
		taburetka.name: &taburetka,
	}
}



func TestSubtyping(t *testing.T) {
	config := z3.NewContextConfig()
	ctx := z3.NewContext(config)

	s := z3.NewSolver(ctx)
	elements := createData()

	super_type := ctx.UninterpretedSort("type_of_all_types")

	consts := make(map[string]z3.Value)

	const_names := []string{}
	for n := range elements {
		const_names = append(const_names, n)
	}

	for _, k :=  range const_names {
		consts[k] = ctx.Const(k, super_type)
	}


	subclassOf := ctx.FuncDecl("SubclassOf", []z3.Sort{super_type, super_type}, ctx.BoolSort())
	superclassOf := ctx.FuncDecl("SuperclassOf", []z3.Sort{super_type, super_type}, ctx.BoolSort())
	subtypeOf := ctx.FuncDecl("SubtypeOf", []z3.Sort{super_type, super_type}, ctx.BoolSort())
	supertypeOf := ctx.FuncDecl("SupertypeOf", []z3.Sort{super_type, super_type}, ctx.BoolSort())

	for k1, v1 := range elements {
		for k2, v2 := range elements {
			s.Assert(subclassOf.Apply(consts[k1], consts[k2]).(z3.Bool).Eq(ctx.FromBool(v1.isSubclassOf(v2))))
			s.Assert(superclassOf.Apply(consts[k1], consts[k2]).(z3.Bool).Eq(ctx.FromBool(v1.isSuperclassOf(v2))))
			s.Assert(subtypeOf.Apply(consts[k1], consts[k2]).(z3.Bool).Eq(ctx.FromBool(v1.isSubtypeOf(v2))))
			s.Assert(supertypeOf.Apply(consts[k1], consts[k2]).(z3.Bool).Eq(ctx.FromBool(v1.isSupertypeOf(v2))))
		}
	}

	println(s.AssertionsString())
	if v, _ := s.Check(); !v {
		println("Unsolveable")
	} else {
		m := s.Model()
		println(m.String())
		println("EVALS")
		println(m.Eval(subclassOf.Apply(consts["Animal"], consts["Object"]), true).String())
		println(m.Eval(subclassOf.Apply(consts["Object"], consts["Animal"]), true).String())
		println(m.Eval(subclassOf.Apply(consts["Student"], consts["Animal"]), true).String())
		println(m.Eval(subclassOf.Apply(consts["Taburet"], consts["Animal"]), true).String())
	}


}
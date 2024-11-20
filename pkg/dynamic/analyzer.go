package dynamic

type Machine struct {
	Scheduler Scheduler
	States    []*State
	//Visitor Visitor
}

func CreateMachine(scheduler_type SCH_TYPE) *Machine {
	switch scheduler_type {
	case ROUND_ROBIN:
		return &Machine{&RoundRobbinScheduler{0}, []*State{}}
	default:
		panic("not implemented")
	}
}

func (m *Machine) RunForFileFunc(file string, fun string) {
	m.States = []*State{}
	GetSsaFromFile(file)

}

func (n *Machine) NextStep() {
	
}

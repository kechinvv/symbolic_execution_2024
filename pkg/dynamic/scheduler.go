package dynamic

import (
	"math/rand"
)

type SCH_TYPE int

const (
	ROUND_ROBIN SCH_TYPE = iota
)

type Scheduler interface {
	GetExecuteCandidate(states []*State) *State
}


type RoundRobbinScheduler struct {
	counter int
}

func (s *RoundRobbinScheduler) GetExecuteCandidate(states []*State) *State {
	if s.counter >= len(states) {
		s.counter = 0
		if len(states) == 0 {
			return nil
		}
	}
	state := states[s.counter]
	s.counter++
	return state
}

type RandomScheduler struct {
	
}

func (s *RandomScheduler) GetExecuteCandidate(states []*State) *State {
	return states[rand.Intn(len(states))]
}


type DFSScheduler struct {
	
}

func (s *DFSScheduler) GetExecuteCandidate(states []*State) *State {
	return states[rand.Intn(len(states))]
}

type BFSScheduler struct {
	
}

func (s *BFSScheduler) GetExecuteCandidate(states []*State) *State {
	return states[rand.Intn(len(states))]
}
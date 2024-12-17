package dynamic

import (
	"math/rand"
)

type SCH_TYPE int

const (
	ROUND_ROBIN SCH_TYPE = iota
)

type Scheduler interface {
	GetExecuteCandidate(states []*State) (*State, int)
}


type RoundRobbinScheduler struct {
	counter int
}

func (s *RoundRobbinScheduler) GetExecuteCandidate(states []*State) (*State, int) {
	if s.counter >= len(states) {
		s.counter = 0
		if len(states) == 0 {
			return nil, -1
		}
	}
	c := s.counter
	state := states[c]
	s.counter++
	return state, c
}

type RandomScheduler struct {
	
}

func (s *RandomScheduler) GetExecuteCandidate(states []*State) (*State, int) {
	r := rand.Intn(len(states))
	return states[r], r
}


type DFSScheduler struct {
	
}

func (s *DFSScheduler) GetExecuteCandidate(states []*State) (*State, int)  {
	r := rand.Intn(len(states))
	return states[r], r
}

type BFSScheduler struct {
	
}

func (s *BFSScheduler) GetExecuteCandidate(states []*State) (*State, int)  {
	r := rand.Intn(len(states))
	return states[r], r
}
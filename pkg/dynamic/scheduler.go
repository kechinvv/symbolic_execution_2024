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
	Append(ar []*State, el *State) []*State
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

func (s *RoundRobbinScheduler) Append(ar []*State, el *State) []*State {
	return append(ar, el)
}

type RandomScheduler struct {
}

func (s *RandomScheduler) GetExecuteCandidate(states []*State) (*State, int) {
	r := rand.Intn(len(states))
	return states[r], r
}

func (s *RandomScheduler) Append(ar []*State, el *State) []*State {
	return append(ar, el)
}

type DFSScheduler struct {
}

// always return last, because new possible paths add to last_index-1
func (s *DFSScheduler) GetExecuteCandidate(states []*State) (*State, int) {
	last_i := len(states) - 1
	return states[last_i], last_i
}

func (s *DFSScheduler) Append(ar []*State, el *State) []*State {
	last_i := len(ar) - 1
	return append(ar[:last_i], el, ar[last_i])
}

type BFSScheduler struct {
	counter int
}

//round robbin, but new states add to begin
func (s *BFSScheduler) GetExecuteCandidate(states []*State) (*State, int) {
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

func (s *BFSScheduler) Append(ar []*State, el *State) []*State {
	s.counter++
	temp := append(make([]*State, 0, len(ar)+1), el)
	return append(temp, ar...)
}

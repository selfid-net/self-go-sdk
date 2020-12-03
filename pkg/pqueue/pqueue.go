// Copyright 2020 Self Group Ltd. All Rights Reserved.

package pqueue

import (
	"sync"
)

// Queue a priority queue implementation
type Queue struct {
	partitions []list
	cond       *sync.Cond
}

// New creates a new prioriy queue
func New(size int) *Queue {
	return &Queue{
		partitions: make([]list, size),
		cond:       sync.NewCond(&sync.Mutex{}),
	}
}

// Push an item to the queue
func (q *Queue) Push(priority int, value interface{}) {
	q.partitions[priority].push(value)
	q.cond.L.Lock()
	q.cond.Signal()
	q.cond.L.Unlock()
}

// Pop an item from the queue
func (q *Queue) Pop() interface{} {
	_, v := q.pop()
	return v
}

// Pop an item from the queue with its priority
func (q *Queue) PopWithPrioriry() (int, interface{}) {
	return q.pop()
}

func (q *Queue) pop() (int, interface{}) {
	for i := 0; i < len(q.partitions); i++ {
		if q.partitions[i].empty() {
			continue
		}

		v := q.partitions[i].pop()
		if v != nil {
			return i, v
		}
	}

	q.cond.L.Lock()
	q.cond.Wait()
	q.cond.L.Unlock()

	return q.pop()
}

// Flush clears a partitions results
func (q *Queue) Flush(priority int) {
	q.partitions[priority].flush()
}

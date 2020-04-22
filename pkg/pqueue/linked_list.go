package pqueue

import (
	"sync"
	"sync/atomic"
)

type node struct {
	next  *node
	value interface{}
}

// list a simple linked list implementation
type list struct {
	head  *node
	tail  *node
	items int64
	mu    sync.Mutex
}

// push a value to the list
func (l *list) push(value interface{}) {
	n := node{
		value: value,
	}

	l.mu.Lock()
	if l.head == nil {
		l.head = &n
	} else {
		l.tail.next = &n
	}

	l.tail = &n

	l.mu.Unlock()

	atomic.AddInt64(&l.items, 1)
}

// pop an item from the head of the queue
func (l *list) pop() interface{} {
	l.mu.Lock()

	if l.head == nil {
		l.mu.Unlock()
		return nil
	}

	value := l.head.value
	l.head = l.head.next
	l.mu.Unlock()

	atomic.AddInt64(&l.items, -1)

	return value
}

// flush the lists entrys
func (l *list) flush() {
	l.mu.Lock()
	l.head = nil
	l.tail = nil
	atomic.StoreInt64(&l.items, 0)
	l.mu.Unlock()
}

func (l *list) empty() bool {
	return atomic.LoadInt64(&l.items) < 1
}

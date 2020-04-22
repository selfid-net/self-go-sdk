package pqueue

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestQueue(t *testing.T) {
	q := New(8)

	q.Push(0, "p0")
	q.Push(2, "p2")
	q.Push(3, "p3")
	q.Push(2, "p2")
	q.Push(1, "p1")
	q.Push(4, "p4")

	assert.Equal(t, int64(1), q.partitions[0].items)
	assert.Equal(t, int64(1), q.partitions[1].items)
	assert.Equal(t, int64(2), q.partitions[2].items)
	assert.Equal(t, int64(1), q.partitions[3].items)
	assert.Equal(t, int64(1), q.partitions[4].items)

	assert.Equal(t, "p0", q.Pop())
	assert.Equal(t, "p1", q.Pop())
	assert.Equal(t, "p2", q.Pop())
	assert.Equal(t, "p2", q.Pop())
	assert.Equal(t, "p3", q.Pop())
	assert.Equal(t, "p4", q.Pop())

	q.Push(6, "p6")
	q.Push(5, "p5")
	q.Push(7, "p7")
	q.Push(7, "p7")

	assert.Equal(t, int64(1), q.partitions[5].items)
	assert.Equal(t, int64(1), q.partitions[6].items)
	assert.Equal(t, int64(2), q.partitions[7].items)

	assert.Equal(t, "p5", q.Pop())
	assert.Equal(t, "p6", q.Pop())
	assert.Equal(t, "p7", q.Pop())
	assert.Equal(t, "p7", q.Pop())

	q = New(8)

	for i := 0; i < 100; i++ {
		q.Push(rand.Intn(8), i)
	}

	for i := 0; i < 100; i++ {
		assert.NotNil(t, q.Pop())
	}
}

func TestQueuePopWait(t *testing.T) {
	done := make(chan interface{})

	q := New(8)

	go func() {
		done <- q.Pop()
	}()

	assert.True(t, timeout(done))

	q.Push(0, "test")

	assert.False(t, timeout(done))
}

func TestQueueConcurrentPush(t *testing.T) {
	q := New(8)

	var wg sync.WaitGroup
	wg.Add(16)

	for i := 0; i < 16; i++ {
		go func(v int) {
			for x := 0; x < 1000; x++ {
				q.Push(rand.Intn(8), v)
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	var count int64

	for i := range q.partitions {
		count = count + q.partitions[i].items
	}

	assert.Equal(t, int64(16000), count)
}

func TestQueueConcurrentPop(t *testing.T) {
	q := New(8)

	for i := 0; i < 16000; i++ {
		q.Push(rand.Intn(8), i)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var count int64

	for i := 0; i < 16; i++ {
		go func() {
			for q.Pop() != nil {
				nv := atomic.AddInt64(&count, 1)
				if nv == 16000 {
					wg.Done()
				}
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(16000), count)
}

func TestQueueConcurrentMixed(t *testing.T) {
}

func timeout(c chan interface{}) bool {
	select {
	case <-c:
		return false
	case <-time.After(time.Millisecond * 100):
		return true
	}
}

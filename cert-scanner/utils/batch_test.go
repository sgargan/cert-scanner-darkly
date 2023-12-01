package utils

import (
	"context"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type BatchProcessTests struct {
	suite.Suite
}

type Item struct {
	index   int
	current int64
}

func (t *BatchProcessTests) TestProcessesInBatches() {
	var inflight int64 = 0

	batchSize := int64(10)
	items := make([]*Item, 1000)
	for x := 0; x < len(items); x++ {
		items[x] = &Item{
			index:   x,
			current: -2,
		}
	}

	// process each item, tracking the number of executions in flight using an atomic
	// sleeps for a random interval of between 10 and 50 milliseconds to simulate work
	processor := func(ctx context.Context, item *Item) (err error) {
		defer atomic.AddInt64(&inflight, -1)
		// set this items spot in the array to the current inflight total
		items[item.index].current = atomic.AddInt64(&inflight, 1)
		duration := time.Duration(rand.Intn(50)+10) * time.Millisecond
		time.Sleep(duration)
		return
	}

	// process all the items, with a max of batchSize
	group := BatchProcess[*Item](context.Background(), items, int(batchSize), processor)
	err := group.Wait()
	t.NoError(err)

	// check that all items are greater than zero indicating they all got processed
	// also that at any stage the number in flight was less than the batch size
	for x := 0; x < len(items); x++ {
		inflightAtTimeOfProcessing := items[x].current
		t.GreaterOrEqual(inflightAtTimeOfProcessing, int64(0))
		t.LessOrEqual(inflightAtTimeOfProcessing, batchSize)
	}
}

func (t *BatchProcessTests) TestSliceRequired() {
	called := false
	group := BatchProcess[*Item](context.Background(), nil, 10, func(ctx context.Context, item *Item) (err error) {
		called = true
		return nil
	})
	err := group.Wait()
	t.False(called)
	t.ErrorContains(err, "a valid slice of items to process is required")
}

func (t *BatchProcessTests) TestUsesItemsLengthIfLargerBatchSizeRequested() {
	called := false
	group := BatchProcess[int](context.Background(), []int{1, 2, 3}, 10, func(ctx context.Context, item int) (err error) {
		called = true
		return nil
	})
	t.NoError(group.Wait())
	t.True(called)
}

func TestBatchProcessTests(t *testing.T) {
	suite.Run(t, &BatchProcessTests{})
}

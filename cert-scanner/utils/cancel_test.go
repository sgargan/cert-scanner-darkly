package utils

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type CancelContextTests struct {
	suite.Suite
}

func (t *CancelContextTests) TestContextCompletion() {
	watcher := CreateContextWatcher()
	ctx, cancel := CreateSignalledContext(100*time.Millisecond, syscall.SIGUSR1)
	t.Equal(Complete, watcher.Watch(ctx, cancel, 50*time.Millisecond))
}

func (t *CancelContextTests) TestContextCancelledByTimeout() {
	watcher := CreateContextWatcher()
	ctx, cancel := CreateSignalledContext(50*time.Millisecond, syscall.SIGUSR1)
	t.Equal(Cancelled, watcher.Watch(ctx, cancel, 100*time.Millisecond))
}

func (t *CancelContextTests) TestContextCancelledBySignal() {
	watcher := CreateContextWatcher()
	ctx, cancel := CreateSignalledContext(100*time.Millisecond, syscall.SIGUSR1)

	time.AfterFunc(50*time.Millisecond, func() {
		syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	})
	t.Equal(Cancelled, watcher.Watch(ctx, cancel, 100*time.Millisecond))
}

func (t *CancelContextTests) TestWaitWithContextReleasedWhenContexCancelled() {
	ctx, cancel := context.WithCancel(context.Background())
	wwc := &ContextualWaitGroup{}
	wwc.Add(1)

	var done atomic.Bool
	time.AfterFunc(50*time.Millisecond, func() {
		done.Store(true)
		cancel()
	})
	wwc.WaitWithContext(ctx)
	t.NotNil(ctx.Err())
	t.True(done.Load())
}

func (t *CancelContextTests) TestWaitWithContextReleasedWhenWaitDone() {
	ctx := context.Background()
	wwc := &ContextualWaitGroup{}
	wwc.Add(1)

	var waited atomic.Bool
	time.AfterFunc(50*time.Millisecond, func() {
		wwc.Done()
		waited.Store(true)
	})
	wwc.WaitWithContext(ctx)
	t.Nil(ctx.Err())

}

type WatchResult int64

const (
	Cancelled WatchResult = 1
	Complete  WatchResult = 2
)

// ContextWatcher simulates work being done with a context allowing inspection of whether the work completed
// or the context got cancelled.ma
type ContextWatcher struct {
	watchChan chan struct{}
}

func CreateContextWatcher() *ContextWatcher {
	return &ContextWatcher{
		watchChan: make(chan struct{}),
	}
}

func (c *ContextWatcher) Watch(ctx context.Context, cancel func(), workDuration time.Duration) WatchResult {
	go func() {
		defer close(c.watchChan)
		time.Sleep(workDuration)
	}()

	select {
	case <-ctx.Done():
		return Cancelled
	case <-c.watchChan:
		return Complete
	}
}

func TestCancelContextTests(t *testing.T) {
	suite.Run(t, &CancelContextTests{})
}

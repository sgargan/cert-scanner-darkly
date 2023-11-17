package utils

import (
	"context"
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

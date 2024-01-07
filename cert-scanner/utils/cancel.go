package utils

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"time"
)

// Create a Context that will be cancelled if any of the given Signals are received or if the given timeout elapses.
func CreateSignalledContext(timeout time.Duration, signals ...os.Signal) (context.Context, context.CancelFunc) {
	return CreateSignalledContextWithContext(context.Background(), timeout, signals...)
}

// Create a Context to enrich the given context such that it will be cancelled if any of the given Signals are received or if the given timeout elapses.
func CreateSignalledContextWithContext(ctx context.Context, timeout time.Duration, signals ...os.Signal) (context.Context, context.CancelFunc) {
	withSignals, _ := signal.NotifyContext(ctx, signals...)
	return context.WithTimeout(withSignals, timeout)
}

type ContextualWaitGroup struct {
	sync.WaitGroup
}

func (w *ContextualWaitGroup) WaitWithContext(ctx context.Context) {
	// create a simple channel & goroutine so we can wait on both the wait group and context concurrently
	waitCh := make(chan struct{})
	go func() { w.Wait(); close(waitCh) }()

	select {
	case <-waitCh:
		return
	case <-ctx.Done():
		return
	}
}

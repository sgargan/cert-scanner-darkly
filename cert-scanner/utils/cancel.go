package utils

import (
	"context"
	"os"
	"os/signal"
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

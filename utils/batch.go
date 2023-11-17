package utils

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
)

// BatchProcess[T any] will iterate over the given slice of items processing them in parallel such that batchSize of them will be concurrently
// processing at any one time.
func BatchProcess[T any](ctx context.Context, items []T, batchSize int, processor func(ctx context.Context, item T) error) *errgroup.Group {
	group, gctx := errgroup.WithContext(ctx)
	if items == nil {
		group.SetLimit(1)
		group.Go(func() error { return errors.New("a valid slice of items to process is required") })
		return group
	}

	numItems := len(items)
	if batchSize > numItems {
		batchSize = numItems
	}
	group.SetLimit(batchSize)
	for _, item := range items {
		copy := item
		group.Go(func() error {
			return processor(gctx, copy)
		})
	}
	return group
}

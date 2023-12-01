package scanner

import (
	"context"

	"golang.org/x/exp/slog"

	"github.com/sgargan/cert-scanner-darkly/discovery"
	"github.com/sgargan/cert-scanner-darkly/processors"
	"github.com/sgargan/cert-scanner-darkly/reporters"
	"github.com/sgargan/cert-scanner-darkly/validations"
)

func PerformScan(ctx context.Context) error {
	discoveries, err := discovery.CreateDiscoveries()
	if err != nil {
		slog.Error("error configuring discovery mechanisms", "err", err.Error())
		return err
	}

	processors, err := processors.CreateProcessors()
	if err != nil {
		slog.Error("error configuring processors", "err", err.Error())
		return err
	}

	validations, err := validations.CreateValidations()
	if err != nil {
		slog.Error("error configuring validations", "err", err.Error())
		return err
	}

	reporters, err := reporters.CreateReporters()
	if err != nil {
		slog.Error("error configuring reporters", "err", err.Error())
		return err
	}

	if err := CreateScan(discoveries, processors, validations, reporters).Scan(ctx); err != nil {
		slog.Error("error running scan", "err", err.Error())
	}
	return nil
}

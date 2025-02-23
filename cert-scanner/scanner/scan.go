package scanner

import (
	"context"

	"golang.org/x/exp/slog"

	"github.com/sgargan/cert-scanner-darkly/discovery"
	"github.com/sgargan/cert-scanner-darkly/processors"
	"github.com/sgargan/cert-scanner-darkly/reporters"
	"github.com/sgargan/cert-scanner-darkly/validations"
)

func PerformScan(ctx context.Context) (*Scan, error) {
	slog.Info("creating service discovery mechanisms")
	discoveries, err := discovery.CreateDiscoveries()
	if err != nil {
		slog.Error("error configuring discovery mechanisms", "err", err.Error())
		return nil, err
	}

	slog.Info("creating processors")
	processors, err := processors.CreateProcessors()
	if err != nil {
		slog.Error("error configuring processors", "err", err.Error())
		return nil, err
	}

	slog.Info("creating validations")
	validations, err := validations.CreateValidations()
	if err != nil {
		slog.Error("error configuring validations", "err", err.Error())
		return nil, err
	}

	slog.Info("creating reporters")
	reporters, err := reporters.CreateReporters()
	if err != nil {
		slog.Error("error configuring reporters", "err", err.Error())
		return nil, err
	}

	scan := CreateScan(discoveries, processors, validations, reporters)
	if err := scan.Scan(ctx); err != nil {
		slog.Error("error running scan", "err", err.Error())
		return nil, err
	}
	return scan, nil
}

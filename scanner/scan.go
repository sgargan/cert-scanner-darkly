package scanner

import (
	"context"

	"github.com/sagikazarmark/slog-shim"
	"github.com/sgargan/cert-scanner-darkly/discovery"
	"github.com/sgargan/cert-scanner-darkly/processors"
	"github.com/sgargan/cert-scanner-darkly/reporters"
	"github.com/sgargan/cert-scanner-darkly/validations"
)

func PerformScan(ctx context.Context) error {
	discoveries, err := discovery.CreateDiscoveries()
	if err != nil {
		slog.Error("error configuring discovery mechanisms", "msg", err.Error())
		return err
	}

	processors, err := processors.CreateProcessors()
	if err != nil {
		slog.Error("error configuring processors", "msg", err.Error())
		return err
	}

	validations, err := validations.CreateValidations()
	if err != nil {
		slog.Error("error configuring validations", "msg", err.Error())
		return err
	}

	reporters, err := reporters.CreateReporters()
	if err != nil {
		slog.Error("error configuring reporters", "msg", err.Error())
		return err
	}

	CreateScan(discoveries, processors, validations, reporters).Scan(ctx)
	return nil
}

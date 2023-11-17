package scanner

import (
	"context"

	"github.com/sagikazarmark/slog-shim"
	"github.com/sgargan/cert-scanner-darkly/discovery"
	"github.com/sgargan/cert-scanner-darkly/reporters"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/sgargan/cert-scanner-darkly/validations"
)

func PerformScan(ctx context.Context, targets []*Target) error {

	discovery, err := discovery.CreateDiscoveries()
	if err != nil {
		slog.Error("error configuring discovery mechanisms", "msg", err.Error())
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

	scan := CreateScan(validations, reporters)

	scan.Validate(ctx)
	scan.Report(ctx)
	return nil
}

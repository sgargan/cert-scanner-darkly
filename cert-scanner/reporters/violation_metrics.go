package reporters

import (
	"context"

	"github.com/sgargan/cert-scanner-darkly/metrics"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

type ValidationMetricsReporter struct {
	timingMetric     func(float32, map[string]string)
	validationMetric func(map[string]string)
}

func CreateValidationMetricsReporter() (*ValidationMetricsReporter, error) {
	return &ValidationMetricsReporter{
		timingMetric:     metrics.Timing,
		validationMetric: metrics.Validation,
	}, nil
}

func (m *ValidationMetricsReporter) Report(ctx context.Context, scan *TargetScan) {
	for _, violation := range scan.Violations {
		m.validationMetric(violation.Labels())
	}
}

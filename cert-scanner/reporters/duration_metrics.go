package reporters

import (
	"context"

	"github.com/sgargan/cert-scanner-darkly/metrics"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

const (
	Success = "success"
	Failed  = "failed"
)

type DurationMetricsReporter struct {
	timingMetric     func(float32, map[string]string)
	validationMetric func(map[string]string)
}

func CreateMetricsReporter() (*DurationMetricsReporter, error) {
	return &DurationMetricsReporter{
		timingMetric:     metrics.Timing,
		validationMetric: metrics.Validation,
	}, nil
}

func (m *DurationMetricsReporter) Report(ctx context.Context, scan *TargetScan) {
	for _, result := range scan.Results {
		m.timingMetric(float32(result.Duration), result.Labels())
	}
}

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

var (
	DurationBuckets = []float64{5, 10, 50, 75, 100, 150, 300, 500, 750, 1000}

	DurationsLabelKeys = []string{
		"address", "source", "source_type", "failed", "type",
	}

	DurationsValidationsHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cert_scanner",
		Name:      "validation_durations",
		Help:      "histogram tracking durations of each validation",
		Buckets:   DurationBuckets,
	}, DurationsLabelKeys)
)

func CreateDurationsReporter(ignoreResultTypes []string) (Reporter, error) {
	return &HistogramReporter{
		ignoreResultTypes: ignoreResultTypes,
		requiredLabels:    DurationsLabelKeys,
		histogram:         DurationsValidationsHistogram,
	}, nil
}

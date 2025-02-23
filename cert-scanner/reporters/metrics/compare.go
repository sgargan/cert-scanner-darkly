package metrics

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

type MetricsScanComparator struct {
	metrics []*prometheus.MetricVec
}

// CreateMetricsComparator compares two scans in order to clear metrics for addresses that
// are no longer present in the current set.
func CreateMetricsComparator() *MetricsScanComparator {
	return &MetricsScanComparator{
		metrics: []*prometheus.MetricVec{
			ExpiryValidationsCounter.MetricVec,
			NotYetValidValidationsCounter.MetricVec,
			TLSVersionValidationsCounter.MetricVec,
			TrustChainValidationsCounter.MetricVec,
			DurationsValidationsHistogram.MetricVec,
		},
	}
}

func (m *MetricsScanComparator) Compare(previous, current CompletedScan) {
	currentSet := GetAddressSet(current)

	for _, previous := range previous.Results() {
		address := previous.Target.Address.String()
		if !currentSet.ContainsAddress(address) {
			slog.Debug("previous target address not in current scan results, removing from metrics", "address", address, "target", previous.Target.Name, "source", previous.Target.Source, "sourceType", previous.Target.SourceType)
			for _, metric := range m.metrics {
				metric.DeleteLabelValues(address)
			}
		}
	}
}

//go:generate mockery --name Counter
//go:generate mockery --name CounterVec
//go:generate mockery --name Histogram
//go:generate mockery --name HistogramVec
package metrics

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

const (
	ResultTypeLabel       = "type"
	ResultSourceTypeLabel = "source_type"
)

type CounterReporter struct {
	counter           CounterVec
	ignoreResultTypes []string
	requiredLabels    []string
	validationType    string
}

func (m *CounterReporter) Report(ctx context.Context, scan *TargetScan) {
	for _, violation := range scan.Violations {
		labels := violation.Labels()
		if isValidationType(m.validationType, labels) {
			allLabels := mergeLabels(labels, scan.Target.Labels())
			labelKeys := append(m.requiredLabels, GetAddtionalLabelsForSource(labels)...)
			filteredLabels := FilterLabelsValues(allLabels, labelKeys...)
			m.counter.WithLabelValues(filteredLabels...).Inc()
		}
	}
}

func (m *CounterReporter) Delete(address string) bool {
	return m.counter.DeleteLabelValues(address)
}

type HistogramReporter struct {
	histogram         HistogramVec
	ignoreResultTypes []string
	requiredLabels    []string
	validationType    string
}

func (m *HistogramReporter) Report(ctx context.Context, scan *TargetScan) {
	for _, violation := range scan.Violations {
		labels := violation.Labels()
		if isValidationType(m.validationType, labels) {
			allLabels := mergeLabels(labels, scan.Target.Labels())
			labelKeys := append(m.requiredLabels, GetAddtionalLabelsForSource(labels)...)
			filteredLabels := FilterLabelsValues(allLabels, labelKeys...)
			duration := float64(violation.Result().Duration.Milliseconds())
			m.histogram.WithLabelValues(filteredLabels...).Observe(duration)
		}
	}
}

func (m *HistogramReporter) Delete(address string) bool {
	return m.histogram.DeleteLabelValues(address)
}

// FilterLabelsValues filters a set of collected labels retrieving the values for a
// list of given keys.
func FilterLabelsValues(labels map[string]string, filterKeys ...string) []string {
	filtered := make([]string, 0)
	for _, labelKey := range filterKeys {
		labelValue, present := labels[labelKey]
		if !present {
			labelValue = "n/a"
		}
		filtered = append(filtered, labelValue)
	}

	return filtered
}

func isValidationType(violationType string, labels map[string]string) bool {
	resultType := labels["type"]
	return violationType != "" && resultType == violationType
}

// ShouldReportMetric tests if a result metric should be recorded, primarily this
// is used to filter fail
func ShouldReportMetric(result *ScanResult, required string, ignoredResultTypes []string) bool {
	resultType := result.Labels()["type"]
	for _, t := range ignoredResultTypes {
		if resultType == t {
			return false
		}
	}
	return !viper.GetBool("reporters.metrics.failuresOnly") || result.Failed
}

var additionalLabelsCache = make(map[string][]string, 0)

func GetAddtionalLabelsForSource(labels map[string]string) []string {
	source := labels["sourceType"]
	if cachedAddtionalLabels, ok := additionalLabelsCache[source]; !ok {
		additionalLabels := viper.GetStringSlice(fmt.Sprintf("discovery.%s.additionalLabels", source))
		additionalLabelsCache[source] = additionalLabels
		return additionalLabels
	} else {
		return cachedAddtionalLabels
	}
}

func mergeLabels(labelSets ...map[string]string) map[string]string {
	merged := make(map[string]string, 0)
	for _, labels := range labelSets {
		for k, v := range labels {
			merged[k] = v
		}
	}
	return merged
}

// these interfaces allow us to mock out the prometheus collectors for testing
type Counter interface {
	prometheus.Counter
}

type CounterVec interface {
	WithLabelValues(lvs ...string) prometheus.Counter
	DeleteLabelValues(lvs ...string) bool
}

type Histogram interface {
	prometheus.Histogram
}

type HistogramVec interface {
	WithLabelValues(lvs ...string) prometheus.Observer
	DeleteLabelValues(lvs ...string) bool
}

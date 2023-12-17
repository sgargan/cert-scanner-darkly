package reporters

import (
	"context"
	"fmt"

	"github.com/sgargan/cert-scanner-darkly/metrics"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

const (
	Success = "success"
	Failed  = "failed"
)

type MetricsReporter struct {
	timingMetric     func(float32, map[string]string)
	validationMetric func(map[string]string)
}

func CreateMetricsReporter() (*MetricsReporter, error) {
	return &MetricsReporter{
		timingMetric:     metrics.Timing,
		validationMetric: metrics.Validation,
	}, nil
}

func (m *MetricsReporter) Report(ctx context.Context, result *CertScanResult) {
	if result != nil && result.Target != nil {
		m.timingMetric(float32(result.Duration), result.Labels())
		for _, err := range result.Errors {
			labels := getCertificateLabels(result)
			for k, v := range err.Labels() {
				labels[k] = v
			}
			m.validationMetric(labels)
		}
	}
}

func getCertificateLabels(result *CertScanResult) map[string]string {
	labels := result.Labels()
	if result.State != nil && len(result.State.PeerCertificates) > 0 {
		labels["id"] = fmt.Sprintf("%x", result.State.PeerCertificates[0].SerialNumber)
		labels["common_name"] = result.State.PeerCertificates[0].Subject.CommonName
	}
	return labels
}

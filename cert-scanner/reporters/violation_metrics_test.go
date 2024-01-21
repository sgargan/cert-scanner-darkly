package reporters

import (
	"context"
	"math/big"
	"testing"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/sgargan/cert-scanner-darkly/validations"
	"github.com/stretchr/testify/suite"
)

type MetricsReporterTests struct {
	suite.Suite
	sut                      *ValidationMetricsReporter
	testScan                 *TestCertResult
	receivedDuration         float32
	receivedTimingLabels     map[string]string
	receivedValidationLabels map[string]string
}

func (t *MetricsReporterTests) SetupTest() {
	t.sut, _ = CreateValidationMetricsReporter()

	// mock out the actual metrics calls
	t.sut.timingMetric = t.mockTimingMetric
	t.sut.validationMetric = t.mockValidationMetric

	ca, _ := CreateTestCA(1)
	cert, _, _, _ := ca.CreateLeafCert("somehost")
	cert.SerialNumber = (&big.Int{}).SetBytes([]byte{1, 2, 3, 4})

	t.testScan = CreateTestTargetScan().WithCertificates(cert).WithTarget(target)

	t.receivedValidationLabels = nil
}

func (t *MetricsReporterTests) TestReportsViolationResultAsMetric() {

	result, err := createTestViolation()
	t.sut.Report(context.Background(), t.testScan.WithScanResult(result).WithViolation(err).Build())

	t.Equal(t.receivedValidationLabels,
		map[string]string{
			"address":          "172.1.2.34:8080",
			"common_name":      "somehost",
			"failed":           "true",
			"foo":              "bar",
			"id":               "1020304",
			"not_after":        "1673740800000",
			"source":           "SomePod-acdf-bdfe",
			"source_type":      "kubernetes",
			"type":             "expiry",
			"warning_duration": "168h0m0s",
		},
	)
}

func (t *MetricsReporterTests) mockTimingMetric(duration float32, labels map[string]string) {
	t.receivedDuration = duration
	t.receivedTimingLabels = labels
}

func (t *MetricsReporterTests) mockValidationMetric(labels map[string]string) {
	t.receivedValidationLabels = labels
}

func createTestViolation() (*ScanResult, ScanError) {
	warning := time.Duration(7 * 24 * time.Hour)
	expiry, _ := time.Parse(time.RFC3339, "2023-01-15T00:00:00Z")
	expiry.Add(-1*warning + (time.Hour))

	result := NewScanResult()
	result.Failed = true
	return result, validations.CreateExpiryValidationError(time.Duration(7*24*time.Hour), expiry, result)
}

func TestMetricsReporterTests(t *testing.T) {
	suite.Run(t, &MetricsReporterTests{})
}

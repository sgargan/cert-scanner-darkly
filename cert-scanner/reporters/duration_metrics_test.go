package reporters

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

type DurationMetricsReporterTests struct {
	suite.Suite
	sut                  *DurationMetricsReporter
	testScan             *TestCertResult
	receivedDuration     float32
	receivedTimingLabels map[string]string
}

func (t *DurationMetricsReporterTests) SetupTest() {
	t.sut, _ = CreateMetricsReporter()

	// mock out the actual metrics calls
	t.sut.timingMetric = t.mockTimingMetric

	ca, _ := CreateTestCA(1)
	cert, _, _, _ := ca.CreateLeafCert("somehost")
	cert.SerialNumber = (&big.Int{}).SetBytes([]byte{1, 2, 3, 4})

	t.testScan = CreateTestTargetScan().WithCertificates(cert).WithTarget(testutils.TestTarget())

	t.receivedDuration = 0
	t.receivedTimingLabels = nil
}

func (t *DurationMetricsReporterTests) TestReportsSuccessfulResultAsMetric() {
	scan := t.testScan.WithDuration(time.Duration(123)).Build()
	t.sut.Report(context.Background(), scan)

	t.Equal(float32(123), t.receivedDuration)
	t.Equal(map[string]string{
		"address":     "172.1.2.34:8080",
		"common_name": "somehost",
		"failed":      "false",
		"foo":         "bar",
		"id":          "1020304",
		"source":      "SomePod-acdf-bdfe",
		"source_type": "kubernetes",
	}, t.receivedTimingLabels)
}

func (t *DurationMetricsReporterTests) TestReportsFailureResultAsMetric() {
	result, err := createTestViolation()
	scan := t.testScan.WithScanResult(result).WithDuration(time.Duration(123)).WithViolation(err).Build()
	t.sut.Report(context.Background(), scan)

	t.Equal(float32(123), t.receivedDuration)
	t.Equal(map[string]string{
		"address":     "172.1.2.34:8080",
		"common_name": "somehost",
		"failed":      "true",
		"foo":         "bar",
		"id":          "1020304",
		"source":      "SomePod-acdf-bdfe",
		"source_type": "kubernetes",
	}, t.receivedTimingLabels)
}

func (t *DurationMetricsReporterTests) mockTimingMetric(duration float32, labels map[string]string) {
	t.receivedDuration = duration
	t.receivedTimingLabels = labels
}

func TestDurationMetricsReporterTests(t *testing.T) {
	suite.Run(t, &DurationMetricsReporterTests{})
}

package reporters

import (
	"context"
	"errors"
	"math/big"
	"net/netip"
	"testing"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

var target = &Target{
	Address: netip.MustParseAddrPort("172.1.2.34:8080"),
	Metadata: Metadata{
		Labels:     map[string]string{"foo": "bar"},
		SourceType: "kubernetes",
		Source:     "SomePod-acdf-bdfe",
	},
}

type MetricsReporterTests struct {
	suite.Suite
	sut                      *MetricsReporter
	testResult               *TestCertResult
	receivedDuration         float32
	receivedTimingLabels     map[string]string
	receivedValidationLabels map[string]string
}

func (t *MetricsReporterTests) SetupTest() {
	t.sut, _ = CreateMetricsReporter()

	// mock out the actual metrics calls
	t.sut.timingMetric = t.mockTimingMetric
	t.sut.validationMetric = t.mockValidationMetric

	ca, _ := CreateTestCA(1)
	cert, _, _, _ := ca.CreateLeafCert("somehost")
	cert.SerialNumber = (&big.Int{}).SetBytes([]byte{1, 2, 3, 4})

	t.testResult = CreateTestCertScanResult().WithCertificates(cert).WithTarget(target)

	t.receivedDuration = 0
	t.receivedTimingLabels = nil
	t.receivedValidationLabels = nil
}

func (t *MetricsReporterTests) TestReportsSuccessfulResultAsMetric() {
	result := t.testResult.Build()
	result.Duration = time.Duration(123)
	t.sut.Report(context.Background(), result)

	t.Equal(float32(123), t.receivedDuration)
	t.Equal(map[string]string{"address": "172.1.2.34:8080", "failed": "false", "foo": "bar", "source": "SomePod-acdf-bdfe", "source_type": "kubernetes"}, t.receivedTimingLabels)
	t.Equal(map[string]string(nil), t.receivedValidationLabels)
}

func (t *MetricsReporterTests) TestReportsFailureResultAsMetric() {
	err := CreateGenericError("some-error", errors.New("something-barfed"))
	result := t.testResult.WithError(err).Build()
	result.Duration = time.Duration(123)
	t.sut.Report(context.Background(), result)

	t.Equal(float32(123), t.receivedDuration)
	t.Equal(map[string]string{"address": "172.1.2.34:8080", "failed": "true", "foo": "bar", "source": "SomePod-acdf-bdfe", "source_type": "kubernetes"}, t.receivedTimingLabels)
	t.Equal(map[string]string{"address": "172.1.2.34:8080", "failed": "true", "foo": "bar", "source": "SomePod-acdf-bdfe", "source_type": "kubernetes", "type": "some-error", "common_name": "somehost", "id": "1020304"}, t.receivedValidationLabels)
}

func (t *MetricsReporterTests) mockTimingMetric(duration float32, labels map[string]string) {
	t.receivedDuration = duration
	t.receivedTimingLabels = labels
}

func (t *MetricsReporterTests) mockValidationMetric(labels map[string]string) {
	t.receivedValidationLabels = labels
}

func TestMetricsReporterTests(t *testing.T) {
	suite.Run(t, &MetricsReporterTests{})
}

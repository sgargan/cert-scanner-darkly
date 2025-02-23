package metrics

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/reporters/metrics/mocks"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

type MetricsReporterTests struct {
	suite.Suite
}

func (t *MetricsReporterTests) TestCounterReporterIncrementsCounter() {
	counter := &mocks.Counter{}
	counterVec := &mocks.CounterVec{}

	counterVec.On("WithLabelValues", "172.1.2.34:8080", "some-cluster", "kubernetes", "somepod-acdf-bdfe").Return(counter)
	counter.On("Inc").Return()

	reporter := CounterReporter{
		counter:           counterVec,
		ignoreResultTypes: []string{},
		requiredLabels:    []string{"address", "source", "source_type", "pod"},
		validationType:    "some-error",
	}

	testResult := t.createTestScan()
	reporter.Report(context.Background(), testResult)

	counterVec.AssertExpectations(t.T())
	counter.AssertExpectations(t.T())
}

func (t *MetricsReporterTests) TestHistogramReporterIncrementsCounter() {
	histogram := &mocks.Histogram{}
	histogramVec := &mocks.HistogramVec{}

	histogramVec.On("WithLabelValues", "172.1.2.34:8080", "some-cluster", "kubernetes", "somepod-acdf-bdfe").Return(histogram)
	histogram.On("Observe", 123.0).Return()

	reporter := HistogramReporter{
		histogram:         histogramVec,
		ignoreResultTypes: []string{},
		requiredLabels:    []string{"address", "source", "source_type", "pod"},
		validationType:    "some-error",
	}

	testResult := t.createTestScan()
	reporter.Report(context.Background(), testResult)

	histogramVec.AssertExpectations(t.T())
	histogram.AssertExpectations(t.T())
}

func (t *MetricsReporterTests) createTestScan() *TargetScan {
	testScan := CreateTestTargetScan().WithTarget(TestTarget())
	violation := func(result *ScanResult) ScanError {
		return CreateGenericError("some-error", fmt.Errorf("there was some scanning error or violation"), result)
	}
	return testScan.WithDuration(time.Duration(123 * time.Millisecond)).WithViolation(violation).Build()
}

func TestMetricsReporterTests(t *testing.T) {
	suite.Run(t, &MetricsReporterTests{})
}

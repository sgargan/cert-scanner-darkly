package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/reporters/metrics/mocks"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ScanStatsReporterTests struct {
	sut          *ScanStatsReporter
	histogram    *mocks.Histogram
	histogramVec *mocks.HistogramVec
	counter      *mocks.Counter
	counterVec   *mocks.CounterVec
	suite.Suite
}

func (t *ScanStatsReporterTests) SetupTest() {
	t.histogram = &mocks.Histogram{}
	t.histogramVec = &mocks.HistogramVec{}

	t.counter = &mocks.Counter{}
	t.counterVec = &mocks.CounterVec{}

	t.sut = &ScanStatsReporter{
		tlsVersionCounter:     t.counterVec,
		scanDurationHistogram: t.histogramVec,
	}
}

func (t *ScanStatsReporterTests) TestShouldMetricsFromSuccessfulScan() {
	t.counterVec.On("WithLabelValues", "some-cluster", "kubernetes", "somepod-acdf-bdfe", "true", "1.2", "TLS_AES_128_GCM_SHA256").Return(t.counter)
	t.counter.On("Inc").Return()

	t.histogramVec.On("WithLabelValues", "some-cluster", "kubernetes", "true").Return(t.histogram)
	t.histogram.On("Observe", 123.0).Return()

	testScan := CreateTestTargetScan().WithTarget(TestTarget()).Build()
	testScan.Duration = 123 * time.Millisecond
	t.sut.Report(context.Background(), testScan)

	t.assertions()
}

func (t *ScanStatsReporterTests) TestShouldSkipFailedScansIfOnlySuccessfulIsEnabled() {
	viper.Set("reporters.scan_stats.only_successful", true)
	defer viper.Reset()

	t.histogramVec.On("WithLabelValues", "some-cluster", "kubernetes", "false").Return(t.histogram)
	t.histogram.On("Observe", 123.0).Return()

	testScan := CreateTestTargetScan().WithTarget(TestTarget()).Build()
	testScan.Results[0].Failed = true

	testScan.Duration = 123 * time.Millisecond
	t.sut.Report(context.Background(), testScan)

	t.assertions()
}

func (t *ScanStatsReporterTests) assertions() {
	t.counterVec.AssertExpectations(t.T())
	t.counter.AssertExpectations(t.T())

	t.histogramVec.AssertExpectations(t.T())
	t.histogram.AssertExpectations(t.T())
}

func TestScanStatsReporter(t *testing.T) {
	suite.Run(t, new(ScanStatsReporterTests))
}

package metrics

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestFilterLabelsValues(t *testing.T) {
	labels := map[string]string{"foo": "bar", "type": "tls-handshake", "source": "kubernetes"}

	require.Equal(t, FilterLabelsValues(labels, "foo"), []string{"bar"})
	require.Equal(t, FilterLabelsValues(labels, "doesnotexist"), []string{"n/a"})
	require.Equal(t, FilterLabelsValues(labels, "foo", "type"), []string{"bar", "tls-handshake"})
	require.Equal(t, FilterLabelsValues(map[string]string{}, "foo", "type"), []string{"n/a", "n/a"})
}

func TestShouldReportMetric(t *testing.T) {
	result := createTestResult()
	testShouldReport(t, result, true)

	result.Failed = true
	testShouldReport(t, result, true)
}

func TestShouldOnlyReportFailures(t *testing.T) {
	viper.Set("reporters.metrics.failuresOnly", true)
	defer viper.Reset()
	result := createTestResult()
	testShouldReport(t, result, false)

	result.Failed = true
	testShouldReport(t, result, true)
}

func TestShouldReportFilterIgnoredLabels(t *testing.T) {
	result := createTestResult()
	testShouldReport(t, result, false, "tls-handshake")
	testShouldReport(t, result, true, "not-filtered")
}

func testShouldReport(t *testing.T, result *ScanResult, expected bool, ignoredTypes ...string) {
	require.Equal(t, expected, ShouldReportMetric(result, "", ignoredTypes))
}

func createTestResult() *ScanResult {
	target := testutils.TestTarget()
	target.Metadata.Labels["type"] = "tls-handshake"
	return testutils.CreateTestTargetScan().WithTarget(target).Build().Results[0]
}

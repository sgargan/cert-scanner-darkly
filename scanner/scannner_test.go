package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"

	"github.com/stretchr/testify/suite"
)

type ScannerTests struct {
	suite.Suite
}

func (t *ScannerTests) TestValidScanCallsAllValidations() {
	validations := make([]Validation, 0)
	reporters := make([]Reporter, 0)
	for x := 0; x < 10; x++ {
		validations = append(validations, &MockValidation{results: make([]*CertScanResult, 0)})
		reporters = append(reporters, &MockReporter{results: make([]*CertScanResult, 0)})
	}
	scan := CreateScan(validations, reporters)
	addResults(scan)

	scan.Validate(context.Background())

	for x := 0; x < 10; x++ {
		v := validations[x].(*MockValidation)
		t.True(v.called)
		t.Equal(10, len(v.results))
	}
}

func (t *ScannerTests) TestValidScanCallsAllReporters() {
	reporters := make([]Reporter, 0)
	for x := 0; x < 10; x++ {
		reporters = append(reporters, &MockReporter{results: make([]*CertScanResult, 0)})
	}

	scan := CreateScan(nil, reporters)
	addResults(scan)
	scan.Report(context.Background())

	for x := 0; x < 10; x++ {
		r := reporters[x].(*MockReporter)
		t.True(r.called)
		t.Equal(10, len(r.results))
	}
}

func (t *ScannerTests) TestCallsRetrieval() {
	scan := CreateScan(nil, nil)
	scan.Retrieve(context.Background(), GetTestTargets())
	t.Greater(len(scan.Results), 0)
}

func (t *ScannerTests) TestBatchSizeRetrieval() {
	t.Equal(getBatchSize(), runtime.NumCPU())
	viper.Set("batch.processors", 16)
	t.Equal(getBatchSize(), 16)
}

func addResults(scan *Scan) {
	for x := 0; x < 10; x++ {
		result := CreateTestCertScanResult().WithTarget(
			&Target{
				Address: netip.MustParseAddrPort(fmt.Sprintf("123.123.231.231:%d", x)),
			})
		scan.AddResult(result.Build())
	}
}

type MockValidation struct {
	sync.Mutex
	err     ScanError
	called  bool
	results []*CertScanResult
}

func (m *MockValidation) Validate(result *CertScanResult) ScanError {
	m.Lock()
	defer m.Unlock()
	m.called = true
	m.results = append(m.results, result)
	return m.err
}

type MockReporter struct {
	sync.Mutex
	called  bool
	results []*CertScanResult
}

func (m *MockReporter) Report(ctx context.Context, result *CertScanResult) {
	m.Lock()
	defer m.Unlock()
	m.called = true
	m.results = append(m.results, result)
}

func TestScannerTests(t *testing.T) {
	suite.Run(t, &ScannerTests{})
}

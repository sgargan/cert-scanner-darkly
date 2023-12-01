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
	sut         *Scan
	discoveries Discoveries
	processors  Processors
	validations Validations
	reporters   Reporters
}

func (t *ScannerTests) SetupTest() {
	t.discoveries = make(Discoveries, 0)
	t.processors = make(Processors, 0)
	t.validations = make(Validations, 0)
	t.reporters = make(Reporters, 0)
	for x := 0; x < 10; x++ {
		t.discoveries = append(t.discoveries, &MockDiscovery{})
		t.processors = append(t.processors, &MockProcessor{})
		t.validations = append(t.validations, &MockValidation{results: make([]*CertScanResult, 0)})
		t.reporters = append(t.reporters, &MockReporter{results: make([]*CertScanResult, 0)})
	}
	t.sut = CreateScan(t.discoveries, t.processors, t.validations, t.reporters)
}

func (t *ScannerTests) TestValidScanCallsAllDiscoveries() {
	targets, err := t.sut.discover(context.Background())
	t.NoError(err)
	t.Equal(100, len(targets))
	for x := 0; x < 10; x++ {
		m := t.discoveries[x].(*MockDiscovery)
		t.True(m.called)
	}
}

func (t *ScannerTests) TestValidScanCallsProcessOnAllTargets() {
	targets, _ := t.sut.discover(context.Background())
	t.NoError(t.sut.process(context.Background(), targets))
	t.Equal(1000, len(t.sut.Results))

	for x := 0; x < 10; x++ {
		r := t.sut.processors[x].(*MockProcessor)
		t.True(r.called)
	}
}

func (t *ScannerTests) TestValidScanCallsAllValidations() {
	t.sut.Scan(context.Background())
	for x := 0; x < 10; x++ {
		v := t.validations[x].(*MockValidation)
		t.True(v.called)
		t.Equal(1000, len(v.results))
	}
}

func (t *ScannerTests) TestValidScanCallsAllReporters() {
	t.sut.Scan(context.Background())
	for x := 0; x < 10; x++ {
		r := t.reporters[x].(*MockReporter)
		t.True(r.called)
		t.Equal(1000, len(r.results))
	}
}

func (t *ScannerTests) TestErrorDuringDiscovery() {
	t.discoveries = Discoveries{
		&MockDiscovery{err: fmt.Errorf("something barfed during discovery")},
	}
	err := CreateScan(t.discoveries, nil, nil, nil).Scan(context.Background())
	t.ErrorContains(err, "something barfed during discovery")
}

func (t *ScannerTests) TestBatchSizeRetrieval() {
	t.Equal(getBatchSize(), runtime.NumCPU())
	viper.Set("batch.processors", 16)
	t.Equal(getBatchSize(), 16)
}

type MockDiscovery struct {
	sync.Mutex
	err    error
	called bool
}

func (m *MockDiscovery) Discover(ctx context.Context, targets chan *Target) error {
	m.Lock()
	defer m.Unlock()
	m.called = true
	for x := 0; x < 10; x++ {
		targets <- &Target{
			Address: netip.MustParseAddrPort(fmt.Sprintf("123.123.231.231:%d", x)),
		}
	}
	return m.err
}

type MockProcessor struct {
	sync.Mutex
	err    ScanError
	called bool
}

func (m *MockProcessor) Process(ctx context.Context, target *Target) *CertScanResult {
	m.Lock()
	defer m.Unlock()
	m.called = true
	return CreateTestCertScanResult().WithTarget(target).Build()
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

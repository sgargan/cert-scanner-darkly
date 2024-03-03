package types

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type Labels = map[string]string

// Target represents a discovered service running on a given address and port
// that may be TLS enabled
type Target struct {
	Metadata
	Address netip.AddrPort
}

func (t *Target) Labels() Labels {
	copy := Labels{
		"source":      t.Source,
		"source_type": t.SourceType,
		"address":     t.Address.String(),
	}
	for k, v := range t.Metadata.Labels {
		copy[k] = v
	}
	return copy
}

type Metadata struct {
	Name       string
	Source     string
	SourceType string
	Labels     Labels
}

// TargetScan captures the state gathered from scanning a single target. This will consist
// of one or more Scan results.
type TargetScan struct {
	sync.Mutex
	Target          *Target
	Results         []*ScanResult
	scanTime        time.Time
	Duration        time.Duration
	Failed          bool
	FirstSuccessful *ScanResult
	Violations      []ScanError
}

func NewTargetScanResult(target *Target) *TargetScan {
	return &TargetScan{
		Target:     target,
		scanTime:   time.Now(),
		Violations: make([]ScanError, 0),
	}
}

// AddViolation adds a detected violation for one ScanResult to the target scan
func (t *TargetScan) AddViolation(violation ScanError) {
	if violation != nil {
		t.Violations = append(t.Violations, violation)
	}
}

// Add the result of scanning the target with a single protocol and version to the TargetScan
func (t *TargetScan) Add(r *ScanResult) {
	t.Lock()
	defer t.Unlock()
	r.target = t.Target
	t.Results = append(t.Results, r)
	t.Duration = time.Since(t.scanTime)
	if !r.Failed && t.FirstSuccessful == nil {
		t.FirstSuccessful = r
	}
}

func (t *TargetScan) ShouldValidate() bool {
	return !t.Failed && t.FirstSuccessful != nil
}

// ScanResult is the state detected from a single scan of a target with a specific TLS
// cipher and version.
type ScanResult struct {
	State    *tls.ConnectionState
	Cipher   *tls.CipherSuite
	scanTime time.Time
	Duration time.Duration
	Failed   bool
	Error    ScanError
	target   *Target
}

func NewScanResult() *ScanResult {
	return &ScanResult{
		scanTime: time.Now(),
	}
}

func (s *ScanResult) SetState(state *tls.ConnectionState, cipher *tls.CipherSuite, err ScanError) {
	s.Duration = time.Since(s.scanTime)
	s.State = state
	s.Cipher = cipher
	s.Failed = err != nil
	s.Error = err
}

// Labels returns a copy of the result targets labels
func (s *ScanResult) Labels() map[string]string {
	copy := s.target.Labels()
	if s.Failed {
		copy["failed"] = "true"
	} else {
		copy["failed"] = "false"
	}

	if s.Error != nil {
		for k, v := range s.Error.Labels() {
			copy[k] = v
		}
	}

	if s.State != nil && len(s.State.PeerCertificates) > 0 {
		copy["id"] = fmt.Sprintf("%x", s.State.PeerCertificates[0].SerialNumber)
		copy["common_name"] = s.State.PeerCertificates[0].Subject.CommonName
	}
	return copy
}

type Factory[T comparable] func() (T, error)

// Discovery is implemented by various integrations that can discover tls services
type Discovery interface {
	// Discover [Target]s, emitting them to th given channel. Raises an error if there
	// is any problem during discovery
	Discover(ctx context.Context, targets chan *Target) error
}

type Discoveries = []Discovery

// Processor will be implemented by modules interested in examining discovered [Target]s.
type Processor interface {

	// Process a given target returning a TargetScan
	Process(ctx context.Context, target *Target, results chan<- *TargetScan)
}

type Processors = []Processor

// Validation makes a single cert validation request against a received certificate result
type Validation interface {

	// Validate runs the single validation against the given result, returning an error if
	// the result state fails the validation or nil if the validation passes.
	Validate(result *TargetScan) ScanError
}

type Validations = []Validation

// Reporter will be implemented by modules interested in acting on ScanResults. Typically theses
// report on Violations dected during the scan, but they have access to the entire TargetScan so
// can report on any aspect
type Reporter interface {

	// Report will inspect the given scan and determine if it should report on the outcome.
	Report(ctx context.Context, scan *TargetScan)
}

type Reporters = []Reporter

// ScanError is a wrapper interface for errors that provides a type string for use in reporting
type ScanError interface {
	Labels() map[string]string

	Error() string
}

const (
	ConnectionError = "connection-error"
	HandshakeError  = "tls-handshake"
)

type GenericScanError struct {
	errorType string
	error
}

func (e *GenericScanError) Labels() map[string]string {
	return map[string]string{"type": e.errorType}
}

func CreateGenericError(errorType string, err error) ScanError {
	return &GenericScanError{errorType: errorType, error: err}
}

func IsError(err error, errorType string) bool {
	generic, isGeneric := err.(*GenericScanError)
	return isGeneric && generic.errorType == errorType
}

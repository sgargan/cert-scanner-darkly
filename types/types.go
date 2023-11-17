package types

import (
	"context"
	"crypto/tls"
	"net/netip"
	"time"
)

// Target represents a discovered service running on a given address and port
// that may be TLS enabled
type Target struct {
	Metadata
	Address netip.AddrPort
}

type Labels = map[string]string

type Metadata struct {
	Name       string
	Source     string
	SourceType string
	Labels     map[string]string
}

type CertScanResult struct {
	State    *tls.ConnectionState
	Target   *Target
	scanTime time.Time
	Failed   bool
	Duration time.Duration
	Errors   []ScanError
}

func NewCertScanResult(target *Target) *CertScanResult {
	return &CertScanResult{
		Target:   target,
		scanTime: time.Now(),
	}
}

func (c *CertScanResult) SetState(state *tls.ConnectionState, err ScanError) {
	c.Duration = time.Since(c.scanTime)
	c.State = state
	c.Fail(err)
}

func (c *CertScanResult) Fail(err ScanError) {
	if err != nil {
		c.Failed = true
		c.Errors = append(c.Errors, err)
	}
}

// Labels returns a copy of the result targets labels
func (c *CertScanResult) Labels() map[string]string {
	failed := "false"
	if c.Failed {
		failed = "true"
	}

	copy := map[string]string{
		"source":      c.Target.Source,
		"source_type": c.Target.SourceType,
		"failed":      failed,
	}
	for k, v := range c.Target.Labels {
		copy[k] = v
	}
	return copy
}

// Discovery is implemented by various integrations that can discover tls services
type Discovery interface {
	Discover(ctx context.Context) ([]*Target, error)
}

type Discoveries = []Discovery

type DiscoveryFactory = func() (Discovery, error)

// Validation makes a single cert validation request against a received certificate result
type Validation interface {

	// Validate runs the single validation against the given result, returning an error if
	// the result state fails the validation or nil if the validation passes.
	Validate(result *CertScanResult) ScanError
}

type Validations = []Validation

type ValidationFactory = func() (Validation, error)

// Reporter will be implemented by modules interested in acting on ScanResults. They can be used to
// audit the various certificates in use or alert on any violations that are detected.
type Reporter interface {

	// Report will inspect the given result and determine if it should report on the outcome.
	Report(ctx context.Context, result *CertScanResult)
}

type Reporters = []Reporter

type ReporterFactory = func() (Reporter, error)

// ScanError is a wrapper interface for errors that provides a type string for use in reporting
type ScanError interface {
	Labels() map[string]string

	Error() string
}

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

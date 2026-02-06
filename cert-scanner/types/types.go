package types

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

type Labels = map[string]string

// Address is the location that will be connected to for scanning.
// it is typically an net.IP or a url
type Address interface {
	Connect(context context.Context) (net.Conn, error)
	String() string
	ValidateHostname() bool
}

type NetIPAddress struct {
	ip netip.AddrPort
}

func CreateNetIPAddress(ip netip.AddrPort) *NetIPAddress {
	return &NetIPAddress{
		ip: ip,
	}
}

func (n *NetIPAddress) Connect(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 1 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp", n.ip.String())
}

// NetIp does not validate the hostname as part of the tls handshake
func (n *NetIPAddress) ValidateHostname() bool {
	return false
}

func (n *NetIPAddress) String() string {
	return n.ip.String()
}

type UrlAddress struct {
	url *url.URL
}

func ParseUrlAddress(u string) (*UrlAddress, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	return CreateUrlAddress(parsed), nil
}

func CreateUrlAddress(url *url.URL) *UrlAddress {
	return &UrlAddress{
		url: url,
	}
}

func (n *UrlAddress) Connect(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 1 * time.Second,
	}
	port := n.url.Port()
	if port == "" && (n.url.Scheme == "tls" || n.url.Scheme == "https") {
		port = "443"
	}
	return dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", n.url.Host, port))
}

// URLs shoud validate the hostname as part of the tls handshake
func (n *UrlAddress) ValidateHostname() bool {
	return true
}

func (n *UrlAddress) String() string {
	return n.url.Hostname()
}

// Target represents a discovered service running on a given address and port
// that may be TLS enabled
type Target struct {
	Metadata
	Address Address
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

// Metadata describes the common information about a Target
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

func (t *TargetScan) Failed() bool {
	for _, result := range t.Results {
		if result.Failed {
			return true
		}
	}
	return false
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

// Factory is a simple interface used dynamically create resources based on the
// presence/value of configuration vars
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

	Result() *ScanResult

	Error() string
}

// CompletedScan
type CompletedScan interface {
	Results() []*TargetScan
}

// AddressSet represents all the results of a scan, indexed by Target address
type AddressSet map[string]*TargetScan

func GetAddressSet(scan CompletedScan) AddressSet {
	set := make(AddressSet, 0)
	for _, result := range scan.Results() {
		address := result.Target.Address.String()
		set[address] = result
	}
	return set
}

func (a AddressSet) ContainsAddress(address string) bool {
	_, present := a[address]
	return present
}

const (
	ConnectionError = "connection-error"
	HandshakeError  = "tls-handshake"
)

type GenericScanError struct {
	result    *ScanResult
	errorType string
	error
}

func (e *GenericScanError) Labels() map[string]string {
	return map[string]string{"type": e.errorType}
}

func (e *GenericScanError) Result() *ScanResult {
	return e.result
}

func CreateGenericError(errorType string, err error, result *ScanResult) ScanError {
	return &GenericScanError{
		errorType: errorType,
		error:     err,
		result:    result,
	}
}

func IsError(err error, errorType string) bool {
	generic, isGeneric := err.(*GenericScanError)
	return isGeneric && generic.errorType == errorType
}

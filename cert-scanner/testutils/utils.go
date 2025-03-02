package testutils

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

type TestCertificate struct {
	x509.Certificate
	ca *TestCA
}

func CreateTestCert() *TestCertificate {

	return &TestCertificate{
		Certificate: x509.Certificate{
			SerialNumber: big.NewInt(12345),
			Subject: pkix.Name{
				Organization: []string{"Cert Scanner"},
				Country:      []string{"US"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  false,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		},
	}
}

func (tc *TestCertificate) WithBefore(date time.Time) *TestCertificate {
	tc.Certificate.NotBefore = date
	return tc
}

func (tc *TestCertificate) WithAfter(date time.Time) *TestCertificate {
	tc.Certificate.NotAfter = date
	return tc
}

func (tc *TestCertificate) WithCA(ca *TestCA) *TestCertificate {
	tc.ca = ca
	return tc
}

func (tc *TestCertificate) Build() (cert *x509.Certificate, err error) {
	cert = &tc.Certificate
	if tc.ca != nil {
		cert, _, _, err = tc.ca.CreateLeafFromTemplate(cert)
	}
	return cert, err
}

type TestCertResult struct {
	target    *Target
	err       ScanError
	violation func(*ScanResult) ScanError
	duration  time.Duration
	result    *ScanResult
	tls.ConnectionState
}

func CreateTestTargetScan() *TestCertResult {
	return &TestCertResult{
		target: &Target{},
		ConnectionState: tls.ConnectionState{
			Version:          tls.VersionTLS12,
			CipherSuite:      tls.TLS_AES_256_GCM_SHA384,
			PeerCertificates: []*x509.Certificate{},
			VerifiedChains:   [][]*x509.Certificate{},
		},
	}
}

func (tc *TestCertResult) WithTarget(target *Target) *TestCertResult {
	tc.target = target
	return tc
}

func (tc *TestCertResult) WithError(err ScanError) *TestCertResult {
	tc.err = err
	return tc
}

func (tc *TestCertResult) WithViolation(violation func(result *ScanResult) ScanError) *TestCertResult {
	tc.violation = violation
	return tc
}

func (tc *TestCertResult) WithTLSVersion(version uint16) *TestCertResult {
	tc.Version = version
	return tc
}

func (tc *TestCertResult) WithCertificates(certs ...*x509.Certificate) *TestCertResult {
	tc.PeerCertificates = certs
	return tc
}

func (tc *TestCertResult) WithCipherSuite(suite *tls.CipherSuite) *TestCertResult {
	tc.result.Cipher = suite
	return tc
}

func (tc *TestCertResult) WithDuration(duration time.Duration) *TestCertResult {
	tc.duration = duration
	return tc
}

func (tc *TestCertResult) WithScanResult(result *ScanResult) *TestCertResult {
	tc.result = result
	return tc
}

func (tc *TestCertResult) Build() *TargetScan {
	scan := NewTargetScanResult(tc.target)

	result := tc.result
	if result == nil {
		result = NewScanResult()
		result.Cipher = tls.CipherSuites()[0]
	}

	result.SetState(&tc.ConnectionState, result.Cipher, tc.err)
	result.Duration = tc.duration

	if tc.violation != nil {
		scan.AddViolation(tc.violation(result))
		result.Failed = true
	}

	scan.Add(result)
	result.Duration = tc.duration
	return scan
}

func TestTarget() *Target {
	return &Target{
		Address: CreateNetIPAddress(netip.MustParseAddrPort("172.1.2.34:8080")),
		Metadata: Metadata{
			Labels:     map[string]string{"foo": "bar", "pod": "somepod-acdf-bdfe"},
			SourceType: "kubernetes",
			Source:     "some-cluster",
		},
	}
}

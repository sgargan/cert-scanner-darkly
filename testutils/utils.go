package testutils

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
	target *Target
	err    ScanError
	CertScanResult
	tls.ConnectionState
}

func CreateTestCertScanResult() *TestCertResult {
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

func (tc *TestCertResult) WithTLSVersion(version uint16) *TestCertResult {
	tc.Version = version
	return tc
}

func (tc *TestCertResult) WithCertificates(certs ...*x509.Certificate) *TestCertResult {
	tc.PeerCertificates = certs
	return tc
}

func (tc *TestCertResult) Build() *CertScanResult {
	result := NewCertScanResult(tc.target)
	result.SetState(&tc.ConnectionState, tc.err)
	return result
}

package validations

import (
	"crypto/tls"
	"testing"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

type CipherSuiteValidationTests struct {
	suite.Suite
	scan           *TargetScan
	allowedCiphers []string
	allCiphers     []*tls.CipherSuite
}

func (t *CipherSuiteValidationTests) SetupTest() {
	t.allCiphers = tls.CipherSuites()
	// Use the first two ciphers as the allowed list
	t.allowedCiphers = []string{
		t.allCiphers[0].Name,
		t.allCiphers[1].Name,
	}

	cert := testutils.CreateTestCert()
	t.scan = CreateTestTargetScan().
		WithCertificates(&cert.Certificate).
		WithTarget(testutils.TestTarget()).
		Build()
}

func (t *CipherSuiteValidationTests) TestCipherIsAllowed() {
	validation, err := CreateCipherSuiteValidation(t.allowedCiphers)
	t.NoError(err)

	t.scan.Results[0].Cipher = t.allCiphers[0]
	t.NoError(validation.Validate(t.scan))

	t.scan.Results[0].Cipher = t.allCiphers[1]
	t.NoError(validation.Validate(t.scan))
}

func (t *CipherSuiteValidationTests) TestCipherNotAllowed() {
	validation, err := CreateCipherSuiteValidation(t.allowedCiphers)
	t.NoError(err)

	disallowedCipher := t.allCiphers[len(t.allCiphers)-1]
	t.scan.Results[0].Cipher = disallowedCipher

	err = validation.Validate(t.scan)
	t.Error(err)
	t.Contains(err.Error(), "negotiated cipher that was not in the configured allowed list of ciphers")
}

func (t *CipherSuiteValidationTests) TestLabelsOnViolation() {
	validation, err := CreateCipherSuiteValidation(t.allowedCiphers)
	t.NoError(err)

	disallowedCipher := t.allCiphers[len(t.allCiphers)-1]
	t.scan.Results[0].Cipher = disallowedCipher

	violation := validation.Validate(t.scan)
	t.Error(violation)

	labels := violation.Labels()
	t.Equal("require_tls", labels["type"])
	t.Equal("172.1.2.34:8080", labels["address"])
}

func (t *CipherSuiteValidationTests) TestEmptyAllowedCiphersList() {
	_, err := CreateCipherSuiteValidation([]string{})
	t.Error(err)
	t.Contains(err.Error(), "no allowed ciphers configured")
}

func (t *CipherSuiteValidationTests) TestInvalidCipherName() {
	_, err := CreateCipherSuiteValidation([]string{"INVALID_CIPHER_NAME"})
	t.Error(err)
	t.Contains(err.Error(), "configured cipher INVALID_CIPHER_NAME not present in available tls.CipherSuite")
}

func (t *CipherSuiteValidationTests) TestMixedValidAndInvalidCiphers() {
	_, err := CreateCipherSuiteValidation([]string{t.allCiphers[0].Name, "INVALID_CIPHER"})
	t.Error(err)
	t.Contains(err.Error(), "configured cipher INVALID_CIPHER not present in available tls.CipherSuite")
}

func (t *CipherSuiteValidationTests) TestMultipleResults() {
	validation, err := CreateCipherSuiteValidation(t.allowedCiphers)
	t.NoError(err)

	cert := testutils.CreateTestCert()

	result1 := NewScanResult()
	result1.Cipher = t.allCiphers[0]
	result1.SetState(&tls.ConnectionState{}, result1.Cipher, nil)

	result2 := NewScanResult()
	result2.Cipher = t.allCiphers[len(t.allCiphers)-1]
	result2.SetState(&tls.ConnectionState{}, result2.Cipher, nil)

	scan := CreateTestTargetScan().
		WithCertificates(&cert.Certificate).
		WithTarget(testutils.TestTarget()).
		Build()

	scan.Results = []*ScanResult{result1, result2}

	err = validation.Validate(scan)
	t.Error(err)
	t.Contains(err.Error(), "negotiated cipher that was not in the configured allowed list of ciphers")
}

func (t *CipherSuiteValidationTests) TestAllResultsAllowed() {
	validation, err := CreateCipherSuiteValidation(t.allowedCiphers)
	t.NoError(err)

	cert := testutils.CreateTestCert()

	result1 := NewScanResult()
	result1.Cipher = t.allCiphers[0]
	result1.SetState(&tls.ConnectionState{}, result1.Cipher, nil)

	result2 := NewScanResult()
	result2.Cipher = t.allCiphers[1]
	result2.SetState(&tls.ConnectionState{}, result2.Cipher, nil)

	scan := CreateTestTargetScan().
		WithCertificates(&cert.Certificate).
		WithTarget(testutils.TestTarget()).
		Build()

	scan.Results = []*ScanResult{result1, result2}

	t.NoError(validation.Validate(scan))
}

func (t *CipherSuiteValidationTests) TestNilResults() {
	validation, err := CreateCipherSuiteValidation(t.allowedCiphers)
	t.NoError(err)

	// Create a scan with nil results
	scan := NewTargetScanResult(testutils.TestTarget())
	scan.Results = nil

	// Should not panic and pass without error
	t.NotPanics(func() {
		err := validation.Validate(scan)
		t.NoError(err)
	})
}

func TestCipherSuiteValidations(t *testing.T) {
	suite.Run(t, &CipherSuiteValidationTests{})
}

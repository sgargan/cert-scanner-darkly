package validations

import (
	"crypto/tls"
	"testing"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

type TLSVersionValidationTests struct {
	suite.Suite
}

func (t *TLSVersionValidationTests) TestIsValidVersion() {
	TLSVersionValidation, _ := CreateTLSVersionValidation("1.2")
	result := CreateTestCertScanResult().WithTLSVersion(tls.VersionTLS12)
	t.NoError(TLSVersionValidation.Validate(result.Build()))
	t.NoError(TLSVersionValidation.Validate(result.WithTLSVersion(tls.VersionTLS13).Build()))
}

func (t *TLSVersionValidationTests) TestInValidVersion() {
	TLSVersionValidation, _ := CreateTLSVersionValidation("1.2")
	result := CreateTestCertScanResult().WithTLSVersion(tls.VersionTLS11).Build()
	t.ErrorContains(TLSVersionValidation.Validate(result), "connection supports an invalid tls version 1.1, min version is 1.2")
}

func (t *TLSVersionValidationTests) TestTLSVersionValidationCreation() {
	for _, version := range []string{"1.0", "1.1", "1.2", "1.3"} {
		_, err := CreateTLSVersionValidation(version)
		t.NoError(err)
	}
	_, err := CreateTLSVersionValidation("???")
	t.ErrorContains(err, "??? is not a valid tls version string use one of 1.0, 1.1, 1.2, 1.3")
}

func (t *TLSVersionValidationTests) TestLabels() {
	err := TLSVersionValidationError{
		detectedVersion: "1.1",
		minVersion:      "1.3",
	}
	t.Equal(map[string]string{
		"type":             "tls_version",
		"min_version":      "1.3",
		"detected_version": "1.1",
	}, err.Labels())
}

func (t *TLSVersionValidationTests) TestConversions() {
	t.assertVersion("1.3")
	t.assertVersion("1.2")
	t.assertVersion("1.1")
	t.assertVersion("1.0")
	t.Equal("unknown", toVersion(1234))

	_, err := fromVersion("not_a_tls_version")
	t.ErrorContains(err, "not_a_tls_version is not a valid tls version string use one of 1.0, 1.1, 1.2, 1.3")

}

func (t *TLSVersionValidationTests) assertVersion(version string) {
	converted, err := fromVersion(version)
	t.NoError(err)
	t.Equal(version, toVersion(converted))
}

func TestTLSVersionValidations(t *testing.T) {
	suite.Run(t, &TLSVersionValidationTests{})
}

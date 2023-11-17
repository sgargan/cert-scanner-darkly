package validations

import (
	"testing"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

type BeforeValidationTests struct {
	suite.Suite
}

func (t *BeforeValidationTests) TestIsCurrentlyValid() {
	cert := CreateTestCert().WithBefore(time.Now().Add(-1 * day))
	result := CreateTestCertScanResult().WithCertificates(&cert.Certificate).Build()
	t.NoError((&BeforeValidation{}).Validate(result))
}

func (t *BeforeValidationTests) TestIsNotValidTillTomorrow() {
	cert := CreateTestCert().WithBefore(time.Now().Add(1 * day))
	result := CreateTestCertScanResult().WithCertificates(&cert.Certificate).Build()
	t.ErrorContains((&BeforeValidation{}).Validate(result), "cert will not be valid for 23h59m59")
}

func (t *BeforeValidationTests) TestLabels() {
	timedate, _ := time.Parse("Thu, 05/19/11, 10:47PM", "Mon, 01/02/06, 03:04PM")
	err := BeforeValidationError{
		untilValid: time.Duration(123 * time.Hour),
		notBefore:  timedate,
	}
	t.Equal(map[string]string{
		"type":        "before",
		"until_valid": "123h0m0s",
		"not_before":  "-62135596800000",
	}, err.Labels())
}

func TestBeforeations(t *testing.T) {
	suite.Run(t, &BeforeValidationTests{})
}

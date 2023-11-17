package validations

import (
	"testing"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

var day = time.Hour * 24

type ExpiryValidationTests struct {
	suite.Suite
}

func (t *ExpiryValidationTests) TestIsNotExpired() {
	cert := CreateTestCert().WithAfter(time.Now().Add(8 * day))
	result := CreateTestCertScanResult().WithCertificates(&cert.Certificate).Build()
	t.NoError(CreateExpiryValidation(7 * day).Validate(result))
}

func (t *ExpiryValidationTests) TestWillExpireInNDays() {
	cert := CreateTestCert().WithAfter(time.Now().Add(6 * day))
	result := CreateTestCertScanResult().WithCertificates(&cert.Certificate).Build()
	t.ErrorContains(CreateExpiryValidation(7*day).Validate(result), "cert will expire in less than 168h0m0s on ")
}

func (t *ExpiryValidationTests) TestLabels() {
	timedate, _ := time.Parse("Mon, 01/02/06, 03:04PM", "Thu, 11/15/23, 10:47PM")
	err := ExpiryValidationError{
		warningDuration: time.Duration(168 * time.Hour),
		notAfter:        timedate,
	}
	t.Equal(map[string]string{
		"type":             "expiry",
		"warning_duration": "168h0m0s",
		"not_after":        "1700088420000",
	}, err.Labels())
}

func TestExpiryValidations(t *testing.T) {
	suite.Run(t, &ExpiryValidationTests{})
}

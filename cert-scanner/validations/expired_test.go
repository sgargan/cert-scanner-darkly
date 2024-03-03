package validations

import (
	"fmt"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

var day = time.Hour * 24

type ExpiryValidationTests struct {
	suite.Suite
	ca *TestCA
}

func (t *ExpiryValidationTests) SetupTest() {
	ca, err := CreateTestCA(3)
	t.NoError(err)
	t.ca = ca
}

func (t *ExpiryValidationTests) TestIsNotExpired() {
	cert := CreateTestCert().WithAfter(time.Now().Add(8 * day))
	result := CreateTestTargetScan().WithCertificates(&cert.Certificate).Build()
	t.NoError(CreateExpiryValidation(7 * day).Validate(result))
}

func (t *ExpiryValidationTests) TestWillExpireInNDays() {
	cert := CreateTestCert().WithAfter(time.Now().Add(6 * day))
	result := CreateTestTargetScan().WithCertificates(&cert.Certificate).Build()
	t.ErrorContains(CreateExpiryValidation(7*day).Validate(result), "cert will expire in less than 168h0m0s on ")
}

func (t *ExpiryValidationTests) TestLabels() {
	cert, _, _, err := t.ca.CreateLeafCert("somehost")
	t.NoError(err)

	scan := CreateTestTargetScan().WithTarget(testutils.TestTarget()).WithCertificates(cert).Build()

	timedate, _ := time.Parse("Mon, 01/02/06, 03:04PM", "Thu, 11/15/23, 10:47PM")
	violation := &ExpiryValidationError{
		warningDuration: time.Duration(168 * time.Hour),
		notAfter:        timedate,
		result:          scan.Results[0],
	}
	t.Equal(map[string]string{
		"address":          "172.1.2.34:8080",
		"common_name":      "somehost",
		"failed":           "false",
		"foo":              "bar",
		"id":               fmt.Sprintf("%x", cert.SerialNumber),
		"not_after":        "1700088420000",
		"not_after_date":   "2023-11-15T22:47:00Z",
		"source":           "SomePod-acdf-bdfe",
		"source_type":      "kubernetes",
		"type":             "expiry",
		"warning_duration": "168h0m0s",
	}, violation.Labels())
}

func TestExpiryValidations(t *testing.T) {
	suite.Run(t, &ExpiryValidationTests{})
}

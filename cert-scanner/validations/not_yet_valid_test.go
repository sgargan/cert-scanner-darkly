package validations

import (
	"fmt"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

type BeforeValidationTests struct {
	suite.Suite
	ca *TestCA
}

func (t *BeforeValidationTests) SetupTest() {
	ca, err := CreateTestCA(3)
	t.NoError(err)
	t.ca = ca
}

func (t *BeforeValidationTests) TestIsCurrentlyValid() {
	cert := CreateTestCert().WithBefore(time.Now().Add(-1 * day))
	result := CreateTestTargetScan().WithCertificates(&cert.Certificate).Build()
	t.NoError((&BeforeValidation{}).Validate(result))
}

func (t *BeforeValidationTests) TestIsNotValidTillTomorrow() {
	cert := CreateTestCert().WithBefore(time.Now().Add(1 * day))
	result := CreateTestTargetScan().WithCertificates(&cert.Certificate).Build()
	t.ErrorContains((&BeforeValidation{}).Validate(result), "cert will not be valid for 23h59m59")
}

func (t *BeforeValidationTests) TestLabels() {
	cert, _, _, err := t.ca.CreateLeafCert("somehost")
	t.NoError(err)
	scan := CreateTestTargetScan().WithTarget(testutils.TestTarget()).WithCertificates(cert).Build()
	scan.Results[0].Failed = true

	timedate, _ := time.Parse("Mon, 01/02/06, 03:04PM", "Thu, 11/15/23, 10:47PM")
	violation := &BeforeValidationError{
		untilValid: time.Duration(123 * time.Hour),
		notBefore:  timedate,
		result:     scan.Results[0],
	}

	t.Equal(map[string]string{
		"address":         "172.1.2.34:8080",
		"common_name":     "somehost",
		"failed":          "true",
		"foo":             "bar",
		"id":              fmt.Sprintf("%x", cert.SerialNumber),
		"not_before":      "1700088420000",
		"not_before_date": "2023-11-15T22:47:00Z",
		"pod":             "somepod-acdf-bdfe",
		"source":          "some-cluster",
		"source_type":     "kubernetes",
		"type":            "before",
		"until_valid":     "123h0m0s",
	}, violation.Labels())
}

func TestBeforeations(t *testing.T) {
	suite.Run(t, &BeforeValidationTests{})
}

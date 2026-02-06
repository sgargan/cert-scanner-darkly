package validations

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

type RequireTLSValidationTests struct {
	suite.Suite
	scan *TargetScan
}

func (t *RequireTLSValidationTests) SetupTest() {
	cert := testutils.CreateTestCert()
	t.scan = CreateTestTargetScan().WithCertificates(&cert.Certificate).WithTarget(testutils.TestTarget()).Build()
}

func (t *RequireTLSValidationTests) TestTLSConfigured() {
	// A successful scan (with TLS) should pass validation
	result := CreateTestTargetScan().Build()
	t.NoError(CreateRequireTLSValidation().Validate(result))
}

func (t *RequireTLSValidationTests) TestTLSNotConfigured() {
	t.scan.Results[0].Failed = true
	err := CreateRequireTLSValidation().Validate(t.scan)
	t.Error(err)
	t.Contains(err.Error(), "Target is not configured with TLS")

	labels := err.Labels()
	t.Equal("require_tls", labels["type"])
	t.Equal("172.1.2.34:8080", labels["address"])
}

func TestRequireTLSValidations(t *testing.T) {
	suite.Run(t, &RequireTLSValidationTests{})
}

package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type TLSUtilsTests struct {
	suite.Suite
}

func (t *TLSUtilsTests) TestConversions() {
	t.assertVersion("1.3")
	t.assertVersion("1.2")
	t.assertVersion("1.1")
	t.assertVersion("1.0")
	t.Equal("unknown", ToVersion(1234))

	_, err := FromVersion("not_a_tls_version")
	t.ErrorContains(err, "not_a_tls_version is not a valid tls version string use one of 1.0, 1.1, 1.2, 1.3")

}

func (t *TLSUtilsTests) assertVersion(version string) {
	converted, err := FromVersion(version)
	t.NoError(err)
	t.Equal(version, ToVersion(converted))
}

func TestTLSVersionValidations(t *testing.T) {
	suite.Run(t, &TLSUtilsTests{})
}

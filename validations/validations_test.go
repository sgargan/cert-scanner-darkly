package validations

import (
	"fmt"
	"testing"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ValidationsTests struct {
	suite.Suite
}

func (t *ValidationsTests) SetupTest() {
	viper.Set(config.ConfigExpiryWindow, DefaultWarningDuration)
	viper.Set("validations.expiry.enabled", false)
	viper.Set(config.ConfigTLSMinVersion, "1.2")
}

func (t *ValidationsTests) TestValidationsOnlyAppliedIfEnabled() {
	for x, validations := range []string{"expiry", "before", "tls-version", "trust-chain"} {
		t.assertValidations(x)
		viper.Set(fmt.Sprintf("validations.%s.enabled", validations), true)
		t.assertValidations(x + 1)
	}
	t.assertValidations(4)
}

func (t *ValidationsTests) TestValidationsCreationError() {
	viper.Set("validations.expiry.enabled", true)
	viper.Set(config.ConfigExpiryWindow, "invalid duration")
	_, err := CreateValidations()
	t.ErrorContains(err, "error parsing expiry warning duration from invalid duration")
}

func (t *ValidationsTests) assertValidations(expected int) {
	validations, err := CreateValidations()
	t.NoError(err)
	t.Equal(expected, len(validations))
}

func TestValidations(t *testing.T) {
	suite.Run(t, &ValidationsTests{})
}

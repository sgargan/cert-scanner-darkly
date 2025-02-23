package validations

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ValidationsTests struct {
	suite.Suite
}

func (t *ValidationsTests) SetupTest() {
	viper.Set(config.ValidationsExpiryWindow, DefaultWarningDuration)
}

func (t *ValidationsTests) TestValidationsCreationError() {
	viper.Set("validations.expiry.enabled", true)
	viper.Set(config.ValidationsExpiryWindow, "invalid duration")
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

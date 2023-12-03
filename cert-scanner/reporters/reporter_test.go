package reporters

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ReportersTests struct {
	suite.Suite
}

func (t *ReportersTests) SetupTest() {
	viper.Reset()
	config.LoadConfiguration()
	viper.Set("reporters.logging.file", "/tmp/somelog.log")
}

func (t *ReportersTests) TestReportersEnabledByDefault() {
	t.assertReporter(2)
}

func (t *ReportersTests) TestReportersOnlyAppliedIfEnabled() {
	t.assertReporter(2)
	viper.Set("reporters.logging.enabled", false)
	t.assertReporter(1)
	viper.Set("reporters.metrics.enabled", false)
	t.assertReporter(0)
}

func (t *ReportersTests) assertReporter(expected int) {
	reporters, err := CreateReporters()
	t.NoError(err)
	t.Equal(expected, len(reporters))
}

func TestReporters(t *testing.T) {
	suite.Run(t, &ReportersTests{})
}

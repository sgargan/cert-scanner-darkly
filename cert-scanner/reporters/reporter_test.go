package reporters

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ReportersTests struct {
	suite.Suite
}

func (t *ReportersTests) SetupTest() {
	viper.Set("reporters.logging.file", "/tmp/somelog.log")
}

func (t *ReportersTests) TestReportersOnlyAppliedIfEnabled() {
	for x, reporter := range []string{"logging", "metrics"} {
		t.assertReporter(x)
		viper.Set(fmt.Sprintf("reporters.%s.enabled", reporter), true)
		t.assertReporter(x + 1)
	}
}

func (t *ReportersTests) assertReporter(expected int) {
	reporters, err := CreateReporters()
	t.NoError(err)
	t.Equal(expected, len(reporters))
}

func TestReporters(t *testing.T) {
	suite.Run(t, &ReportersTests{})
}

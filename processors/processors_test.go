package processors

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ProcessorsTests struct {
	suite.Suite
}

func (t *ProcessorsTests) TestProcessorsOnlyAppliedIfEnabled() {
	viper.Set("processors.tls-state.enabled", false)
	for x, processors := range []string{"tls-state"} {
		t.assertProcessors(x)
		viper.Set(fmt.Sprintf("processors.%s.enabled", processors), true)
		t.assertProcessors(x + 1)
	}
	t.assertProcessors(1)
}

func (t *ProcessorsTests) assertProcessors(expected int) {
	processors, err := CreateProcessors()
	t.NoError(err)
	t.Equal(expected, len(processors))
}

func TestProcessors(t *testing.T) {
	suite.Run(t, &ProcessorsTests{})
}

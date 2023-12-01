package config

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

type FactoryTests struct {
	suite.Suite
	factories map[string]Factory[string]
}

func (t *FactoryTests) TestCreateOnlyAppliedIfEnabled() {

	mockOne := &MockFactory{}
	mockTwo := &MockFactory{}
	mockThree := &MockFactory{}

	t.factories = map[string]Factory[string]{
		"one":   mockOne.Create,
		"two":   mockTwo.Create,
		"three": mockThree.Create,
	}

	for x, factory := range []string{"one", "two", "three"} {
		t.assertValidations(x)
		viper.Set(fmt.Sprintf("somegroup.%s.enabled", factory), false)
		t.assertValidations(x)
		viper.Set(fmt.Sprintf("somegroup.%s.enabled", factory), true)
		t.assertValidations(x + 1)
	}
	t.assertValidations(3)
}

func (t *FactoryTests) TestCreateRaisesError() {

	viper.Set("somegroup.fails.enabled", true)
	mockFails := &MockFactory{
		err: fmt.Errorf("something barfed"),
	}

	t.factories = map[string]Factory[string]{
		"fails": mockFails.Create,
	}

	_, err := CreateConfigured[string]("somegroup", t.factories)
	t.ErrorContains(err, "something barfed")

}

func (t *FactoryTests) assertValidations(expected int) {
	created, err := CreateConfigured[string]("somegroup", t.factories)
	t.NoError(err)
	t.Equal(expected, len(created))
}

type MockFactory struct {
	err    error
	called bool
}

func (m *MockFactory) Create() (string, error) {
	m.called = true
	return "called", m.err
}

func TestFactory(t *testing.T) {
	suite.Run(t, &FactoryTests{})
}

package discovery

import (
	"fmt"
	"testing"

	"github.com/sgargan/cert-scanner-darkly/discovery/kubernetes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type DiscoveryTests struct {
	suite.Suite
}

func (t *DiscoveryTests) SetupSuite() {
	if _, _, err := kubernetes.GetClientset(); err != nil {
		t.T().Skipf("cannot load k8s client, this may be a CI env. Please test his outside fo ci")
	}
	viper.Set("discovery.kubernetes.enabled", false)
}

func (t *DiscoveryTests) TestDiscoveryOnlyAppliedIfEnabled() {
	viper.Set("discovery.kubernetes.source", "some-source")
	for x, discovery := range []string{"kubernetes"} {
		t.assertDiscovery(x)
		viper.Set(fmt.Sprintf("discovery.%s.enabled", discovery), true)
		t.assertDiscovery(x + 1)
	}
	t.assertDiscovery(1)
}

func (t *DiscoveryTests) TestDiscoveryCreationError() {
	viper.Set("discovery.kubernetes.enabled", true)
	viper.Set("discovery.kubernetes.source", "")
	_, err := CreateDiscoveries()
	t.ErrorContains(err, "a valid source label for the cluster is required")
}

func (t *DiscoveryTests) assertDiscovery(expected int) {
	discoveries, err := CreateDiscoveries()
	t.NoError(err)
	t.Equal(expected, len(discoveries))
}

func TestDiscovery(t *testing.T) {
	suite.Run(t, &DiscoveryTests{})
}

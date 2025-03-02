package discovery

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/discovery/kubernetes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type DiscoveryTests struct {
	suite.Suite
}

func (t *DiscoveryTests) SetupTest() {
	if _, _, err := kubernetes.GetClientset(); err != nil {
		t.T().Skipf("cannot load k8s client, this may be a CI env. Please test this outside of ci")
	}
	viper.Reset()
}

func (t *DiscoveryTests) TestDiscoveryOfPodsOnlyAppliedIfEnabled() {
	t.assertDiscovery(0)
	viper.Set("discovery.kubernetes.source", "some-source")
	t.assertDiscovery(1)
	viper.Set("discovery.kubernetes.enabled", false)
	t.assertDiscovery(0)
}

func (t *DiscoveryTests) TestDiscoveryOfFilesIfPathsInConfig() {
	t.assertDiscovery(0)
	viper.Set("discovery.files.paths", []string{"/path/to/some/hosts.yaml"})
	t.assertDiscovery(1)
	viper.Set("discovery.files.enabled", false)
}

func (t *DiscoveryTests) TestK8sDiscoveryCreationError() {
	viper.Set("discovery.kubernetes.enabled", true)
	viper.Set("discovery.kubernetes.source", "")
	_, err := CreateDiscoveries()
	t.ErrorContains(err, "a valid source label for the cluster is required")
}

func (t *DiscoveryTests) TestFileDiscoveryCreationError() {

	viper.Set("discovery.files.enabled", true)
	_, err := CreateDiscoveries()
	t.ErrorContains(err, "no host file paths configured in discovery.files.paths")
}

func (t *DiscoveryTests) assertDiscovery(expected int) {
	discoveries, err := CreateDiscoveries()
	t.NoError(err)
	t.Equal(expected, len(discoveries))
}

func TestDiscovery(t *testing.T) {
	suite.Run(t, &DiscoveryTests{})
}

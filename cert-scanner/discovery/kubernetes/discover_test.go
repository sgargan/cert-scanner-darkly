package kubernetes

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type DiscoveryTests struct {
	suite.Suite
}

func (t *DiscoveryTests) SetupSuite() {
	if _, _, err := GetClientset(); err != nil {
		t.T().Skipf("cannot load k8s client, this may be a CI env. Please test his outside fo ci")
	}
}

func (t *DiscoveryTests) TestDiscoveryLoadsConfig() {
	viper.Set(config.DiscoveryK8sSource, "somecluster")
	viper.Set(config.DiscoveryK8sNamespace, "somenamespace")
	viper.Set(config.DiscoveryK8sKeys, []string{"foo", "bar"})
	viper.Set(config.DiscoveryK8sIgnore, []string{"somecontainer"})

	d, err := CreateDiscovery()
	t.NoError(err)

	discovery := d.(*PodDiscovery)
	t.Equal("somecluster", discovery.source)
	t.Equal([]string{"foo", "bar"}, discovery.labelKeys)
	t.Equal(map[string]string{"somecontainer": ""}, discovery.ignore)
}

func TestDiscoveryTests(t *testing.T) {
	suite.Run(t, &DiscoveryTests{})
}

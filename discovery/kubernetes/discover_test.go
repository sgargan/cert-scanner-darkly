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

func (t *DiscoveryTests) TestDiscoveryLoadsConfig() {
	viper.Set(config.DiscoveryK8sSource, "somecluster")
	viper.Set(config.DiscoveryK8sNamespace, "somenamespace")
	viper.Set(config.DiscoveryK8sKeys, []string{"foo", "bar"})

	d, err := CreateDiscovery()
	t.NoError(err)

	discovery := d.(*PodDiscovery)
	t.Equal("somecluster", discovery.source)
	// t.Equal("somenamespace", discovery.pods)
	t.Equal([]string{"foo", "bar"}, discovery.labelKeys)
}

func TestDiscoveryTests(t *testing.T) {
	suite.Run(t, &DiscoveryTests{})
}

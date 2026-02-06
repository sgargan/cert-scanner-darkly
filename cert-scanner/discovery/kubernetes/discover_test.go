package kubernetes

import (
	"regexp"
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
	} else {
		t.T().Log("k8s client creation successful, running testsuite....")
	}
}

func (t *DiscoveryTests) TestDiscoveryLoadsConfig() {
	viper.Set(config.DiscoveryK8sSource, "somecluster")
	viper.Set(config.DiscoveryK8sNamespace, "somenamespace")
	viper.Set(config.DiscoveryK8sKeys, []string{"foo", "bar"})
	viper.Set(config.DiscoveryK8sIgnorePatterns, []map[string]interface{}{
		{"pattern": "{.metadata.name}", "match": []string{"some-pod"}},
	})

	d, err := CreateDiscovery()
	t.NoError(err)

	discovery := d.(*PodDiscovery)
	t.Equal("somecluster", discovery.source)
	t.Equal([]string{"foo", "bar"}, discovery.labelKeys)
	t.Len(discovery.ignorePatterns, 2)
	t.Equal("{.metadata.name}", discovery.ignorePatterns[0].pattern)
	t.Equal(regexp.MustCompile("some-pod"), discovery.ignorePatterns[0].matches[0])
	t.Equal("{.metadata.name}", discovery.ignorePatterns[1].pattern)
	t.Equal(regexp.MustCompile("cert-scanner"), discovery.ignorePatterns[1].matches[0])
}

func TestDiscoveryTests(t *testing.T) {
	suite.Run(t, &DiscoveryTests{})
}

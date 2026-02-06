package kubernetes

import (
	"fmt"
	"net"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

// CreateKubernetesDiscovery creates Discovery instance to detect TLS based services running in
// a kubernetes cluster
func CreateDiscovery() (Discovery, error) {
	_, client, err := GetClientset()
	if err != nil {
		return nil, fmt.Errorf("error getting kubernetes client set: %v", err)
	}

	var matchCIDR *net.IPNet
	configuredCidr := viper.GetString(config.DiscoveryK8sMatchCIDR)
	if configuredCidr != "" {
		_, matchCIDR, err = net.ParseCIDR(configuredCidr)
		if err != nil {
			return nil, fmt.Errorf("error parsing match cidr: %v", err)
		}
	}

	var ignorePatterns []IgnorePattern
	if err := viper.UnmarshalKey(config.DiscoveryK8sIgnorePatterns, &ignorePatterns); err != nil {
		return nil, fmt.Errorf("error parsing ignore patterns: %v", err)
	}

	var ignoreContainers []IgnorePattern
	if err := viper.UnmarshalKey(config.DiscoveryK8sIgnoreContainers, &ignoreContainers); err != nil {
		return nil, fmt.Errorf("error parsing ignore containers: %v", err)
	}

	cfg := PodDiscoveryConfig{
		source:           viper.GetString(config.DiscoveryK8sSource),
		labelKeys:        viper.GetStringSlice(config.DiscoveryK8sKeys),
		ignorePatterns:   ignorePatterns,
		ignoreContainers: ignoreContainers,
		matchCIDR:        matchCIDR,
	}

	return CreatePodDiscovery(cfg, client.CoreV1().Pods(viper.GetString(config.DiscoveryK8sNamespace)))
}

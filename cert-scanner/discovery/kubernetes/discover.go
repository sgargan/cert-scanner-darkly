package kubernetes

import (
	"fmt"
	"strings"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

// CreateKubernetesDiscovery creates Discovery instance to detect TLS based services running in
// a kubernetes cluster
func CreateDiscovery() (Discovery, error) {
	_, client, err := GetClientset()
	if err != nil {
		return nil, fmt.Errorf("error getting kubernetes client set: %v", err)
	}

	source := viper.GetString(config.DiscoveryK8sSource)
	namespace := viper.GetString(config.DiscoveryK8sNamespace)
	keys := viper.GetStringSlice(config.DiscoveryK8sKeys)
	ignore := viper.GetStringSlice(config.DiscoveryK8sIgnore)

	slog.Info("creating k8s discovery", "source", source, "namespace", namespace, "keys", strings.Join(keys, ","))
	return CreatePodDiscovery(source, keys, ignore, client.CoreV1().Pods(namespace))
}

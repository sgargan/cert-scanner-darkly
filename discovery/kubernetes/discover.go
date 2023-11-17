package kubernetes

import (
	"fmt"
	"strings"

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

	source := viper.GetString("discovery.kubernetes.source")
	namespace := viper.GetString("discovery.kubernetes.namespace")
	keys := viper.GetStringSlice("discovery.kubernetes.keys")

	slog.Info("creating k8s discovery", "source", source, "namespace", namespace, "keys", strings.Join(keys, ","))
	return CreatePodDiscovery(source, keys, client.CoreV1().Pods(namespace))
}

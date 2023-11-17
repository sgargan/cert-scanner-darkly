package kubernetes

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// GetClientset loads a kubernetes clientset to interact with kubernetes api
func GetClientset() (*rest.Config, *kubernetes.Clientset, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, nil)

	clientConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to configure Kubernetes client: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to initialize Kubernetes clientset: %v", err)
	}
	return clientConfig, clientset, nil
}

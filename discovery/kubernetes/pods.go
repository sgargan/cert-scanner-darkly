package kubernetes

import (
	"context"
	"fmt"
	"net/netip"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	Kubernetes = "kubernetes"
	PortName   = "port_name"
	Namespace  = "namespace"
	Container  = "container"
)

type PodsInterface interface {
	typedcorev1.PodInterface
}

type PodDiscovery struct {
	source    string
	pods      PodsInterface
	labelKeys []string
}

// Creates a new Pod discovery instance to discover scan candidates via the k8s cluster with the given source
// label
func CreatePodDiscovery(source string, labelKeys []string, pods PodsInterface) (*PodDiscovery, error) {
	if source == "" {
		return nil, fmt.Errorf("a valid source label for the cluster is required")
	}
	if pods == nil {
		return nil, fmt.Errorf("no pods api has been provided")
	}
	return &PodDiscovery{
		source:    source,
		pods:      pods,
		labelKeys: labelKeys,
	}, nil
}

// Discover lists all kubernetes pods through the pods api and creates Candidates for scanning.
// returns a slice of candidates parsed from the pods or an error if they cannot be retrieved or parsed.
func (e *PodDiscovery) Discover(ctx context.Context) ([]*Target, error) {
	pods, err := e.pods.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error discovering pods: %v", err)
	}

	candidates := make([]*Target, 0)
	for _, pod := range pods.Items {
		podIP := pod.Status.PodIP
		ip, err := netip.ParseAddr(podIP)
		if err != nil {
			return nil, fmt.Errorf("error parsing ip from %s", podIP)
		}
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {

				labels := Labels{
					PortName:  port.Name,
					Namespace: pod.ObjectMeta.Namespace,
					Container: container.Name,
				}

				for _, key := range e.labelKeys {
					if label, ok := pod.ObjectMeta.Labels[key]; ok {
						labels[key] = label
					}
				}

				if port.Protocol == v1.ProtocolTCP {
					candidates = append(candidates, &Target{
						Address: netip.AddrPortFrom(ip, uint16(port.ContainerPort)),
						Metadata: Metadata{
							Name:       pod.ObjectMeta.Name,
							Source:     e.source,
							SourceType: Kubernetes,
							Labels:     labels,
						},
					})
				}
			}
		}
	}
	slog.Info("pod discovery", "num_pods", len(pods.Items), "num_candidates", len(candidates))
	return candidates, nil
}

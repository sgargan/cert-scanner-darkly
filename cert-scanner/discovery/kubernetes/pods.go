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

// Discover lists all kubernetes pods through the pods api and creates candidate [Target]s for scanning.
// Each target is emitted onto the given channel for processing. Returns an error if the pods cannot be
// be retrieved or parsed from the api
func (d *PodDiscovery) Discover(ctx context.Context, targets chan *Target) error {
	slog.Debug("starting pod discovery", "source", d.source)
	pods, err := d.pods.List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Debug("error retrieving pods", "source", d.source)
		return fmt.Errorf("error discovering pods: %v", err)
	}
	slog.Debug("retrieved pods from api", "source", d.source, "pods", len(pods.Items))
	numTargets := 0
	for _, pod := range pods.Items {
		podIP := pod.Status.PodIP
		ip, err := netip.ParseAddr(podIP)
		if err != nil {
			slog.Error("error parsing pod ip", "namespace", pod.Namespace, "pod", pod.Name, "ip", podIP, "error", err.Error())
			continue
		}
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {

				labels := Labels{
					PortName:  port.Name,
					Namespace: pod.ObjectMeta.Namespace,
					Container: container.Name,
				}

				for _, key := range d.labelKeys {
					if label, ok := pod.ObjectMeta.Labels[key]; ok {
						labels[key] = label
					}
				}

				if port.Protocol == v1.ProtocolTCP {
					numTargets++
					targets <- &Target{
						Address: netip.AddrPortFrom(ip, uint16(port.ContainerPort)),
						Metadata: Metadata{
							Name:       pod.ObjectMeta.Name,
							Source:     d.source,
							SourceType: Kubernetes,
							Labels:     labels,
						},
					}
					slog.Debug("created target from pod", "namespace", pod.Namespace, "pod", pod.Name, "ip", podIP)
				}
			}
		}
	}
	slog.Info("finished pod discovery", "pods", len(pods.Items), "targets", numTargets)
	return nil
}

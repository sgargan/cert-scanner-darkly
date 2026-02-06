package kubernetes

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/jsonpath"
)

const (
	Kubernetes        = "kubernetes"
	PortName          = "port_name"
	Namespace         = "target_namespace"
	PodName           = "target_pod"
	Container         = "container"
	ScannerPodEnvName = "CERT_SCANNER_POD_NAME"
)

type PodsInterface interface {
	typedcorev1.PodInterface
}

type PodDiscovery struct {
	pods             PodsInterface
	ignorePatterns   []parsedIgnorePattern
	ignoreContainers []parsedIgnorePattern
	PodDiscoveryConfig
}

type parsedIgnorePattern struct {
	pattern  string
	jsonPath *jsonpath.JSONPath
	matches  []*regexp.Regexp
}

type IgnorePattern struct {
	Pattern string   `mapstructure:"pattern"`
	Match   []string `mapstructure:"match"`
}

type PodDiscoveryConfig struct {
	source           string
	labelKeys        []string
	ignorePatterns   []IgnorePattern
	ignoreContainers []IgnorePattern
	matchCIDR        *net.IPNet
	namespace        string
}

// Creates a new Pod discovery instance to discover scan candidates via the k8s cluster with the given source
// label
func CreatePodDiscovery(config PodDiscoveryConfig, pods PodsInterface) (*PodDiscovery, error) {
	slog.Info("creating k8s discovery", "source", config.source, "namespace", config.namespace, "keys", strings.Join(config.labelKeys, ","), "matchCIDR", config.matchCIDR.String())
	if config.source == "" {
		return nil, fmt.Errorf("a valid source label for the cluster is required")
	}
	if pods == nil {
		return nil, fmt.Errorf("no pods api has been provided")
	}

	config.ignorePatterns = append(config.ignorePatterns, IgnorePattern{Pattern: "{.metadata.name}", Match: []string{"cert-scanner"}})
	ignorePodPatterns, err := parseIgnorePatterns(config.ignorePatterns)
	if err != nil {
		return nil, fmt.Errorf("error parsing ignore patterns: %v", err)
	}

	ignoreContainerPatterns, err := parseIgnorePatterns(config.ignoreContainers)
	if err != nil {
		return nil, fmt.Errorf("error parsing ignore container patterns: %v", err)
	}

	return &PodDiscovery{
		PodDiscoveryConfig: config,
		pods:               pods,
		ignorePatterns:     ignorePodPatterns,
		ignoreContainers:   ignoreContainerPatterns,
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
		ignored, err := d.ignorePod(&pod)
		if err != nil {
			slog.Error("error ignoring pod", "namespace", pod.Namespace, "pod", pod.Name, "error", err.Error())
			continue
		}
		if ignored || !isPodReady(&pod) {
			continue
		}
		podIP := pod.Status.PodIP
		ip, err := netip.ParseAddr(podIP)
		if err != nil {
			slog.Error("error parsing pod ip", "namespace", pod.Namespace, "pod", pod.Name, "ip", podIP, "error", err.Error())
			continue
		}

		if d.matchCIDR != nil && !d.matchCIDR.Contains(net.ParseIP(podIP)) {
			slog.Debug("pod does not match match cidr", "namespace", pod.Namespace, "pod", pod.Name, "ip", podIP, "matchCIDR", d.matchCIDR.String())
			continue
		}

		for _, container := range pod.Spec.Containers {
			ignored, err := d.ignoreContainer(&pod)
			if err != nil {
				slog.Error("error ignoring container", "namespace", pod.Namespace, "pod", pod.Name, "container", container.Name, "error", err.Error())
				continue
			}
			if ignored {
				continue
			}

			for _, port := range container.Ports {
				labels := Labels{
					PortName:  port.Name,
					Namespace: pod.ObjectMeta.Namespace,
					PodName:   pod.ObjectMeta.Name,
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
						Address: CreateNetIPAddress(netip.AddrPortFrom(ip, uint16(port.ContainerPort))),
						Metadata: Metadata{
							Name:       pod.ObjectMeta.Name,
							Source:     d.source,
							SourceType: Kubernetes,
							Labels:     labels,
						},
					}
					slog.Debug("created target from pod", "namespace", pod.Namespace, "pod", pod.Name, "ip", podIP, "port", port.ContainerPort)
				}
			}
		}
	}
	slog.Info("finished pod discovery", "pods", len(pods.Items), "targets", numTargets)
	return nil
}

func isPodReady(pod *v1.Pod) bool {
	// Check if pod phase is Running
	if pod.Status.Phase != v1.PodRunning {
		return false
	}

	// Check all containers are ready
	for _, container := range pod.Status.ContainerStatuses {
		if !container.Ready {
			return false
		}
	}

	// Check pod conditions
	for _, condition := range pod.Status.Conditions {
		if condition.Type == v1.PodReady {
			if condition.Status == v1.ConditionTrue {
				return true
			}
			return false
		}
	}
	return false
}

func (d *PodDiscovery) ignorePod(pod *v1.Pod) (bool, error) {
	return ignore(pod, d.ignorePatterns)
}

func (d *PodDiscovery) ignoreContainer(pod *v1.Pod) (bool, error) {
	return ignore(pod, d.ignoreContainers)
}

func ignore(pod *v1.Pod, patterns []parsedIgnorePattern) (bool, error) {
	for _, pattern := range patterns {
		results, err := pattern.jsonPath.FindResults(pod)
		if err != nil {
			return false, fmt.Errorf("error matching jsonpath pattern to pod (%s): %v", pod.Name, err)
		}

		for _, result := range results {
			for _, value := range result {
				if !value.IsValid() {
					continue
				}
				extractedValue := fmt.Sprintf("%v", value.Interface())

				// If no match values specified, any valid result means ignore
				if len(pattern.matches) == 0 {
					return true, nil
				}

				// Check if extracted value matches any of the specified match values
				for _, matchValue := range pattern.matches {
					if matchValue.MatchString(extractedValue) {
						slog.Debug("ignoring due to pattern match", "pod", pod.Name, "pattern", pattern.pattern, "value", extractedValue)
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

// podsuffix trims the idenifier from a podname for filtering
func podSuffix(podname string) string {
	parts := strings.Split(podname, "-")

	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return podname
}

func parseJsonPath(pattern string) (*jsonpath.JSONPath, error) {
	j := jsonpath.New(pattern)
	err := j.Parse(pattern)
	if err != nil {
		return nil, fmt.Errorf("error parsing ignore pattern: %v", err)
	}
	return j, nil
}

func parseIgnorePatterns(ignorePatterns []IgnorePattern) ([]parsedIgnorePattern, error) {
	parsedPatterns := make([]parsedIgnorePattern, 0)
	for _, pattern := range ignorePatterns {
		j, err := parseJsonPath(pattern.Pattern)
		if err != nil {
			return nil, err
		}
		matches := make([]*regexp.Regexp, 0, len(pattern.Match))
		for _, match := range pattern.Match {
			matches = append(matches, regexp.MustCompile(match))
		}
		parsedPatterns = append(parsedPatterns, parsedIgnorePattern{
			pattern:  pattern.Pattern,
			jsonPath: j,
			matches:  matches,
		})
	}
	return parsedPatterns, nil
}

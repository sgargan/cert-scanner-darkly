//go:generate mockery --name PodsInterface
package kubernetes

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/sgargan/cert-scanner-darkly/discovery/kubernetes/mocks"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodTests struct {
	MockPods
	suite.Suite
}

func (t *PodTests) SetupSuite() {
	if _, _, err := GetClientset(); err != nil {
		t.T().Skipf("cannot load k8s client, this may be a CI env. Please test his outside fo ci")
	}
}

func (t *PodTests) SetupTest() {
	t.MockPods = NewMockPods()
}

func (t *PodTests) TestDiscoveryCreationErrors() {
	_, err := CreatePodDiscovery("", []string{}, []string{}, t.Build())
	t.ErrorContains(err, "a valid source label for the cluster is required")

	_, err = CreatePodDiscovery("somecluster", []string{}, []string{}, nil)
	t.ErrorContains(err, "no pods api has been provided")
}

func (t *PodTests) TestDiscoversValidPods() {
	t.AddPods("some-pod", "some-namespace", map[string]string{"foo": "bar"},
		v1.PodIP{IP: "10.0.1.1"}, v1.ContainerPort{Name: "some-port", ContainerPort: 8080, Protocol: v1.ProtocolTCP},
	)
	t.AddPods("another-pod", "another-namespace", map[string]string{"bar": "baz", "app": "some-app"},
		v1.PodIP{IP: "10.0.1.2"}, v1.ContainerPort{Name: "another-port", ContainerPort: 8081, Protocol: v1.ProtocolTCP},
	)

	podDiscovery, err := CreatePodDiscovery("some-cluster", []string{"foo", "app"}, []string{}, t.Build())
	t.NoError(err)

	targets := make(chan *Target, 2)
	err = podDiscovery.Discover(context.Background(), targets)
	t.NoError(err)
	t.Equal(&Target{
		Metadata: Metadata{
			Name:       "some-pod",
			Source:     "some-cluster",
			SourceType: "kubernetes",
			Labels: map[string]string{
				"foo":       "bar",
				"namespace": "some-namespace",
				"port_name": "some-port",
				"container": "somecontainer",
			},
		},
		Address: getAddress("10.0.1.1:8080"),
	}, <-targets)

	t.Equal(&Target{
		Metadata: Metadata{
			Name:       "another-pod",
			Source:     "some-cluster",
			SourceType: "kubernetes",
			Labels: map[string]string{
				"app":       "some-app",
				"namespace": "another-namespace",
				"port_name": "another-port",
				"container": "somecontainer",
			},
		},
		Address: getAddress("10.0.1.2:8081"),
	}, <-targets)
}

func (t *PodTests) TestExtractsLabels() {
	t.AddPods("some-pod", "some-namespace", map[string]string{"foo": "bar", "bar": "baz", "app": "some-app"},
		v1.PodIP{IP: "10.0.1.1"}, createContainerPort(8080),
	)

	podDiscovery, _ := CreatePodDiscovery("some-cluster", []string{"foo", "app"}, []string{}, t.Build())

	targets := make(chan *Target, 2)
	t.NoError(podDiscovery.Discover(context.Background(), targets))
	target := <-targets
	t.Equal(map[string]string{
		"address":     "10.0.1.1:8080",
		"app":         "some-app",
		"foo":         "bar",
		"namespace":   "some-namespace",
		"container":   "somecontainer",
		"port_name":   "some-port",
		"source":      "some-cluster",
		"source_type": "kubernetes",
	},
		target.Labels(),
	)
}

func (t *PodTests) TestIssueLoadingPodsRaisesError() {
	t.RaiseError("something barfed loading ")
	podDiscovery, _ := CreatePodDiscovery("some-cluster", []string{"foo", "app"}, []string{}, t.Build())
	targets := make(chan *Target, 2)
	err := podDiscovery.Discover(context.Background(), targets)
	t.ErrorContains(err, "error discovering pods: something barfed")
}

func (t *PodTests) TestIgnoresPods() {
	t.AddPods("some-pod-7475bbf4d4-nr79n", "some-namespace", map[string]string{},
		v1.PodIP{IP: "10.0.1.1"}, createContainerPort(8080),
	)
	t.AddPods("some-pod-7475bbf4d4-nr79n", "some-namespace", map[string]string{},
		v1.PodIP{IP: "10.0.1.1"}, createContainerPort(8080),
	)

	podDiscovery, _ := CreatePodDiscovery("some-cluster", []string{}, []string{"some-pod"}, t.Build())
	targets := make(chan *Target, 2)
	t.NoError(podDiscovery.Discover(context.Background(), targets))
	t.Equal(0, len(targets))
}

func (t *PodTests) TestIgnoresScanner() {
	os.Setenv(ScannerPodEnvName, "cert-scanner-12345fed")
	t.AddPods("cert-scanner-1234abcd", "some-namespace", map[string]string{},
		v1.PodIP{IP: "10.0.1.1"}, createContainerPort(8080),
	)

	podDiscovery, _ := CreatePodDiscovery("some-cluster", []string{}, []string{}, t.Build())
	targets := make(chan *Target, 2)
	t.NoError(podDiscovery.Discover(context.Background(), targets))
	t.Equal(0, len(targets))
}

func createContainerPort(port int32) v1.ContainerPort {
	return v1.ContainerPort{
		Name:          "some-port",
		Protocol:      v1.ProtocolTCP,
		ContainerPort: port,
	}
}

func getAddress(addr string) *NetIPAddress {
	return CreateNetIPAddress(netip.MustParseAddrPort(addr))
}

type MockPods struct {
	pods *mocks.PodsInterface
	list *v1.PodList
	err  error
}

func NewMockPods() MockPods {
	return MockPods{
		pods: &mocks.PodsInterface{},
		list: &v1.PodList{
			Items: make([]v1.Pod, 0),
		},
	}
}

func (m *MockPods) AddPods(name, namespace string, labels map[string]string, ip v1.PodIP, port v1.ContainerPort) {
	m.list.Items = append(m.list.Items, v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "somecontainer",
					Ports: []v1.ContainerPort{port},
				},
			},
		},
		Status: v1.PodStatus{
			PodIP:  ip.IP,
			PodIPs: []v1.PodIP{ip},
		},
	})
}

func (m *MockPods) RaiseError(err string) {
	m.err = errors.New(err)
}

func (m *MockPods) Build() *mocks.PodsInterface {
	m.pods.On("List", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("v1.ListOptions")).Return(m.list, m.err)
	return m.pods
}

func (m *MockPods) Verify(t *testing.T) bool {
	return m.pods.AssertExpectations(t)
}

func TestPodSuite(t *testing.T) {
	suite.Run(t, &PodTests{})
}

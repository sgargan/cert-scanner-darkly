package discovery

import (
	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/sgargan/cert-scanner-darkly/discovery/file"
	"github.com/sgargan/cert-scanner-darkly/discovery/kubernetes"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

var factories = map[string]Factory[Discovery]{
	"kubernetes": kubernetes.CreateDiscovery,
	"files":      file.CreateDiscovery,
}

func CreateDiscoveries() (Discoveries, error) {
	return config.CreateConfigured[Discovery]("discovery", factories)
}

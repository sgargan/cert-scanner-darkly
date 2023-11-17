package discovery

import (
	"fmt"

	"github.com/spf13/viper"
	"golang.org/x/exp/slog"

	"github.com/sgargan/cert-scanner-darkly/discovery/kubernetes"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

var factories = map[string]DiscoveryFactory{"kubernetes": kubernetes.CreateDiscovery}

func CreateDiscoveries() (Discoveries, error) {
	discoverys := make(Discoveries, 0)
	for name, discoveryFactory := range factories {
		if v, err := getDiscovery(name, discoveryFactory); err != nil {
			return nil, err
		} else if v != nil {
			discoverys = append(discoverys, v)
		}
	}
	slog.Debug("created all discoverys", "count", len(discoverys))
	return discoverys, nil
}

func getDiscovery(name string, factory DiscoveryFactory) (discovery Discovery, err error) {
	enabled := viper.GetBool(fmt.Sprintf("discovery.%s.enabled", name))
	if enabled {
		discovery, err = factory()
	}
	slog.Debug("create discovery", "type", name, "enabled", enabled, "created", discovery != nil)
	return
}

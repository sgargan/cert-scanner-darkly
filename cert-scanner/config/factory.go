package config

import (
	"fmt"
	"reflect"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

// CreateConfigured is used to build instance via a factory if it has been explicitly enabled in the configuration.
// it iterates each of the given factories and checks if an entry 'processor.name.enabled' has been set to true. If it
// has the factory will be invoked e.g. for a group 'processors' and a factories map containing a factorys named foo,
// this will check that a config key 'processors.foo' is present an only invoke the factory function
// is this is true. A config can be disabled by setting an 'enabled' config value to false e.g. processors.foo.enabled: false
// It returns a slice containing the enabled instances or an error if there was any issue during construction.
func CreateConfigured[T comparable](group string, factories map[string]Factory[T]) ([]T, error) {
	created := make([]T, 0)

	for name, factory := range factories {
		key := fmt.Sprintf("%s.%s", group, name)
		enabled := fmt.Sprintf("%s.enabled", key)

		keyset := viper.Get(key) != nil
		noEnableConfigForKey := viper.GetString(enabled) == ""
		boolEnabled := viper.GetBool(enabled)
		if boolEnabled || (keyset && noEnableConfigForKey) {
			if t, err := factory(); err != nil {
				return nil, err
			} else if !reflect.ValueOf(t).IsZero() {
				created = append(created, t)
			}
			slog.Debug("created type via factory", "group", group, "factory", name)
		} else {
			slog.Debug("factory not enabled", "group", group, "factory", name)
		}

	}
	slog.Debug("created all instances of type", "group", group, "count", len(created))
	return created, nil
}

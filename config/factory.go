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
// this will check that a config key 'processors.foo.enabled: true' is present an only invoke the factory function
// is this is true. It returns a slice containing the enabled instances or an error if there was any issue during construction.
func CreateConfigured[T comparable](group string, factories map[string]Factory[T]) ([]T, error) {
	created := make([]T, 0)

	for name, factory := range factories {
		if viper.GetBool(fmt.Sprintf("%s.%s.enabled", group, name)) {
			if t, err := factory(); err != nil {
				return nil, err
			} else if !reflect.ValueOf(t).IsZero() {
				created = append(created, t)
			}
			slog.Debug("created configured type", "group", group, "type", name)
		}

	}
	slog.Debug("created all enabled types", "group", group, "count", len(created))
	return created, nil
}

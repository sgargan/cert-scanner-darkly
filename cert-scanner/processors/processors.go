package processors

import (
	"github.com/sgargan/cert-scanner-darkly/config"
	//lint:ignore ST1001 types are ok
	. "github.com/sgargan/cert-scanner-darkly/types"
)

var factories = map[string]Factory[Processor]{"tls-state": CreateTLSStateRetrieval}

func CreateProcessors() (Processors, error) {
	return config.CreateConfigured[Processor]("processors", factories)
}

package compare

import (
	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/sgargan/cert-scanner-darkly/reporters/metrics"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

// factories that will create comparators based on the presence of
// comparator.key.enabled being present in the configuration
var factories = map[string]Factory[ScanComparator]{}

type ScanComparator interface {
	Compare(previous, current CompletedScan)
}

func CreateComparators() ([]ScanComparator, error) {
	comparators, err := config.CreateConfigured[ScanComparator]("comparators", factories)
	if err != nil {
		return nil, err
	}

	return append(comparators, metrics.CreateMetricsComparator()), nil
}

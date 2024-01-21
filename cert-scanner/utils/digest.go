package utils

import (
	"fmt"
	"sort"

	"github.com/cespare/xxhash"
	"github.com/sgargan/cert-scanner-darkly/types"
)

// Digest creates a hash for a given set of labels
func Digest(labels types.Labels) string {
	d := xxhash.New()
	keys := make([]string, 0)

	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d.Write([]byte(k))
		d.Write([]byte(labels[k]))
	}
	return fmt.Sprintf("%x", d.Sum64())
}

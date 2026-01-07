package utils

import (
	"crypto/tls"
	"fmt"
)

const MaxInt = ^int(0) >> 1

// Convert from a tls version int to a string representation
func ToVersion(version int) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return "unknown"
}

// Convert from a known version string to a given tls version int
func FromVersion(version string) (int, error) {
	switch version {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return MaxInt, fmt.Errorf("%s is not a valid tls version string use one of 1.0, 1.1, 1.2, 1.3", version)
}

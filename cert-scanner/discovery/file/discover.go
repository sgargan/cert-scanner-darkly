package file

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type HostsFile struct {
	Groups []HostsGroup `yaml:"groups"`
}

type HostsGroup struct {
	Source           string            `yaml:"source"`
	AdditionalLabels []string          `yaml:"additional_labels"`
	Hosts            []TargetHostEntry `yaml:"hosts"`
}

// TargetHostEntry contains the details of a target host
type TargetHostEntry struct {
	Host string `json,yaml:"host"`
}

type FileDiscovery struct {
}

// CreateDiscovery creates Discovery instance that loads target hosts from a file
// on the filesystem.
func CreateDiscovery() (Discovery, error) {
	slog.Info("creating file discovery")
	if len(viper.GetStringSlice(config.DiscoveryFilePaths)) == 0 {
		return nil, fmt.Errorf("no host file paths configured in %s", config.DiscoveryFilePaths)
	}
	return &FileDiscovery{}, nil
}

// Discover iterates through each configured file and loads the targets they contain and
// emits them to the supplied targest channel.
func (d *FileDiscovery) Discover(ctx context.Context, targets chan *Target) error {
	files := viper.GetStringSlice(config.DiscoveryFilePaths)
	slog.Debug("Host file entries", "count", len(files))
	numTargets := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			slog.Error("error reading host file contents", "file", file, "error", err)
			continue
		}

		details := &HostsFile{}
		err = yaml.Unmarshal(data, details)
		if err != nil {
			slog.Error("error unmarshalling host file contents", "file", file, "error", err)
			continue
		}
		slog.Debug("loaded host entries from file", "source", file, "additionalLabels", "groups", len(details.Groups))

		for _, group := range details.Groups {
			for _, host := range group.Hosts {
				address, err := getTargetAddress(host)
				if err != nil {
					slog.Error("error parsing host from file source", "source", file, "error", err, "host", host.Host)
					continue
				}
				numTargets++
				targets <- &Target{
					Address: address,
					Metadata: Metadata{
						Name:       host.Host,
						Source:     group.Source,
						SourceType: "file",
						Labels: Labels{
							"file": file,
						},
					},
				}
			}
		}
	}
	slog.Info("finished file discovery", "files", len(files), "targets", numTargets)
	return nil
}

func getTargetAddress(host TargetHostEntry) (Address, error) {
	url, err := url.Parse(host.Host)
	if err != nil || url.Host == "" {
		ipAddr, err := netip.ParseAddrPort(host.Host)
		if err != nil {
			return nil, fmt.Errorf("could not parse address:port or url from %s", host.Host)
		}
		return CreateNetIPAddress(ipAddr), nil
	}
	return CreateUrlAddress(url), nil
}

package file

import (
	"context"
	"os"
	"testing"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

type DiscoveryTests struct {
	suite.Suite
	files []*os.File
}

func (t *DiscoveryTests) TearDownSuite() {
	for _, file := range t.files {
		file.Close()
		os.Remove(file.Name())
	}
}

func (t *DiscoveryTests) TestDiscoveryLoadsConfig() {

	filename, targets := t.configureTestFileDiscovery("someFile", `---
groups:
- source: some_source
  hosts:
   - host: https://google.com
   - host: https://github.com
   - host: https://golang.org
`)

	t.Equal(3, len(targets))
	t.validateFileTarget("https://google.com", "some_source", filename, <-targets)
	t.validateFileTarget("https://github.com", "some_source", filename, <-targets)
	t.validateFileTarget("https://golang.org", "some_source", filename, <-targets)
}

func (t *DiscoveryTests) TestSkipsInvalidEntriesConfig() {

	filename, targets := t.configureTestFileDiscovery("someFile", `---
groups:
- source: some_source
  hosts:
   - host: 10.3.23
   - host: https://golang.org
`)

	t.Equal(1, len(targets))
	t.validateFileTarget("https://golang.org", "some_source", filename, <-targets)
}

func (t *DiscoveryTests) TestMultipleGroupsConfig() {

	filename, targets := t.configureTestFileDiscovery("someFile", `---
groups:
- source: group_one
  hosts:
   - host: https://golang.org
- source: group_two
  hosts:
   - host: https://github.org
`)

	t.Equal(2, len(targets))
	t.validateFileTarget("https://golang.org", "group_one", filename, <-targets)
	t.validateFileTarget("https://github.org", "group_two", filename, <-targets)
}

func (t *DiscoveryTests) configureTestFileDiscovery(file, content string) (string, chan *Target) {
	filename := t.createTestFile(file, content)
	viper.Set(config.DiscoveryFilePaths, []string{filename})

	d, err := CreateDiscovery()
	t.NoError(err)

	targets := make(chan *Target, 3)
	discovery := d.(*FileDiscovery)
	discovery.Discover(context.Background(), targets)

	return filename, targets
}

func (t *DiscoveryTests) validateFileTarget(url, source, filename string, target *Target) {
	address, _ := ParseUrlAddress(url)
	t.Equal(&Target{
		Address: address,
		Metadata: Metadata{
			Source:     source,
			SourceType: "file",
			Name:       url,
			Labels: map[string]string{
				"file": filename,
			},
		},
	}, target)
}

func (t *DiscoveryTests) createTestFile(name string, content string) string {
	file, err := os.CreateTemp(os.TempDir(), name)
	t.NoError(err)
	t.files = append(t.files, file)
	t.NoError(os.WriteFile(file.Name(), []byte(content), os.ModePerm))
	return file.Name()
}

func TestDiscoveryTests(t *testing.T) {
	suite.Run(t, &DiscoveryTests{})
}

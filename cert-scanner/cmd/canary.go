package cmd

import (
	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/sgargan/cert-scanner-darkly/testutils/canary"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type CanaryCommand struct {
	cobra.Command
	port int
}

func CreateCanaryCommand() *CanaryCommand {
	cmd := &cobra.Command{
		Use: "canary",
		Run: RunCanary,
	}

	configureDefaultFlags(cmd)
	if err := config.LoadConfiguration(); err != nil {
		LogExit("error parsing configuration", "err", err)
	}

	return &CanaryCommand{
		Command: *cmd,
	}
}

func RunCanary(cmd *cobra.Command, args []string) {
	canary.RunCanary(viper.GetInt(config.CanaryPort))
}

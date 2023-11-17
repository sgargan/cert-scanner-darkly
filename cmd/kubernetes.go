package cmd

import (
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

type KubernetesScanCommand struct {
	cobra.Command
	namespace string
	tokenPath string
}

func CreateKubernetesScanCommand() *KubernetesScanCommand {
	cmd := &KubernetesScanCommand{
		Command: cobra.Command{
			Aliases: []string{"k8s"},
			Use:     "kubernetes",
			Short:   "scan a kubernetes cluster",
			Long:    "scan the kubernetes cluster available via the current context for cert violations",
		},
	}
	cmd.Command.Run = cmd.Execute
	cmd.configureFlags()
	return cmd
}

func (c *KubernetesScanCommand) Execute(cmd *cobra.Command, args []string) {
	slog.Debug("Running k8s mode")
	// discovery, err := kubernetes.CreateKubernetesDiscovery()
	// if err != nil {
	// 	slog.Error("error creating kubernetes target discovery", "err", err.Error())
	// }

	// context, _ := utils.CreateSignalledContext(viper.GetDuration("timeout"), syscall.SIGINT, syscall.SIGTERM)
	// targets, err := discovery.Discover(context)
	// if err != nil {
	// 	slog.Error("error discovering kubernetes targets", "err", err.Error())
	// }

	// scan := scanner.ExecuteScan
}

func (c *KubernetesScanCommand) configureFlags() {
	configureDefaultFlags(&c.Command)
	flags := c.Command.PersistentFlags()
	flags.StringVarP(&c.namespace, "namespace", "n", "", "namespace to scan for endpoints. defaults to all namespaces")
}

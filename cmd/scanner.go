package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

var configPath string

type ScanCommand struct {
	cobra.Command
}

func CreateScanCommand() *ScanCommand {
	scan := &ScanCommand{
		Command: cobra.Command{
			Use: "cert-scan",
			Run: RunScan,
		},
	}
	return scan
}

func RunScan(cmd *cobra.Command, args []string) {

}

func configureDefaultFlags(cmd *cobra.Command) {
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&configPath, "config", "c", "~/.config/cert-scanner.yml", "config file (default is ~/.config/cert-scanner.yml)")
	persistentFlags.BoolP("debug", "d", false, "Use debug logging mode")
	viper.BindPFlag("debug", persistentFlags.Lookup("debug"))
	cmd.ParseFlags(os.Args[1:])
	configureLogging()
}

func configureLogging() {
	level := slog.LevelInfo
	if viper.GetBool("debug") {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

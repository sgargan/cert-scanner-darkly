package main

import (
	"github.com/sgargan/cert-scanner-darkly/cmd"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{}
	root.AddCommand(
		&cmd.CreateCanaryCommand().Command,
		&cmd.CreateScanCommand().Command,
	)
	root.Execute()
}

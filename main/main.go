package main

import (
	"github.com/sgargan/cert-scanner-darkly/cmd"
)

func main() {
	cmd.CreateScanCommand().Execute()
}

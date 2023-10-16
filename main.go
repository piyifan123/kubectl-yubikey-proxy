package main

import (
	"os"

	"github.com/piyifan123/kubectl-yubikey-proxy/cmd"
)

func main() {
	root := cmd.NewCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

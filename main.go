// Sigil CLI provides cryptographic trust scores for AI agent tools.
package main

import (
	"os"

	"github.com/fwilkerson/sigil-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

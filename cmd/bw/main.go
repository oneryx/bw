// Command bw is a Go implementation of the Bitwarden CLI for Vaultwarden.
package main

import (
	"os"

	"github.com/yangxiang/bw/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}

// Command gk is a local-first vault for project environment variables.
package main

import (
	"os"

	"gatekeeper/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}

// Package main is the entry point for the LumiNet server application.
// It delegates all command handling to the cmd package via cobra.
package main

import (
	"github.com/maybeknott/luminet/cmd"
)

func main() {
	cmd.WebDist = WebDist
	cmd.Execute()
}

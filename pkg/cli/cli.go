// Package cli wires the command-line interface for the injection range.
package cli

import (
	"context"

	"github.com/urfave/cli/v3"
)

// Run builds and executes the CLI.
func Run(ctx context.Context, args []string, version string) error {
	cmd := &cli.Command{
		Name:    "semgate-example",
		Usage:   "A pseudo-vulnerable web service used to validate the semgate guard",
		Version: version,
		Commands: []*cli.Command{
			cmdServe(),
		},
	}
	return cmd.Run(ctx, args)
}

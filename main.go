package main

import (
	"context"
	"fmt"
	"os"

	"github.com/m-mizutani/semgate-example/pkg/cli"
)

var version = "dev"

func main() {
	if err := cli.Run(context.Background(), os.Args, version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

package cli

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/semgate-example/frontend"
	httpctrl "github.com/m-mizutani/semgate-example/pkg/controller/http"
	"github.com/m-mizutani/semgate-example/pkg/usecase"
	"github.com/m-mizutani/semgate-example/pkg/utils/logging"
	"github.com/urfave/cli/v3"
)

func cmdServe() *cli.Command {
	var addr, logFormat, logLevel string
	var rateLimit int
	return &cli.Command{
		Name:  "serve",
		Usage: "Run the injection range HTTP server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "addr",
				Usage:       "listen address",
				Value:       ":8080",
				Sources:     cli.EnvVars("SEMGATE_EXAMPLE_ADDR"),
				Destination: &addr,
			},
			&cli.StringFlag{
				Name:        "log-format",
				Usage:       "log format: json or console",
				Value:       "json",
				Sources:     cli.EnvVars("SEMGATE_EXAMPLE_LOG_FORMAT"),
				Destination: &logFormat,
			},
			&cli.StringFlag{
				Name:        "log-level",
				Usage:       "log level: debug, info, warn, error",
				Value:       "info",
				Sources:     cli.EnvVars("SEMGATE_EXAMPLE_LOG_LEVEL"),
				Destination: &logLevel,
			},
			&cli.IntFlag{
				Name:        "rate-limit",
				Usage:       "max /api requests per client IP per minute (0 disables the limit)",
				Value:       15,
				Sources:     cli.EnvVars("SEMGATE_EXAMPLE_RATE_LIMIT"),
				Destination: &rateLimit,
			},
		},
		Action: func(ctx context.Context, _ *cli.Command) error {
			logger := logging.New(os.Stdout, logging.ParseFormat(logFormat), logging.ParseLevel(logLevel))

			sim, err := usecase.NewSimulator()
			if err != nil {
				return goerr.Wrap(err, "init simulator")
			}
			defer func() { _ = sim.Close() }()

			staticFS, err := fs.Sub(frontend.StaticFiles, "dist")
			if err != nil {
				return goerr.Wrap(err, "bind embedded static files")
			}

			var opts []httpctrl.Option
			if rateLimit != 0 {
				opts = append(opts, httpctrl.WithRateLimit(rateLimit, time.Minute))
			}

			handler, err := httpctrl.New(sim, staticFS, logger, opts...)
			if err != nil {
				return goerr.Wrap(err, "build http handler")
			}

			server := &http.Server{
				Addr:              addr,
				Handler:           handler,
				ReadHeaderTimeout: 30 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				logger.Info("starting injection range", "addr", addr, "log_format", logFormat)
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errCh <- goerr.Wrap(err, "listen and serve")
				}
			}()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

			select {
			case err := <-errCh:
				return err
			case <-sigCh:
				logger.Info("shutting down")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := server.Shutdown(shutdownCtx); err != nil {
					return goerr.Wrap(err, "graceful shutdown")
				}
				return nil
			}
		},
	}
}

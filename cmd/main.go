package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/HAL-X9/threat-info-service/internal/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "threat-info-service: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(os.Args[1:], os.Getenv)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	if err = a.Run(ctx); err != nil {
		return fmt.Errorf("run: %w", err)
	}

	return nil
}

package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/h4775346/vpn-server/internal/api"
	"github.com/h4775346/vpn-server/internal/config"
	"github.com/h4775346/vpn-server/internal/logging"
	"github.com/h4775346/vpn-server/internal/pki"
	"github.com/h4775346/vpn-server/internal/sstp"
)

func main() {
	// Initialize logger
	logger := logging.NewLogger()

	// Load configuration
	cfg := config.Load()

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Ensure PKI is set up
	if err := pki.EnsureCA(cfg.CAKeyPath, cfg.CACertPath); err != nil {
		logger.Fatalf("Failed to ensure CA: %v", err)
	}

	// Start SSTP server
	server, err := sstp.NewServer(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to create SSTP server: %v", err)
	}

	var wg sync.WaitGroup

	// Start SSTP server in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Start(ctx); err != nil {
			logger.Errorf("SSTP server error: %v", err)
		}
	}()

	// Start API server in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		apiServer := api.NewServer(cfg, logger, server)
		if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("API server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-sigChan
	logger.Info("Shutting down servers...")

	// Cancel context to signal shutdown
	cancel()

	// Wait for servers to finish
	wg.Wait()
	logger.Info("Servers stopped")
}

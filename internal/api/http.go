package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/h4775346/vpn-server/internal/config"
	"github.com/h4775346/vpn-server/internal/logging"
	"github.com/h4775346/vpn-server/internal/pki"
	"github.com/h4775346/vpn-server/internal/sstp"
)

// Server represents the HTTP control API server
type Server struct {
	config     *config.Config
	logger     *logging.Logger
	server     *http.Server
	sstpServer *sstp.Server
}

// NewServer creates a new HTTP API server
func NewServer(cfg *config.Config, logger *logging.Logger, sstpServer *sstp.Server) *Server {
	return &Server{
		config:     cfg,
		logger:     logger,
		sstpServer: sstpServer,
	}
}

// Start starts the HTTP API server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", s.healthHandler)

	// Sessions endpoint
	mux.HandleFunc("/sessions", s.sessionsHandler)

	// CA certificate export endpoint
	mux.HandleFunc("/export/ca.crt", s.caCertHandler)

	// Create HTTP server
	s.server = &http.Server{
		Addr:    s.config.APIListenAddr,
		Handler: mux,
	}

	s.logger.Infof("API server listening on %s", s.config.APIListenAddr)

	// Start server
	return s.server.ListenAndServe()
}

// Stop stops the HTTP API server
func (s *Server) Stop() error {
	if s.server != nil {
		// Create a context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// healthHandler handles the /health endpoint
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// sessionsHandler handles the /sessions endpoint
func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get sessions from SSTP server
	sessions := s.sstpServer.GetSessions()

	// Convert to JSON and send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sessions); err != nil {
		s.logger.Errorf("Failed to encode sessions: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// caCertHandler handles the /export/ca.crt endpoint
func (s *Server) caCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if the request is for ca.crt
	if !strings.HasSuffix(r.URL.Path, "/ca.crt") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Set content type for certificate
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")

	// Write CA certificate
	if err := pki.WriteCACert(s.config.CACertPath, w); err != nil {
		s.logger.Errorf("Failed to write CA certificate: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

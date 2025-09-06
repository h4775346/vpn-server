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

type Server struct {
	config     *config.Config
	logger     *logging.Logger
	server     *http.Server
	sstpServer *sstp.Server
}

func NewServer(cfg *config.Config, logger *logging.Logger, sstpServer *sstp.Server) *Server {
	return &Server{
		config:     cfg,
		logger:     logger,
		sstpServer: sstpServer,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/sessions", s.sessionsHandler)
	mux.HandleFunc("/export/ca.crt", s.caCertHandler)

	s.server = &http.Server{
		Addr:         s.config.APIListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Infof("API server listening on %s", s.config.APIListenAddr)
	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var sessions any = []any{}
	if s.sstpServer != nil {
		sessions = s.sstpServer.GetSessions()
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sessions); err != nil {
		s.logger.Errorf("Failed to encode sessions: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) caCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/ca.crt") {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if err := pki.WriteCACert(s.config.CACertPath, w); err != nil {
		s.logger.Errorf("Failed to write CA certificate: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

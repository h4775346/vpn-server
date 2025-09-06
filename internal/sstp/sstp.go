package sstp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/h4775346/vpn-server/internal/config"
	"github.com/h4775346/vpn-server/internal/logging"
	"github.com/h4775346/vpn-server/internal/netutil"
	"github.com/h4775346/vpn-server/internal/pki"
	"github.com/h4775346/vpn-server/internal/ppp"
)

// Server represents the SSTP server
type Server struct {
	config   *config.Config
	logger   *logging.Logger
	tlsConf  *tls.Config
	listener net.Listener
	sessions *SessionManager
	wg       sync.WaitGroup
}

// SessionManager manages active SSTP sessions
type SessionManager struct {
	sessions map[string]*SSTPSession
	mu       sync.RWMutex
}

// SSTPSession represents an SSTP session
type SSTPSession struct {
	ID        string
	Conn      net.Conn
	PPP       *ppp.Session
	StartTime time.Time
	RemoteIP  string
}

// NewServer creates a new SSTP server
func NewServer(cfg *config.Config, logger *logging.Logger) (*Server, error) {
	server := &Server{
		config: cfg,
		logger: logger,
		sessions: &SessionManager{
			sessions: make(map[string]*SSTPSession),
		},
	}

	// Detect public IP
	publicIP, err := netutil.GetPublicIP()
	if err != nil {
		logger.Warnf("Failed to detect public IP, using localhost: %v", err)
		publicIP = net.ParseIP("127.0.0.1")
	}

	// Ensure server certificate for the detected IP
	if err := pki.EnsureServerCertForIP(
		cfg.ServerCertPath,
		cfg.ServerKeyPath,
		cfg.CACertPath,
		cfg.CAKeyPath,
		publicIP,
	); err != nil {
		return nil, fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	// Load certificates
	cert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Configure TLS
	server.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return server, nil
}

// Start starts the SSTP server
func (s *Server) Start(ctx context.Context) error {
	var err error
	s.listener, err = tls.Listen("tcp", s.config.ListenAddr, s.tlsConf)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener: %w", err)
	}

	s.logger.Infof("SSTP server listening on %s", s.config.ListenAddr)

	// Start accepting connections
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Errorf("Failed to accept connection: %v", err)
				continue
			}
		}

		// Handle connection in a goroutine
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(ctx, conn)
		}()
	}
}

// handleConnection handles an incoming SSTP connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Get remote IP
	remoteAddr := conn.RemoteAddr().String()
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		s.logger.Errorf("Failed to parse remote address %s: %v", remoteAddr, err)
		return
	}

	s.logger.Infof("New connection from %s", remoteAddr)

	// Create a buffered reader for HTTP parsing
	reader := bufio.NewReader(conn)

	// Parse initial HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		s.logger.Errorf("Failed to parse HTTP request from %s: %v", remoteAddr, err)
		return
	}

	// Check if this is an SSTP connection request
	if req.Method != "SSTP_DUPLEX_POST" && req.Header.Get("Content-Type") != "application/sstp" {
		s.logger.Warnf("Invalid SSTP request from %s", remoteAddr)
		// We can't use http.Error here because we're not in an HTTP handler context
		// Just close the connection
		return
	}

	// Send SSTP response
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": []string{"application/sstp"},
		},
		Body:          nil,
		ContentLength: -1,
	}

	if err := resp.Write(conn); err != nil {
		s.logger.Errorf("Failed to send SSTP response to %s: %v", remoteAddr, err)
		return
	}

	// Create session ID
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Create PPP session
	pppConfig := &ppp.Config{
		OptionsPath:     s.config.PPPOptionsPath,
		ChapSecretsPath: s.config.PPPChapSecretsPath,
	}

	pppSession, err := ppp.NewSession(sessionID, remoteIP, pppConfig, s.logger)
	if err != nil {
		s.logger.Errorf("Failed to create PPP session for %s: %v", remoteAddr, err)
		return
	}

	// Create SSTP session
	session := &SSTPSession{
		ID:        sessionID,
		Conn:      conn,
		PPP:       pppSession,
		StartTime: time.Now(),
		RemoteIP:  remoteIP,
	}

	// Register session
	s.sessions.add(session)

	// Remove session when done
	defer s.sessions.remove(sessionID)

	// Handle SSTP protocol
	s.handleSSTPProtocol(ctx, session)
}

// handleSSTPProtocol handles the SSTP protocol after HTTP handshake
func (s *Server) handleSSTPProtocol(ctx context.Context, session *SSTPSession) {
	// Create context for this session
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start pumping data between SSTP and PPP
	errChan := make(chan error, 2)

	// Pump data from SSTP to PPP
	go func() {
		err := session.PPP.PumpData(sessionCtx, session.Conn, session.Conn)
		errChan <- err
	}()

	// Handle SSTP control messages (simplified)
	go func() {
		buf := make([]byte, 1500)
		for {
			// In a real implementation, we would parse SSTP control frames here
			// For now, we just read and ignore control messages
			_, err := session.Conn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			// TODO: Implement proper SSTP control message handling
			// - Parse SSTP headers
			// - Handle Call Connect, Call Connected messages
			// - Send keepalive messages
			// - Handle disconnection
		}
	}()

	// Wait for context cancellation or an error
	select {
	case <-sessionCtx.Done():
		s.logger.Infof("Session %s cancelled", session.ID)
	case err := <-errChan:
		if err != io.EOF {
			s.logger.Errorf("Session %s error: %v", session.ID, err)
		} else {
			s.logger.Infof("Session %s ended normally", session.ID)
		}
	}
}

// Wait waits for all connections to finish
func (s *Server) Wait() {
	s.wg.Wait()
}

// GetSessions returns information about all active sessions
func (s *Server) GetSessions() []*ppp.SessionInfo {
	return s.sessions.GetSessions()
}

// add adds a session to the manager
func (sm *SessionManager) add(session *SSTPSession) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.ID] = session
}

// remove removes a session from the manager
func (sm *SessionManager) remove(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

// GetSessions returns information about all active sessions
func (sm *SessionManager) GetSessions() []*ppp.SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*ppp.SessionInfo, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		if session.PPP != nil {
			sessions = append(sessions, session.PPP.GetInfo())
		}
	}
	return sessions
}

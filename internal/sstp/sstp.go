package sstp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
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

	publicIP, err := netutil.GetPublicIP()
	if err != nil {
		logger.Warnf("Failed to detect public IP, using localhost: %v", err)
		publicIP = net.ParseIP("127.0.0.1")
	}

	if err := pki.EnsureServerCertForIP(
		cfg.ServerCertPath,
		cfg.ServerKeyPath,
		cfg.CACertPath,
		cfg.CAKeyPath,
		publicIP,
	); err != nil {
		return nil, fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	server.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256, tls.CurveP384, tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
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

		if tc, ok := conn.(*tls.Conn); ok {
			if err := tc.Handshake(); err != nil {
				s.logger.Errorf("TLS handshake error: %v", err)
				_ = tc.Close()
				continue
			}
			cs := tc.ConnectionState()
			s.logger.Infof("TLS negotiated with %s version=0x%x cipher=0x%x", conn.RemoteAddr().String(), cs.Version, cs.CipherSuite)
		}

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

	remoteAddr := conn.RemoteAddr().String()
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		s.logger.Errorf("Failed to parse remote address %s: %v", remoteAddr, err)
		return
	}

	s.logger.Infof("New connection from %s", remoteAddr)

	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		s.logger.Errorf("failed reading request line from %s: %v", remoteAddr, err)
		return
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		s.logger.Errorf("bad request line from %s: %q", remoteAddr, line)
		return
	}
	method := parts[0]
	if method != "SSTP_DUPLEX_POST" {
		s.logger.Warnf("not SSTP_DUPLEX_POST from %s: %s", remoteAddr, method)
		return
	}

	for {
		h, err := br.ReadString('\n')
		if err != nil {
			s.logger.Errorf("failed reading headers from %s: %v", remoteAddr, err)
			return
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		// accept any Content-Length including 18446744073709551615
		// accept Content-Type variations (e.g., application/soap+xml)
	}

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"Content-Type: application/soap+xml\r\n" +
		"Server: sstpd\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		s.logger.Errorf("failed to write SSTP HTTP response to %s: %v", remoteAddr, err)
		return
	}

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	pppConfig := &ppp.Config{
		OptionsPath:     s.config.PPPOptionsPath,
		ChapSecretsPath: s.config.PPPChapSecretsPath,
	}

	pppSession, err := ppp.NewSession(sessionID, remoteIP, pppConfig, s.logger)
	if err != nil {
		s.logger.Errorf("Failed to create PPP session for %s: %v", remoteAddr, err)
		return
	}

	session := &SSTPSession{
		ID:        sessionID,
		Conn:      conn,
		PPP:       pppSession,
		StartTime: time.Now(),
		RemoteIP:  remoteIP,
	}

	s.sessions.add(session)
	defer s.sessions.remove(sessionID)

	s.handleSSTPProtocol(ctx, session)
}

// handleSSTPProtocol handles the SSTP protocol after HTTP handshake
func (s *Server) handleSSTPProtocol(ctx context.Context, session *SSTPSession) {
	s.logger.Debugf("Starting SSTP protocol handler for session %s", session.ID)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		s.logger.Debugf("SSTP protocol handler ended for session %s", session.ID)
	}()

	errChan := make(chan error, 2)

	go func() {
		s.logger.Debugf("Starting data pump for session %s", session.ID)
		err := session.PPP.PumpData(sessionCtx, session.Conn, session.Conn)
		s.logger.Debugf("Data pump finished for session %s with error: %v", session.ID, err)
		errChan <- err
	}()

	go func() {
		s.logger.Debugf("Starting SSTP control message handler for session %s", session.ID)
		buf := make([]byte, 1500)
		for {
			n, err := session.Conn.Read(buf)
			if err != nil {
				s.logger.Debugf("SSTP control message read error for session %s: %v (read %d bytes)", session.ID, err, n)
				errChan <- err
				return
			}
			s.logger.Debugf("Received %d bytes of SSTP control data for session %s", n, session.ID)
			// TODO: implement SSTP control frames parsing and keepalives
		}
	}()

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

func (sm *SessionManager) add(session *SSTPSession) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.ID] = session
	count := len(sm.sessions)
	// Log session count after adding
	if session.PPP != nil {
		session.PPP.logger.Debugf("Added session %s. Total sessions: %d", session.ID, count)
	}
}

func (sm *SessionManager) remove(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
	count := len(sm.sessions)
	// Log session count after removing
	// We can't log from the session being removed, so we'll use a generic logger
	// In practice, you might want to pass a logger to the SessionManager
}

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

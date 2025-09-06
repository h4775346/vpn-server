package sstp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
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

const (
	sstpVersion10 = 0x10
	ctrlBit       = 0x01

	msgCallConnectRequest = 0x0001
	msgCallConnectAck     = 0x0002
	msgCallConnected      = 0x0004
)

type Server struct {
	config   *config.Config
	logger   *logging.Logger
	tlsConf  *tls.Config
	listener net.Listener
	sessions *SessionManager
	wg       sync.WaitGroup
}

type SessionManager struct {
	sessions map[string]*SSTPSession
	mu       sync.RWMutex
}

type SSTPSession struct {
	ID        string
	Conn      net.Conn
	PPP       *ppp.Session
	StartTime time.Time
	RemoteIP  string
}

func NewServer(cfg *config.Config, logger *logging.Logger) (*Server, error) {
	server := &Server{
		config:   cfg,
		logger:   logger,
		sessions: &SessionManager{sessions: make(map[string]*SSTPSession)},
	}

	publicIP, err := netutil.GetPublicIP()
	if err != nil {
		logger.Warnf("Failed to detect public IP, using localhost: %v", err)
		publicIP = net.ParseIP("127.0.0.1")
	}

	if err := pki.EnsureCA(cfg.CAKeyPath, cfg.CACertPath); err != nil {
		return nil, fmt.Errorf("failed to ensure CA: %w", err)
	}

	if err := pki.EnsureServerCertForIP(cfg.ServerCertPath, cfg.ServerKeyPath, cfg.CACertPath, cfg.CAKeyPath, publicIP); err != nil {
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

func (s *Server) Start(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.config.ListenAddr, s.tlsConf)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener: %w", err)
	}
	s.listener = ln
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
	if len(parts) < 3 || parts[0] != "SSTP_DUPLEX_POST" {
		s.logger.Warnf("not SSTP_DUPLEX_POST from %s: %q", remoteAddr, line)
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
	}

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"Connection: Keep-Alive\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
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

	if err := s.runSSTP(ctx, session, br); err != nil {
		if err != io.EOF {
			s.logger.Errorf("Session %s error: %v", session.ID, err)
		}
	}
}

func (s *Server) runSSTP(ctx context.Context, session *SSTPSession, r *bufio.Reader) error {
	s.logger.Debugf("Waiting for CALL_CONNECT_REQUEST for session %s", session.ID)

	hdr, payload, err := readSSTPPacket(r)
	if err != nil {
		return fmt.Errorf("read first SSTP packet: %w", err)
	}
	if !hdr.control || len(payload) < 4 {
		return fmt.Errorf("unexpected first SSTP packet")
	}
	t := binary.BigEndian.Uint16(payload[0:2])
	if t != msgCallConnectRequest {
		return fmt.Errorf("unexpected control message 0x%04x", t)
	}
	s.logger.Debugf("Got CALL_CONNECT_REQUEST for session %s", session.ID)

	if err := writeCallConnectAck(session.Conn); err != nil {
		return fmt.Errorf("write CALL_CONNECT_ACK: %w", err)
	}
	s.logger.Debugf("Sent CALL_CONNECT_ACK for session %s", session.ID)

	if err := writeCallConnected(session.Conn); err != nil {
		return fmt.Errorf("write CALL_CONNECTED: %w", err)
	}
	s.logger.Debugf("Sent CALL_CONNECTED for session %s", session.ID)

	errCh := make(chan error, 2)

	go func() {
		for {
			h, pl, err := readSSTPPacket(r)
			if err != nil {
				errCh <- err
				return
			}
			if !h.control {
				if len(pl) == 0 {
					continue
				}
				if _, werr := session.PPP.PTY().Write(pl); werr != nil {
					errCh <- werr
					return
				}
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := session.PPP.PTY().Read(buf)
			if n > 0 {
				if werr := writeSSTPDataPacket(session.Conn, buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

type sstpHeader struct {
	version byte
	control bool
	length  uint16
}

func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func readSSTPPacket(r *bufio.Reader) (sstpHeader, []byte, error) {
	var h sstpHeader
	hdr, err := readN(r, 4)
	if err != nil {
		return h, nil, err
	}
	if hdr[0] != sstpVersion10 {
		return h, nil, fmt.Errorf("unsupported SSTP version 0x%02x", hdr[0])
	}
	h.version = hdr[0]
	h.control = (hdr[1] & ctrlBit) != 0
	lenField := binary.BigEndian.Uint16(hdr[2:4]) & 0x0FFF
	if lenField < 4 {
		return h, nil, fmt.Errorf("invalid SSTP length %d", lenField)
	}
	h.length = lenField
	payloadLen := int(lenField) - 4
	payload, err := readN(r, payloadLen)
	return h, payload, err
}

func writeCallConnectAck(w io.Writer) error {
	body := make([]byte, 0, 48-4)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[0:2], msgCallConnectAck)
	binary.BigEndian.PutUint16(tmp[2:4], 1)
	body = append(body, tmp...)

	body = append(body, 0x00)
	body = append(body, 0x04)
	len1 := uint16(0x028)
	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, len1&0x0FFF)
	body = append(body, tmp2...)
	body = append(body, 0x00, 0x00, 0x00)

	body = append(body, byte(0x03))
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	body = append(body, nonce...)

	totalLen := uint16(4 + len(body))
	hdr := make([]byte, 4)
	hdr[0] = sstpVersion10
	hdr[1] = ctrlBit
	binary.BigEndian.PutUint16(hdr[2:4], totalLen&0x0FFF)

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func writeCallConnected(w io.Writer) error {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], msgCallConnected)
	binary.BigEndian.PutUint16(body[2:4], 0)

	totalLen := uint16(4 + len(body))
	hdr := make([]byte, 4)
	hdr[0] = sstpVersion10
	hdr[1] = ctrlBit
	binary.BigEndian.PutUint16(hdr[2:4], totalLen&0x0FFF)

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func writeSSTPDataPacket(w io.Writer, payload []byte) error {
	const max = 4091
	offset := 0
	for offset < len(payload) {
		chunk := payload[offset:]
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		totalLen := uint16(4 + len(chunk))
		hdr := make([]byte, 4)
		hdr[0] = sstpVersion10
		hdr[1] = 0x00
		binary.BigEndian.PutUint16(hdr[2:4], totalLen&0x0FFF)

		if _, err := w.Write(hdr); err != nil {
			return err
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		offset += len(chunk)
	}
	return nil
}

func (s *Server) Wait()                           { s.wg.Wait() }
func (s *Server) GetSessions() []*ppp.SessionInfo { return s.sessions.GetSessions() }

func (sm *SessionManager) add(session *SSTPSession) {
	sm.mu.Lock()
	sm.sessions[session.ID] = session
	sm.mu.Unlock()
}
func (sm *SessionManager) remove(sessionID string) {
	sm.mu.Lock()
	delete(sm.sessions, sessionID)
	sm.mu.Unlock()
}
func (sm *SessionManager) GetSessions() []*ppp.SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]*ppp.SessionInfo, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		if s.PPP != nil {
			out = append(out, s.PPP.GetInfo())
		}
	}
	return out
}

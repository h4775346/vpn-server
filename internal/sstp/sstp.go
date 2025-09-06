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

/*
SSTP constants from MS-SSTP
Message types
  0x0001 CALL_CONNECT_REQUEST
  0x0002 CALL_CONNECT_ACK
  0x0003 CALL_CONNECT_NAK
  0x0004 CALL_CONNECTED
  0x0005 CALL_ABORT
  0x0006 ECHO_REQUEST
  0x0007 ECHO_RESPONSE
Attributes
  0x01 ENCAPSULATED_PROTOCOL_ID
  0x02 STATUS_INFO
  0x03 CRYPTO_BINDING
  0x04 CRYPTO_BINDING_REQ
Encapsulated protocol
  0x0001 PPP
*/

const (
	msgCallConnectRequest = 0x0001
	msgCallConnectAck     = 0x0002
	msgCallConnected      = 0x0004

	attrEncapsulatedProto = 0x01
	attrStatusInfo        = 0x02
	attrCryptoBinding     = 0x03
	attrCryptoBindingReq  = 0x04

	encapPPP = 0x0001
)

// Server represents the SSTP server
type Server struct {
	config   *config.Config
	logger   *logging.Logger
	tlsConf  *tls.Config
	listener net.Listener
	sessions *SessionManager
	wg       sync.WaitGroup
	nonce    [32]byte // server nonce for Crypto-Binding Request
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

	// generate server nonce once per process
	if _, err := rand.Read(server.nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	server.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10, // earliest Mikrotik and some legacy clients
		CurvePreferences: []tls.CurveID{
			tls.CurveP256, tls.CurveP384, tls.X25519,
		},
		CipherSuites: []uint16{
			// RSA suites kept for older RouterOS
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// ECDHE RSA suites for newer clients
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
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

	// request line
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
	if parts[0] != "SSTP_DUPLEX_POST" {
		s.logger.Warnf("not SSTP_DUPLEX_POST from %s: %s", remoteAddr, parts[0])
		return
	}

	// headers, ignore but consume until blank line
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

	// send HTTP 200 OK with infinite length and SOAP content type
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"Content-Type: application/soap+xml\r\n" +
		"Server: sstpd\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		s.logger.Errorf("failed to write SSTP HTTP response to %s: %v", remoteAddr, err)
		return
	}

	// now the body is a bi-directional SSTP stream
	// wait for CALL_CONNECT_REQUEST then reply with CALL_CONNECT_ACK containing a Crypto Binding Request
	if err := s.handleSSTPNegotiation(br, conn); err != nil {
		s.logger.Errorf("SSTP negotiation failed for %s: %v", remoteAddr, err)
		return
	}

	// spin PPP
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

	// start data pumps until one side closes
	s.handleSSTPData(ctx, br, session)
}

func (s *Server) handleSSTPNegotiation(r *bufio.Reader, w io.Writer) error {
	// read CALL_CONNECT_REQUEST control packet
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("read CCR header: %w", err)
	}
	// Version high nibble must be 1 for 1.0
	if hdr[0]>>4 != 0x1 || (hdr[1]&0x80) == 0 {
		return fmt.Errorf("invalid CCR header")
	}
	length := int(binary.BigEndian.Uint16(hdr[2:]) & 0x0FFF)
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read CCR body: %w", err)
	}
	if binary.BigEndian.Uint16(body[0:2]) != msgCallConnectRequest {
		return fmt.Errorf("expected CALL_CONNECT_REQUEST")
	}
	attrCount := int(binary.BigEndian.Uint16(body[2:4]))
	// skip Reserved1 at body[4]
	pos := 5
	encapOK := false
	for i := 0; i < attrCount && pos+4 <= len(body); i++ {
		// attribute header inside control body
		// [AttrID:1][Len:2 with 12-bit size][value...]
		attrID := int(body[pos+1-1]) // pos points to Reserved byte of attribute, so attrID at pos+1
		// actually format is [Reserved:1][AttrID:1][Len:2] then value
		attrID = int(body[pos+1])
		alen := int(binary.BigEndian.Uint16(body[pos+2:pos+4]) & 0x0FFF)
		if pos+alen > len(body) {
			return fmt.Errorf("attribute overrun")
		}
		switch attrID {
		case attrEncapsulatedProto:
			if alen < 6 {
				return fmt.Errorf("ENCAP attribute too short")
			}
			proto := binary.BigEndian.Uint16(body[pos+4 : pos+6])
			if proto == encapPPP {
				encapOK = true
			}
		}
		pos += alen
	}
	if !encapOK {
		return fmt.Errorf("client did not propose PPP encapsulation")
	}

	// send CALL_CONNECT_ACK with a Crypto Binding Request attribute
	ackPkt := s.buildCallConnectAckWithCBR()
	if _, err := w.Write(ackPkt); err != nil {
		return fmt.Errorf("write CCA: %w", err)
	}
	s.logger.Debugf("Sent CALL_CONNECT_ACK with Crypto Binding Request")
	return nil
}

func (s *Server) buildCallConnectAckWithCBR() []byte {
	// attribute: Crypto Binding Request
	// layout:
	// [Reserved:1][AttrID:1=0x04][Len:2=0x028][Reserved1:3][HashBitmask:1][Nonce:32][Reserved2:1]
	attr := make([]byte, 0, 0x28)
	tmp := make([]byte, 2)

	// header fields for attribute
	attr = append(attr, 0x00) // Reserved
	attr = append(attr, byte(attrCryptoBindingReq))
	binary.BigEndian.PutUint16(tmp, 0x028) // length including this 4-byte header
	attr = append(attr, tmp...)
	attr = append(attr, 0x00, 0x00, 0x00) // Reserved1
	attr = append(attr, 0x02)             // Hash Protocol Bitmask: allow SHA256
	attr = append(attr, s.nonce[:]...)    // 32 bytes server nonce
	attr = append(attr, 0x00)             // Reserved2

	// control body
	body := make([]byte, 0, 4+len(attr))
	binary.BigEndian.PutUint16(tmp, msgCallConnectAck)
	body = append(body, tmp...)     // Message Type
	body = append(body, 0x00, 0x01) // Num Attributes = 1
	body = append(body, 0x00)       // Reserved1
	body = append(body, attr...)    // Attribute

	// full SSTP control packet
	pkt := make([]byte, 0, 4+len(body))
	pkt = append(pkt, 0x10) // Version 1.0
	pkt = append(pkt, 0x80) // C bit set for control
	totalLen := 4 + len(body)
	lenField := uint16(totalLen) & 0x0FFF
	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, lenField)
	pkt = append(pkt, tmp2...)
	pkt = append(pkt, body...)
	return pkt
}

// handleSSTPData pumps PPP frames inside SSTP data packets
func (s *Server) handleSSTPData(ctx context.Context, r *bufio.Reader, session *SSTPSession) {
	// writer goroutine: PPP to SSTP
	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := session.PPP.PTY().Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("PPP read: %w", err)
				return
			}
			if n == 0 {
				continue
			}
			// wrap as SSTP data packet
			data := buildSSTPDataPacket(buf[:n])
			if _, err := session.Conn.Write(data); err != nil {
				errCh <- fmt.Errorf("SSTP write: %w", err)
				return
			}
			s.logger.Debugf("PPP->SSTP forwarded %d bytes for session %s", n, session.ID)
		}
	}()

	// reader goroutine: SSTP to PPP
	go func() {
		for {
			c, payload, err := readSSTPPacket(r)
			if err != nil {
				errCh <- err
				return
			}
			if c {
				// control packet during data phase
				if len(payload) >= 2 {
					mt := binary.BigEndian.Uint16(payload[0:2])
					switch mt {
					case msgCallConnected:
						s.logger.Debugf("Got CALL_CONNECTED for session %s", session.ID)
						// do not reply here. validation of Crypto Binding would be next step
					default:
						// ignore echo and others for now
					}
				}
				continue
			}
			if len(payload) == 0 {
				continue
			}
			// write raw PPP bytes into pppd
			if _, err := session.PPP.PTY().Write(payload); err != nil {
				errCh <- fmt.Errorf("PPP write: %w", err)
				return
			}
			s.logger.Debugf("SSTP->PPP forwarded %d bytes for session %s", len(payload), session.ID)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Infof("Session %s cancelled", session.ID)
	case err := <-errCh:
		if err != io.EOF {
			s.logger.Errorf("Session %s error: %v", session.ID, err)
		} else {
			s.logger.Infof("Session %s ended", session.ID)
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
}

func (sm *SessionManager) remove(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
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

// helpers

func buildSSTPDataPacket(payload []byte) []byte {
	h := make([]byte, 4)
	h[0] = 0x10           // Version 1.0
	h[1] = 0x00           // C bit clear for data
	l := 4 + len(payload) // total length
	binary.BigEndian.PutUint16(h[2:], uint16(l)&0x0FFF)
	return append(h, payload...)
}

func readSSTPPacket(r *bufio.Reader) (isControl bool, payload []byte, err error) {
	h := make([]byte, 4)
	if _, err = io.ReadFull(r, h); err != nil {
		return false, nil, err
	}
	if h[0]>>4 != 0x1 {
		return false, nil, fmt.Errorf("bad SSTP version")
	}
	isControl = (h[1] & 0x80) != 0
	l := int(binary.BigEndian.Uint16(h[2:]) & 0x0FFF)
	if l < 4 {
		return false, nil, fmt.Errorf("bad SSTP length")
	}
	body := make([]byte, l-4)
	if _, err = io.ReadFull(r, body); err != nil {
		return false, nil, err
	}
	return isControl, body, nil
}

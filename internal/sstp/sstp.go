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
SSTP framing (per MS-SSTP):
Byte0: Version (major in high nibble, minor in low) -> 0x10 for v1.0
Byte1: Control bit in the LSB (0x01) for control frames, 0x00 for data
Bytes2-3: 12-bit length (big-endian), includes the 4-byte header
*/

const (
	sstpV10 = 0x10
	ctrlBit = 0x01

	msgCallConnectRequest = 0x0001
	msgCallConnectAck     = 0x0002
	msgCallConnected      = 0x0004

	attrEncapsulatedProto = 0x01
	attrCryptoBindingReq  = 0x04

	encapPPP = 0x0001
)

type Server struct {
	config   *config.Config
	logger   *logging.Logger
	tlsConf  *tls.Config
	listener net.Listener
	sessions *SessionManager
	wg       sync.WaitGroup
	nonce    [32]byte
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
	s := &Server{
		config:   cfg,
		logger:   logger,
		sessions: &SessionManager{sessions: make(map[string]*SSTPSession)},
	}

	publicIP, err := netutil.GetPublicIP()
	if err != nil {
		logger.Warnf("Failed to detect public IP, using localhost: %v", err)
		publicIP = net.ParseIP("127.0.0.1")
	}

	if err := pki.EnsureServerCertForIP(cfg.ServerCertPath, cfg.ServerKeyPath, cfg.CACertPath, cfg.CAKeyPath, publicIP); err != nil {
		return nil, fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	if _, err := rand.Read(s.nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	s.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256, tls.CurveP384, tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	return s, nil
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

	// Parse HTTP request line
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

	// Consume headers
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

	// Send HTTP 200 OK with infinite Content-Length
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"Server: sstpd\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		s.logger.Errorf("failed to write SSTP HTTP response to %s: %v", remoteAddr, err)
		return
	}

	// SSTP negotiation
	if err := s.negotiate(br, conn); err != nil {
		s.logger.Errorf("SSTP negotiation failed for %s: %v", remoteAddr, err)
		return
	}

	// Start PPP through pppd
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

	// Pump data both ways until one side closes
	s.dataPump(ctx, br, session)
}

func (s *Server) negotiate(r *bufio.Reader, w io.Writer) error {
	// read SSTP header
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if hdr[0] != sstpV10 || (hdr[1]&ctrlBit) == 0 {
		return fmt.Errorf("invalid CCR header")
	}
	length := int(binary.BigEndian.Uint16(hdr[2:]) & 0x0FFF)
	if length < 8 {
		return fmt.Errorf("short CCR length %d", length)
	}

	// read body
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if binary.BigEndian.Uint16(body[0:2]) != msgCallConnectRequest {
		return fmt.Errorf("expected CALL_CONNECT_REQUEST")
	}

	// parse attributes; accept both formats:
	// A: [Reserved:1][AttrID:1][Len:2][Value...]
	// B: [AttrID:1][Len:2][Value...]   (seen on MikroTik)
	encapOK := false
	for pos := 2 + 2 + 1; pos < len(body); {
		remain := len(body) - pos
		if remain < 3 { // need at least id+len
			break
		}

		// try layout A
		useA := false
		var idA byte
		var lenA int
		if remain >= 4 {
			idA = body[pos+1]
			lenA = int(binary.BigEndian.Uint16(body[pos+2:pos+4]) & 0x0FFF)
			if lenA >= 4 && pos+lenA <= len(body) && idA != 0 {
				useA = true
			}
		}

		if useA {
			valStart := pos + 4
			valEnd := pos + lenA
			if idA == attrEncapsulatedProto {
				if valEnd-valStart >= 2 && binary.BigEndian.Uint16(body[valStart:valStart+2]) == encapPPP {
					encapOK = true
				}
			}
			pos = valEnd
			continue
		}

		// fallback layout B
		idB := body[pos]
		lenB := int(binary.BigEndian.Uint16(body[pos+1:pos+3]) & 0x0FFF)
		if lenB < 3 || pos+lenB > len(body) {
			return fmt.Errorf("malformed attribute")
		}
		valStart := pos + 3
		valEnd := pos + lenB
		if idB == attrEncapsulatedProto {
			if valEnd-valStart >= 2 && binary.BigEndian.Uint16(body[valStart:valStart+2]) == encapPPP {
				encapOK = true
			}
		}
		pos = valEnd
	}

	if !encapOK {
		return fmt.Errorf("client did not propose PPP encapsulation")
	}

	// send Call Connect Ack with Crypto Binding Request
	ack := s.buildCCAWithCBR()
	if _, err := w.Write(ack); err != nil {
		return fmt.Errorf("write CCA: %w", err)
	}

	// send Call Connected
	cc := buildCallConnected()
	if _, err := w.Write(cc); err != nil {
		return fmt.Errorf("write CC: %w", err)
	}

	return nil
}

func (s *Server) buildCCAWithCBR() []byte {
	// Attribute: Crypto Binding Request
	attr := make([]byte, 0, 0x28)
	tmp2 := make([]byte, 2)

	attr = append(attr, 0x00) // Reserved
	attr = append(attr, byte(attrCryptoBindingReq))
	binary.BigEndian.PutUint16(tmp2, 0x028)
	attr = append(attr, tmp2...)
	attr = append(attr, 0x00, 0x00, 0x00) // Reserved1
	attr = append(attr, 0x02)             // Hash mask: SHA256
	attr = append(attr, s.nonce[:]...)    // 32-byte server nonce
	attr = append(attr, 0x00)             // Reserved2

	// Control body
	body := make([]byte, 0, 4+len(attr))
	binary.BigEndian.PutUint16(tmp2, msgCallConnectAck)
	body = append(body, tmp2...)    // Type
	body = append(body, 0x00, 0x01) // NumAttributes = 1
	body = append(body, 0x00)       // Reserved1
	body = append(body, attr...)    // Attribute

	// Frame
	h := make([]byte, 4)
	h[0] = sstpV10
	h[1] = ctrlBit
	binary.BigEndian.PutUint16(h[2:], uint16(4+len(body))&0x0FFF)
	return append(h, body...)
}

func buildCallConnected() []byte {
	// Minimal Call Connected with zero attributes
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], msgCallConnected)
	binary.BigEndian.PutUint16(body[2:4], 0)

	h := make([]byte, 4)
	h[0] = sstpV10
	h[1] = ctrlBit
	binary.BigEndian.PutUint16(h[2:], uint16(4+len(body))&0x0FFF)
	return append(h, body...)
}

func (s *Server) dataPump(ctx context.Context, r *bufio.Reader, sess *SSTPSession) {
	errCh := make(chan error, 2)

	// PPP -> SSTP
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sess.PPP.PTY().Read(buf)
			if n > 0 {
				if err := writeSSTPData(sess.Conn, buf[:n]); err != nil {
					errCh <- fmt.Errorf("SSTP write: %w", err)
					return
				}
				s.snoop(fmt.Sprintf("PPP->SSTP %d bytes", n))
			}
			if err != nil {
				errCh <- fmt.Errorf("PPP read: %w", err)
				return
			}
		}
	}()

	// SSTP -> PPP
	go func() {
		for {
			isCtrl, payload, err := readSSTPPacket(r)
			if err != nil {
				errCh <- err
				return
			}
			if isCtrl {
				// ignore control for now
				continue
			}
			if len(payload) == 0 {
				continue
			}
			if _, err := sess.PPP.PTY().Write(payload); err != nil {
				errCh <- fmt.Errorf("PPP write: %w", err)
				return
			}
			s.snoop(fmt.Sprintf("SSTP->PPP %d bytes", len(payload)))
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Infof("Session %s cancelled", sess.ID)
	case err := <-errCh:
		if err != io.EOF {
			s.logger.Errorf("Session %s error: %v", sess.ID, err)
		} else {
			s.logger.Infof("Session %s ended", sess.ID)
		}
	}
}

func writeSSTPData(w io.Writer, p []byte) error {
	// Split into chunks <= 4091
	for off := 0; off < len(p); {
		chunk := p[off:]
		if len(chunk) > 4091 {
			chunk = chunk[:4091]
		}
		h := make([]byte, 4)
		h[0] = sstpV10
		h[1] = 0x00
		binary.BigEndian.PutUint16(h[2:], uint16(4+len(chunk))&0x0FFF)
		if _, err := w.Write(h); err != nil {
			return err
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		off += len(chunk)
	}
	return nil
}

func readSSTPPacket(r *bufio.Reader) (isControl bool, payload []byte, err error) {
	h := make([]byte, 4)
	if _, err = io.ReadFull(r, h); err != nil {
		return false, nil, err
	}
	if h[0] != sstpV10 {
		return false, nil, fmt.Errorf("bad version 0x%02x", h[0])
	}
	isControl = (h[1] & ctrlBit) != 0
	l := int(binary.BigEndian.Uint16(h[2:]) & 0x0FFF)
	if l < 4 {
		return false, nil, fmt.Errorf("bad length %d", l)
	}
	body := make([]byte, l-4)
	if _, err = io.ReadFull(r, body); err != nil {
		return false, nil, err
	}
	return isControl, body, nil
}

func (s *Server) snoop(msg string) {
	s.logger.Debugf(msg)
}

func (s *Server) Wait() { s.wg.Wait() }

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

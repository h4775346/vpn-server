package ppp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/h4775346/vpn-server/internal/logging"
)

// Session represents a PPP session
type Session struct {
	ID        string
	RemoteIP  string
	StartTime time.Time
	Username  string
	BytesIn   uint64
	BytesOut  uint64

	ptmx   *os.File
	cmd    *exec.Cmd
	logger *logging.Logger
	mu     sync.RWMutex
}

// Config holds PPP configuration
type Config struct {
	OptionsPath     string
	ChapSecretsPath string
}

// NewSession creates a new PPP session
func NewSession(id, remoteIP string, config *Config, logger *logging.Logger) (*Session, error) {
	logger.Debugf("Creating new PPP session %s for remote IP %s", id, remoteIP)

	session := &Session{
		ID:        id,
		RemoteIP:  remoteIP,
		StartTime: time.Now(),
		logger:    logger,
	}

	// Build pppd command
	args := []string{
		"pty",                           // Use pty
		"noauth",                        // Don't authenticate peer
		"nodetach",                      // Don't detach from terminal
		"novj",                          // Disable Van Jacobson compression
		"novjccomp",                     // Disable Van Jacobson header compression
		"nopcomp",                       // Disable protocol field compression
		"noaccomp",                      // Disable address/control field compression
		"default-asyncmap",              // Use default asyncmap
		"plugin", "sstp-pppd-plugin.so", // SSTP plugin
		"sstp-sock", fmt.Sprintf("/tmp/sstp-%s.sock", id), // Socket for SSTP plugin
	}

	// Add options file if specified
	if config.OptionsPath != "" {
		args = append(args, "file", config.OptionsPath)
	}

	logger.Debugf("pppd command args: %v", args)

	// Create pppd command
	session.cmd = exec.Command("pppd", args...)

	// Log the full command for debugging
	logger.Debugf("Executing pppd command: %s", session.cmd.String())

	// Start pppd with pty
	ptmx, err := pty.Start(session.cmd)
	if err != nil {
		logger.Errorf("Failed to start pppd for session %s: %v", id, err)
		return nil, fmt.Errorf("failed to start pppd: %w", err)
	}

	session.ptmx = ptmx
	logger.Debugf("Successfully started pppd for session %s", id)

	// Start monitoring PPP logs for username
	go session.monitorLogs()

	return session, nil
}

// monitorLogs monitors PPP logs to extract the username
func (s *Session) monitorLogs() {
	reader := bufio.NewReader(s.ptmx)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				s.logger.Debugf("Error reading from pppd: %v", err)
			}
			break
		}

		// Log all PPP output for debugging
		s.logger.Debugf("PPP output: %s", strings.TrimSpace(line))

		// Look for authentication success message
		if strings.Contains(line, "mschap_v2:") && strings.Contains(line, "authentication succeeded") {
			// Extract username from log line
			// This is a simplified approach - in practice, you might need more sophisticated parsing
			parts := strings.Split(line, " ")
			for i, part := range parts {
				if part == "login" && i+1 < len(parts) {
					s.mu.Lock()
					s.Username = strings.Trim(parts[i+1], "\"")
					s.mu.Unlock()
					s.logger.Infof("PPP authentication succeeded for user: %s", s.Username)
					break
				}
			}
		}
	}
}

// Read reads data from the PPP session
func (s *Session) Read(p []byte) (n int, err error) {
	return s.ptmx.Read(p)
}

// Write writes data to the PPP session
func (s *Session) Write(p []byte) (n int, err error) {
	return s.ptmx.Write(p)
}

// Close closes the PPP session
func (s *Session) Close() error {
	s.logger.Debugf("Closing PPP session %s", s.ID)

	if s.ptmx != nil {
		s.logger.Debugf("Closing PTY for session %s", s.ID)
		if err := s.ptmx.Close(); err != nil {
			s.logger.Debugf("Error closing PTY for session %s: %v", s.ID, err)
		}
	}

	if s.cmd != nil && s.cmd.Process != nil {
		s.logger.Debugf("Terminating pppd process for session %s (PID: %d)", s.ID, s.cmd.Process.Pid)

		// Try graceful termination first
		if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
			s.logger.Debugf("Error sending interrupt signal to pppd for session %s: %v", s.ID, err)
		}

		// Wait for process to exit or force kill after timeout
		done := make(chan error, 1)
		go func() {
			done <- s.cmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				s.logger.Debugf("pppd process for session %s exited with error: %v", s.ID, err)
			} else {
				s.logger.Debugf("pppd process for session %s exited normally", s.ID)
			}
		case <-time.After(5 * time.Second):
			s.logger.Debugf("pppd process for session %s did not exit gracefully, force killing", s.ID)
			if err := s.cmd.Process.Kill(); err != nil {
				s.logger.Debugf("Error force killing pppd process for session %s: %v", s.ID, err)
			}
		}
	}

	s.logger.Debugf("Finished closing PPP session %s", s.ID)
	return nil
}

// GetInfo returns session information
func (s *Session) GetInfo() *SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &SessionInfo{
		ID:        s.ID,
		RemoteIP:  s.RemoteIP,
		StartTime: s.StartTime,
		Username:  s.Username,
		BytesIn:   s.BytesIn,
		BytesOut:  s.BytesOut,
	}
}

// SessionInfo holds information about a PPP session
type SessionInfo struct {
	ID        string    `json:"id"`
	RemoteIP  string    `json:"remote_ip"`
	StartTime time.Time `json:"start_time"`
	Username  string    `json:"username,omitempty"`
	BytesIn   uint64    `json:"bytes_in"`
	BytesOut  uint64    `json:"bytes_out"`
}

// PumpData pumps data between SSTP and PPP
func (s *Session) PumpData(ctx context.Context, sstpReader io.Reader, sstpWriter io.Writer) error {
	// Log when pumping starts
	s.logger.Debugf("Starting data pump for session %s", s.ID)

	// Create channels for errors
	pppErrChan := make(chan error, 1)
	sstpErrChan := make(chan error, 1)

	// Pump data from PPP to SSTP
	go func() {
		buf := make([]byte, 1500) // Standard MTU size
		for {
			n, err := s.ptmx.Read(buf)
			if err != nil {
				s.logger.Debugf("PPP read error for session %s: %v (read %d bytes)", s.ID, err, n)
				pppErrChan <- err
				return
			}

			// Update bytes out counter
			s.mu.Lock()
			s.BytesOut += uint64(n)
			s.mu.Unlock()

			// Write to SSTP
			written, err := sstpWriter.Write(buf[:n])
			if err != nil {
				s.logger.Debugf("SSTP write error for session %s: %v (written %d bytes)", s.ID, err, written)
				pppErrChan <- err
				return
			}

			s.logger.Debugf("Forwarded %d bytes from PPP to SSTP for session %s", n, s.ID)
		}
	}()

	// Pump data from SSTP to PPP
	go func() {
		buf := make([]byte, 1500) // Standard MTU size
		for {
			n, err := sstpReader.Read(buf)
			if err != nil {
				s.logger.Debugf("SSTP read error for session %s: %v (read %d bytes)", s.ID, err, n)
				sstpErrChan <- err
				return
			}

			// Update bytes in counter
			s.mu.Lock()
			s.BytesIn += uint64(n)
			s.mu.Unlock()

			// Write to PPP
			written, err := s.ptmx.Write(buf[:n])
			if err != nil {
				s.logger.Debugf("PPP write error for session %s: %v (written %d bytes)", s.ID, err, written)
				sstpErrChan <- err
				return
			}

			s.logger.Debugf("Forwarded %d bytes from SSTP to PPP for session %s", n, s.ID)
		}
	}()

	// Wait for context cancellation or an error
	select {
	case <-ctx.Done():
		s.logger.Debugf("Data pump cancelled for session %s: %v", s.ID, ctx.Err())
		return ctx.Err()
	case err := <-pppErrChan:
		s.logger.Debugf("Data pump ended due to PPP error for session %s: %v", s.ID, err)
		return fmt.Errorf("PPP error: %w", err)
	case err := <-sstpErrChan:
		s.logger.Debugf("Data pump ended due to SSTP error for session %s: %v", s.ID, err)
		return fmt.Errorf("SSTP error: %w", err)
	}
}

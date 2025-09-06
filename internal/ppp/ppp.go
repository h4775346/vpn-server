package ppp

import (
	"os"
	"os/exec"
	"time"

	"github.com/creack/pty"
	"github.com/h4775346/vpn-server/internal/logging"
)

// Config holds PPP configuration
type Config struct {
	OptionsPath     string
	ChapSecretsPath string
}

// Session represents a PPP session attached to a PTY
type Session struct {
	ID        string
	RemoteIP  string
	StartTime time.Time

	cmd    *exec.Cmd
	pty    *os.File
	logger *logging.Logger
}

// SessionInfo holds information about a PPP session
type SessionInfo struct {
	ID        string    `json:"id"`
	RemoteIP  string    `json:"remote_ip"`
	StartTime time.Time `json:"start_time"`
}

// NewSession creates a new PPP session using pppd
func NewSession(id, remoteIP string, cfg *Config, logger *logging.Logger) (*Session, error) {
	logger.Debugf("Creating new PPP session %s for remote IP %s", id, remoteIP)

	args := []string{
		"nodetach",
		"notty",
	}
	if cfg.OptionsPath != "" {
		args = append(args, "file", cfg.OptionsPath)
	}

	cmd := exec.Command("pppd", args...)
	logger.Debugf("pppd command args: %v", args)

	f, err := pty.Start(cmd)
	if err != nil {
		logger.Errorf("Failed to start pppd for session %s: %v", id, err)
		return nil, err
	}
	logger.Debugf("Successfully started pppd for session %s", id)

	s := &Session{
		ID:        id,
		RemoteIP:  remoteIP,
		StartTime: time.Now(),
		cmd:       cmd,
		pty:       f,
		logger:    logger,
	}
	return s, nil
}

// PTY returns the pppd PTY file
func (s *Session) PTY() *os.File {
	return s.pty
}

// Close terminates the PPP session
func (s *Session) Close() error {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	if s.pty != nil {
		return s.pty.Close()
	}
	return nil
}

// GetInfo returns session information
func (s *Session) GetInfo() *SessionInfo {
	return &SessionInfo{
		ID:        s.ID,
		RemoteIP:  s.RemoteIP,
		StartTime: s.StartTime,
	}
}

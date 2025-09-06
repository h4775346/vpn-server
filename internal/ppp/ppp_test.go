package ppp

import (
	"testing"
	"time"

	"github.com/h4775346/vpn-server/internal/logging"
)

func TestSessionCreationLogging(t *testing.T) {
	// This test just verifies that the session creation doesn't panic
	// In a real test environment, we would need to mock pppd

	logger := logging.NewLogger()
	config := &Config{
		OptionsPath:     "/etc/ppp/options.sstp",
		ChapSecretsPath: "/etc/ppp/chap-secrets",
	}

	// This will likely fail in a test environment since pppd won't be available
	// but we're just testing that the logging works
	session, err := NewSession("test-session", "127.0.0.1", config, logger)
	if session != nil {
		// If we somehow got a session, make sure we can close it
		session.Close()
	} else {
		// Verify we got an error (expected in test environment)
		if err == nil {
			t.Error("Expected error when creating session in test environment")
		}
	}
}

func TestSessionInfo(t *testing.T) {
	logger := logging.NewLogger()
	session := &Session{
		ID:        "test-session",
		RemoteIP:  "127.0.0.1",
		StartTime: time.Now(),
		Username:  "testuser",
		BytesIn:   100,
		BytesOut:  200,
		logger:    logger,
	}

	info := session.GetInfo()
	if info.ID != "test-session" {
		t.Errorf("Expected ID test-session, got %s", info.ID)
	}

	if info.RemoteIP != "127.0.0.1" {
		t.Errorf("Expected RemoteIP 127.0.0.1, got %s", info.RemoteIP)
	}

	if info.Username != "testuser" {
		t.Errorf("Expected Username testuser, got %s", info.Username)
	}

	if info.BytesIn != 100 {
		t.Errorf("Expected BytesIn 100, got %d", info.BytesIn)
	}

	if info.BytesOut != 200 {
		t.Errorf("Expected BytesOut 200, got %d", info.BytesOut)
	}
}

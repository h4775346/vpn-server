package config

import (
	"os"
	"path/filepath"
)

// Config holds the server configuration
type Config struct {
	// Server configuration
	ListenAddr string

	// Control API configuration
	APIListenAddr string

	// PKI paths
	CAKeyPath      string
	CACertPath     string
	ServerKeyPath  string
	ServerCertPath string

	// PPP configuration
	PPPOptionsPath     string
	PPPChapSecretsPath string
}

// Load loads configuration from environment variables or uses defaults
func Load() *Config {
	cfg := &Config{
		ListenAddr:         getEnv("SSTP_LISTEN_ADDR", ":443"),
		APIListenAddr:      getEnv("SSTP_API_LISTEN_ADDR", ":8080"),
		CAKeyPath:          getEnv("SSTP_CA_KEY_PATH", "/etc/sstpd/pki/ca.key"),
		CACertPath:         getEnv("SSTP_CA_CERT_PATH", "/etc/sstpd/pki/ca.crt"),
		ServerKeyPath:      getEnv("SSTP_SERVER_KEY_PATH", "/etc/sstpd/pki/server.key"),
		ServerCertPath:     getEnv("SSTP_SERVER_CERT_PATH", "/etc/sstpd/pki/server.crt"),
		PPPOptionsPath:     getEnv("SSTP_PPP_OPTIONS_PATH", "/etc/ppp/options.sstp"),
		PPPChapSecretsPath: getEnv("SSTP_PPP_CHAP_SECRETS_PATH", "/etc/ppp/chap-secrets"),
	}

	// Ensure directories exist
	ensureDir(filepath.Dir(cfg.CAKeyPath))
	ensureDir(filepath.Dir(cfg.ServerKeyPath))

	return cfg
}

// getEnv returns the value of the environment variable or a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ensureDir creates a directory if it doesn't exist
func ensureDir(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
}

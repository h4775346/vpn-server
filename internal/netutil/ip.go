package netutil

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetPublicIP detects the public IPv4 address of the server
func GetPublicIP() (net.IP, error) {
	// Try multiple services to get public IP
	services := []string{
		"https://ipv4.icanhazip.com",
		"https://api.ipify.org",
		"http://ipv4bot.whatismyipaddress.com",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 32))
		if err != nil {
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	// If we can't get public IP, return a local IP
	return getLocalIP()
}

// getLocalIP returns a local IP address as fallback
func getLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

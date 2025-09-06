# SSTP VPN Server

A production-grade MVP for an SSTP VPN server implemented in Go.

## Features

- TLS server on port 443 (TLS ≥ 1.2)
- SSTP protocol implementation (HTTP(S) handshake, keepalives, SSTP Data framing)
- PPP bridging using `pppd` via pty
- Local PPP authentication using `/etc/ppp/chap-secrets` (MS-CHAPv2 + MPPE)
- Automatic PKI management (CA and server certificate generation)
- Simple control API with health check and session monitoring
- Clean shutdown and resource cleanup

## Project Structure

```
├─ cmd/sstpd/main.go          # Entry point
├─ internal/config/config.go  # Environment-based configuration
├─ internal/logging/logging.go# Logging utilities
├─ internal/netutil/ip.go     # Public IP detection
├─ internal/pki/pki.go        # CA and certificate management
├─ internal/ppp/ppp.go        # PPP session management
├─ internal/sstp/sstp.go      # SSTP protocol implementation
├─ internal/sstp/frames.go    # SSTP frame encoding/decoding
├─ internal/sstp/frames_test.go # Unit tests for SSTP frames
├─ internal/api/http.go       # Control API endpoints
├─ go.mod                     # Go module definition
├─ README.md                  # This file
├─ sstpd.service             # Systemd service file
├─ etc/ppp/options.sstp      # PPP options file
└─ etc/ppp/chap-secrets      # PPP chap-secrets file (example)
```

## Installation

### Prerequisites

- Go 1.22 or later
- `pppd` (PPP daemon)
- Git

### Installing Dependencies

On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y ppp git golang build-essential
```

On CentOS/RHEL:
```bash
sudo yum install -y ppp git golang
```

## Building

```bash
go build -o sstpd ./cmd/sstpd
```

## Configuration

The server can be configured using environment variables:

- `SSTP_LISTEN_ADDR` - SSTP server listen address (default: ":443")
- `SSTP_API_LISTEN_ADDR` - API server listen address (default: ":8080")
- `SSTP_CA_KEY_PATH` - CA private key path (default: "/etc/sstpd/pki/ca.key")
- `SSTP_CA_CERT_PATH` - CA certificate path (default: "/etc/sstpd/pki/ca.crt")
- `SSTP_SERVER_KEY_PATH` - Server private key path (default: "/etc/sstpd/pki/server.key")
- `SSTP_SERVER_CERT_PATH` - Server certificate path (default: "/etc/sstpd/pki/server.crt")
- `SSTP_PPP_OPTIONS_PATH` - PPP options file path (default: "/etc/ppp/options.sstp")
- `SSTP_PPP_CHAP_SECRETS_PATH` - PPP chap-secrets file path (default: "/etc/ppp/chap-secrets")

## Setting up Authentication

Create `/etc/ppp/chap-secrets` with user credentials:

```bash
# Format: client server secret IP
username sstp password *
```

Example:
```bash
# client  server  secret    IP
testuser sstp    testpass  *
```

## Firewall Configuration

Open port 443 for SSTP connections:
```bash
# UFW
sudo ufw allow 443/tcp

# Or with iptables
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

## Running the Server

```bash
sudo ./sstpd
```

Note: The server needs to be run with sudo because it binds to port 443 (privileged port) and manages PPP connections.

## Control API

The server provides a simple HTTP API for monitoring:

- `GET /health` - Health check endpoint, returns "ok"
- `GET /sessions` - List active sessions in JSON format
- `GET /export/ca.crt` - Download the CA certificate for client trust

## Client Configuration

### Windows

1. Download the CA certificate from `https://SERVER_IP:8080/export/ca.crt`
2. Import the certificate into "Trusted Root Certification Authorities"
3. Create a new VPN connection:
   - Type: SSTP
   - Server: Your server IP
   - Credentials: From chap-secrets file

### Linux

1. Download the CA certificate:
   ```bash
   curl -k https://SERVER_IP:8080/export/ca.crt -o ca.crt
   ```
2. Install the certificate in your system's trust store (varies by distribution)

### Android

1. Download the CA certificate through your browser
2. Install the certificate in "User credentials" (steps vary by OEM)

## RADIUS Integration

To add RADIUS support later, modify `/etc/ppp/options.sstp` to include:

```
plugin radius.so
plugin radattr.so
radius-config-file /etc/ppp/radius/radiusclient.conf
```

The Go code requires no changes for RADIUS integration.

## Testing

1. Start the service
2. Confirm the server is listening:
   ```bash
   ss -lntp | grep :443
   ```
3. Check health endpoint:
   ```bash
   curl -k https://SERVER_IP:8080/health
   ```
4. Connect with an SSTP client using credentials from chap-secrets
5. Verify sessions:
   ```bash
   curl -k https://SERVER_IP:8080/sessions
   ```

## Systemd Service

Create `/etc/systemd/system/sstpd.service`:

```ini
[Unit]
Description=Custom SSTP Server (Go) – PPP
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sstpd
Restart=on-failure
AmbientCapabilities=CAP_NET_ADMIN
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sstpd
sudo systemctl start sstpd
```
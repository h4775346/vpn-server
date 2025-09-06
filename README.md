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

## Building and Running

To build the server, run:

```bash
go build -o sstpd ./cmd/sstpd
```

To run the server (requires root):

```bash
sudo ./sstpd
```

## Deployment

For production deployment, the server can be installed as a systemd service:

1. Copy the service file: `sudo cp sstpd.service /etc/systemd/system/`
2. Reload systemd: `sudo systemctl daemon-reload`
3. Enable the service: `sudo systemctl enable sstpd`
4. Start the service: `sudo systemctl start sstpd`

## Systemd Service

Create `/etc/systemd/system/sstpd.service`:

```

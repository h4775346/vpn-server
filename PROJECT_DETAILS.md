You are an expert Go engineer. Build a production-grade MVP for an SSTP VPN server in Go (Go 1.22). 
NO RADIUS integration now, but the design must be RADIUS-ready for later.

## Objectives
- TLS server on :443 (TLS ≥ 1.2).
- SSTP protocol: HTTP(S) handshake (Call Connect → Call Connected), keepalives, SSTP Data framing.
- Bridge SSTP Data ↔ PPP using `pppd` via pty (github.com/creack/pty).
- **Auth for MVP**: local PPP auth using `/etc/ppp/chap-secrets` (MS-CHAPv2 + MPPE).
- Auto PKI:
  - On first run, generate a private CA (`/etc/sstpd/pki/ca.key`, `ca.crt`).
  - On each boot, detect current public IPv4 and generate a server leaf cert with `SAN=IP:<public IP>` signed by the CA.
  - Store leaf in `/etc/sstpd/pki/server.crt`, `/etc/sstpd/pki/server.key`.
  - Provide HTTP endpoint `/export/ca.crt` to download the CA cert.
- Simple control API:
  - `GET /health` → `ok`
  - `GET /sessions` → JSON list of active sessions (peer addr, start time, optional username if learned from PPP logs).
- Clean shutdown, resource cleanup.

## Non-Goals (for this MVP)
- No RADIUS calls. However, the code layout must allow dropping in a RADIUS module later with minimal changes (clean interfaces around auth/accounting, pppd args).
- No multi-tenant UI; a minimal REST control is enough.

## Project Layout
Create this structure:
├─ cmd/sstpd/main.go # entrypoint
├─ internal/config/config.go # env-based config (paths/ports)
├─ internal/logging/logging.go
├─ internal/netutil/ip.go # public IP detection
├─ internal/pki/pki.go # CA/leaf generation, SAN=IP
├─ internal/ppp/ppp.go # spawn pppd via pty
├─ internal/sstp/sstp.go # handshake, frames, keepalive, pumps
├─ internal/api/http.go # /health, /sessions, /export/ca.crt
├─ go.mod
└─ README.md


## Implementation Requirements
- Use only standard lib + `github.com/creack/pty`.
- Use contexts and proper error handling; log meaningfully.
- `pppd` invocation via pty; read/write loop:
  - SSTP→PPP: deframe SSTP Data and write PPP frames to pty.
  - PPP→SSTP: read from pty and write framed SSTP Data to TLS conn.
- Keepalive:
  - Maintain SSTP control keepalives and LCP echo via `pppd` options.
- Sessions registry:
  - Create a threadsafe registry storing connection info (start time, remote addr, bytes tx/rx if possible).
  - Expose via `/sessions`.

## PPP Configuration (for MVP)
- Create example file content for `/etc/ppp/options.sstp`:
name sstp
refuse-pap
refuse-chap
require-mschap-v2
require-mppe
mtu 1400
mru 1400
lock
nodefaultroute
proxyarp
lcp-echo-interval 20
lcp-echo-failure 3
ms-dns 8.8.8.8
ms-dns 1.1.1.1

- Use `/etc/ppp/chap-secrets` for testing (document example lines):

- **RADIUS-ready**: clearly mark in README how to switch later by just adding:
- `plugin radius.so`, `plugin radattr.so`
- `radius-config-file /etc/ppp/radius/radiusclient.conf`
- and passing no other code changes.

## PKI Details
- `EnsureCA(path)` → creates 4096-bit RSA CA with CN "SSTP Private CA", 10y validity.
- `EnsureServerCertForIP(path, ip)` → creates a 2048/3072-bit RSA leaf cert with `subjectAltName = IP:<ip>`, ~825 days validity, key usage `digitalSignature,keyEncipherment`, EKU `serverAuth`.
- Provide a helper to write `ca.crt` to an `io.Writer` for `/export/ca.crt`.

## TLS Listener
- Load the leaf cert (re-generated on boot if IP changed).
- Create `tls.Config{ MinVersion: tls.VersionTLS12 }`.
- `tls.Listen("tcp", ":443", cfg)` to accept SSTP.

## SSTP Engine
- Implement minimal compliant SSTP control channel over HTTP(S).
- Parse initial HTTP, respond appropriately, enter SSTP control mode.
- Process Call Connect, respond Call Connected.
- Maintain periodic SSTP keepalive (control packets).
- Implement SSTP Data framing/deframing (RFC/behavior compatible with Windows SSTP clients).
- Provide `PumpToPPP` and `PumpFromPPP` with cancellation on either EOF/error.

## Systemd Service
Provide `sstpd.service`:

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



## README.md
Include:
- Build: `go build -o sstpd ./cmd/sstpd`
- Paths: PKI at `/etc/sstpd/pki`, PPP at `/etc/ppp`.
- How to create `/etc/ppp/chap-secrets` for test users.
- How to install `pppd` and dependencies: `sudo apt install -y ppp git golang build-essential`
- How to open firewall or confirm :443 is reachable.
- How to export and trust `CA` on clients:
  - Windows: import `/export/ca.crt` into **Trusted Root Certification Authorities**.
  - Linux: place in system trust store (varies by distro).
  - Android: install user cert (varies by OEM).
- Testing:
  1) Start service, confirm `ss -lntp | grep :443`.
  2) `curl -k https://SERVER_IP:8080/health` (if control API runs on :8080).
  3) Windows SSTP client: create VPN → server `SERVER_IP` → credentials from `chap-secrets`.
  4) Verify connectivity and `/sessions` output.
- **RADIUS later**: document precise changes in `/etc/ppp/options.sstp` only; the Go code remains unchanged.

## Optional Control API Port
- Serve `/health`, `/sessions`, `/export/ca.crt` on `:8080` (plain HTTP or HTTPS self-signed is fine; for simplicity use HTTP on LAN).

## Coding Style
- Idiomatic Go, comments for all exported functions and complex flows.
- Small, testable units; at least unit tests for SSTP frame encode/decode.

Deliver a complete repository with all files, ready to `go build` and run under systemd.

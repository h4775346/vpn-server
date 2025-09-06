#!/bin/bash

# Script to update, build, and restart the SSTP server service
# This script should be run on the Linux server where the SSTP service is deployed

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (sudo)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log "Working in directory: $SCRIPT_DIR"

# Change to the script directory
cd "$SCRIPT_DIR" || {
    error "Failed to change to script directory"
    exit 1
}

# Pull latest changes
log "Pulling latest changes from git..."
if git pull; then
    log "Git pull successful"
else
    error "Git pull failed"
    exit 1
fi

# Stop the service before building and replacing binary
log "Stopping sstpd service..."
if systemctl stop sstpd; then
    log "Service stopped successfully"
else
    warn "Failed to stop service (might not be running)"
fi

# Build the binary
log "Building the SSTP server binary..."
if go build -o sstpd ./cmd/sstpd; then
    log "Build successful"
else
    error "Build failed"
    # Try to restart the service since build failed
    systemctl start sstpd
    exit 1
fi

# Copy binary to system location
log "Copying binary to /usr/local/bin/sstpd..."
if cp sstpd /usr/local/bin/sstpd; then
    log "Binary copied successfully"
else
    error "Failed to copy binary"
    # Try to restart the service since copy failed
    systemctl start sstpd
    exit 1
fi

# Restart the service
log "Starting sstpd service..."
if systemctl start sstpd; then
    log "Service started successfully"
else
    error "Failed to start service"
    exit 1
fi

# Check service status
log "Checking service status..."
if systemctl is-active --quiet sstpd; then
    log "Service is running"
else
    warn "Service may not be running properly. Check with 'systemctl status sstpd'"
fi

log "Deployment completed successfully!"
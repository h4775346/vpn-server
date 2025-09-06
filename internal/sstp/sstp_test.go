package sstp

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

// TestHandleInvalidContentLength tests that requests with invalid Content-Length are rejected
func TestHandleInvalidContentLength(t *testing.T) {
	// Create a mock HTTP request with invalid Content-Length
	request := `SSTP_DUPLEX_POST / HTTP/1.1
Host: localhost
Content-Type: application/sstp
Content-Length: 18446744073709551615

`

	// Parse the request
	reader := bufio.NewReader(strings.NewReader(request))
	_, err := http.ReadRequest(reader)
	// The Go HTTP parser should reject this invalid Content-Length
	if err == nil {
		t.Fatalf("Expected error when parsing request with invalid Content-Length, but got none")
	}
	
	// Check that the error is related to Content-Length
	if !strings.Contains(err.Error(), "bad Content-Length") {
		t.Errorf("Expected error to contain 'bad Content-Length', got: %v", err)
	}
}
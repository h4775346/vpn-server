package sstp

import (
	"encoding/binary"
	"fmt"
)

// SSTP frame constants
const (
	SSTP_VERSION       = 0x10 // SSTP version 1.0
	SSTP_FLAG_CONTROL  = 0x01
	SSTP_FLAG_DATA     = 0x00
	SSTP_FLAG_COMPOUND = 0x02
	SSTP_FLAG_CRC      = 0x04

	// Message types
	SSTP_MSG_CALL_CONNECT_REQUEST = 0x0001
	SSTP_MSG_CALL_CONNECT_ACK     = 0x0002
	SSTP_MSG_CALL_CONNECT_NAK     = 0x0003
	SSTP_MSG_CALL_CONNECTED       = 0x0004
	SSTP_MSG_CALL_ABORT           = 0x0005
	SSTP_MSG_CALL_DISCONNECT      = 0x0006
	SSTP_MSG_CALL_DISCONNECT_ACK  = 0x0007
	SSTP_MSG_ECHO_REQUEST         = 0x0008
	SSTP_MSG_ECHO_RESPONSE        = 0x0009
)

// SSTPFrame represents an SSTP frame
type SSTPFrame struct {
	Version     uint8
	Flags       uint8
	MessageType uint16
	Length      uint16
	Data        []byte
}

// Encode encodes an SSTP frame into bytes
func (f *SSTPFrame) Encode() ([]byte, error) {
	// Calculate total length
	totalLength := 8 + len(f.Data) // 8 bytes for header + data length

	// Create buffer
	buf := make([]byte, totalLength)

	// Set version and flags
	buf[0] = f.Version
	buf[1] = f.Flags

	// Set message type (big endian)
	binary.BigEndian.PutUint16(buf[2:4], f.MessageType)

	// Set length (big endian)
	binary.BigEndian.PutUint16(buf[4:6], uint16(totalLength))

	// Copy data
	copy(buf[8:], f.Data)

	return buf, nil
}

// Decode decodes bytes into an SSTP frame
func (f *SSTPFrame) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("insufficient data to decode SSTP frame header")
	}

	// Parse header
	f.Version = data[0]
	f.Flags = data[1]
	f.MessageType = binary.BigEndian.Uint16(data[2:4])
	f.Length = binary.BigEndian.Uint16(data[4:6])

	// Validate length
	if int(f.Length) > len(data) {
		return fmt.Errorf("frame length %d exceeds available data %d", f.Length, len(data))
	}

	// Extract data
	if f.Length > 8 {
		f.Data = make([]byte, f.Length-8)
		copy(f.Data, data[8:f.Length])
	}

	return nil
}

// IsControl returns true if the frame is a control frame
func (f *SSTPFrame) IsControl() bool {
	return f.Flags&SSTP_FLAG_CONTROL != 0
}

// IsData returns true if the frame is a data frame
func (f *SSTPFrame) IsData() bool {
	return !f.IsControl()
}

// CreateControlFrame creates a control frame
func CreateControlFrame(messageType uint16, data []byte) *SSTPFrame {
	return &SSTPFrame{
		Version:     SSTP_VERSION,
		Flags:       SSTP_FLAG_CONTROL,
		MessageType: messageType,
		Data:        data,
	}
}

// CreateDataFrame creates a data frame
func CreateDataFrame(data []byte) *SSTPFrame {
	return &SSTPFrame{
		Version:     SSTP_VERSION,
		Flags:       SSTP_FLAG_DATA,
		MessageType: 0,
		Data:        data,
	}
}

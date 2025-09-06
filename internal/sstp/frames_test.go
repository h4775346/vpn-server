package sstp

import (
	"reflect"
	"testing"
)

func TestSSTPFrameEncodeDecode(t *testing.T) {
	// Test control frame encoding/decoding
	controlData := []byte("test control data")
	originalFrame := &SSTPFrame{
		Version:     SSTP_VERSION,
		Flags:       SSTP_FLAG_CONTROL,
		MessageType: SSTP_MSG_CALL_CONNECT_REQUEST,
		Data:        controlData,
	}

	// Encode the frame
	encoded, err := originalFrame.Encode()
	if err != nil {
		t.Fatalf("Failed to encode frame: %v", err)
	}

	// Decode the frame
	decodedFrame := &SSTPFrame{}
	err = decodedFrame.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode frame: %v", err)
	}

	// Verify the decoded frame matches the original
	if decodedFrame.Version != originalFrame.Version {
		t.Errorf("Version mismatch: expected %d, got %d", originalFrame.Version, decodedFrame.Version)
	}

	if decodedFrame.Flags != originalFrame.Flags {
		t.Errorf("Flags mismatch: expected %d, got %d", originalFrame.Flags, decodedFrame.Flags)
	}

	if decodedFrame.MessageType != originalFrame.MessageType {
		t.Errorf("MessageType mismatch: expected %d, got %d", originalFrame.MessageType, decodedFrame.MessageType)
	}

	if !reflect.DeepEqual(decodedFrame.Data, originalFrame.Data) {
		t.Errorf("Data mismatch: expected %v, got %v", originalFrame.Data, decodedFrame.Data)
	}

	// Test data frame encoding/decoding
	dataPayload := []byte("test data payload")
	originalDataFrame := &SSTPFrame{
		Version:     SSTP_VERSION,
		Flags:       SSTP_FLAG_DATA,
		MessageType: 0,
		Data:        dataPayload,
	}

	// Encode the data frame
	encodedData, err := originalDataFrame.Encode()
	if err != nil {
		t.Fatalf("Failed to encode data frame: %v", err)
	}

	// Decode the data frame
	decodedDataFrame := &SSTPFrame{}
	err = decodedDataFrame.Decode(encodedData)
	if err != nil {
		t.Fatalf("Failed to decode data frame: %v", err)
	}

	// Verify the decoded data frame matches the original
	if decodedDataFrame.Version != originalDataFrame.Version {
		t.Errorf("Data frame Version mismatch: expected %d, got %d", originalDataFrame.Version, decodedDataFrame.Version)
	}

	if decodedDataFrame.Flags != originalDataFrame.Flags {
		t.Errorf("Data frame Flags mismatch: expected %d, got %d", originalDataFrame.Flags, decodedDataFrame.Flags)
	}

	if decodedDataFrame.MessageType != originalDataFrame.MessageType {
		t.Errorf("Data frame MessageType mismatch: expected %d, got %d", originalDataFrame.MessageType, decodedDataFrame.MessageType)
	}

	if !reflect.DeepEqual(decodedDataFrame.Data, originalDataFrame.Data) {
		t.Errorf("Data frame Data mismatch: expected %v, got %v", originalDataFrame.Data, decodedDataFrame.Data)
	}
}

func TestSSTPFrameIsControl(t *testing.T) {
	controlFrame := &SSTPFrame{Flags: SSTP_FLAG_CONTROL}
	if !controlFrame.IsControl() {
		t.Error("Expected control frame to return true for IsControl()")
	}

	dataFrame := &SSTPFrame{Flags: SSTP_FLAG_DATA}
	if dataFrame.IsControl() {
		t.Error("Expected data frame to return false for IsControl()")
	}
}

func TestSSTPFrameIsData(t *testing.T) {
	controlFrame := &SSTPFrame{Flags: SSTP_FLAG_CONTROL}
	if controlFrame.IsData() {
		t.Error("Expected control frame to return false for IsData()")
	}

	dataFrame := &SSTPFrame{Flags: SSTP_FLAG_DATA}
	if !dataFrame.IsData() {
		t.Error("Expected data frame to return true for IsData()")
	}
}

func TestCreateControlFrame(t *testing.T) {
	messageType := uint16(SSTP_MSG_CALL_CONNECT_REQUEST)
	data := []byte("test data")
	frame := CreateControlFrame(messageType, data)

	if frame.Version != SSTP_VERSION {
		t.Errorf("Expected version %d, got %d", SSTP_VERSION, frame.Version)
	}

	if frame.Flags != SSTP_FLAG_CONTROL {
		t.Errorf("Expected flags %d, got %d", SSTP_FLAG_CONTROL, frame.Flags)
	}

	if frame.MessageType != messageType {
		t.Errorf("Expected message type %d, got %d", messageType, frame.MessageType)
	}

	if !reflect.DeepEqual(frame.Data, data) {
		t.Errorf("Expected data %v, got %v", data, frame.Data)
	}
}

func TestCreateDataFrame(t *testing.T) {
	data := []byte("test data")
	frame := CreateDataFrame(data)

	if frame.Version != SSTP_VERSION {
		t.Errorf("Expected version %d, got %d", SSTP_VERSION, frame.Version)
	}

	if frame.Flags != SSTP_FLAG_DATA {
		t.Errorf("Expected flags %d, got %d", SSTP_FLAG_DATA, frame.Flags)
	}

	if frame.MessageType != 0 {
		t.Errorf("Expected message type 0, got %d", frame.MessageType)
	}

	if !reflect.DeepEqual(frame.Data, data) {
		t.Errorf("Expected data %v, got %v", data, frame.Data)
	}
}

func TestDecodeInsufficientData(t *testing.T) {
	frame := &SSTPFrame{}
	err := frame.Decode([]byte("short"))
	if err == nil {
		t.Error("Expected error when decoding insufficient data")
	}
}

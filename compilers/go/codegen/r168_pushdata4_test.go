package codegen

import (
	"bytes"
	"testing"
)

func TestDecodePushData_PUSHDATA4RoundTrip(t *testing.T) {
	payload := make([]byte, 65536)
	for i := range payload {
		payload[i] = byte(i)
	}
	enc := encodePushData(payload)
	if enc[0] != 0x4e {
		t.Fatalf("encodePushData(65536) opcode = 0x%02x, want 0x4e", enc[0])
	}
	got, next, err := decodePushData(enc, 0)
	if err != nil {
		t.Fatalf("decodePushData: %v", err)
	}
	if next != len(enc) {
		t.Fatalf("next = %d, want %d", next, len(enc))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch after OP_PUSHDATA4 round-trip")
	}
}

func TestDecodePushData_TruncatedPUSHDATA4(t *testing.T) {
	_, _, err := decodePushData([]byte{0x4e, 0x01, 0x00}, 0)
	if err == nil {
		t.Fatal("truncated 0x4e header must fail")
	}
}

package runar

import (
	"fmt"
	"testing"
)

// The state section is framed <len><data>, never MINIMALDATA.
//
// SCRIPT_VERIFY_MINIMALDATA applies to pushes the interpreter EXECUTES —
// unlocking scripts and spliced constructor args, which EncodePushData still
// handles. The state section is raw data after OP_RETURN in the locking
// script: never executed, never MINIMALDATA-checked, and read back by the
// compiler's on-chain state codec (emitPushDataEncode in 05-stack-lower.ts),
// which understands only <len><data>.
//
// #110 applied the MINIMALDATA short-circuit to the state serializer in all
// seven SDKs and none of the seven compilers. A 1-byte 0x05 state field then
// serialised off-chain as "55" while the script rebuilt it as "0105", so the
// continuation hash never matched (unspendable), and a contract DEPLOYED with
// such a value could not be spent at all (the on-chain reader takes 0x55 as a
// length-85 push).

func byteStringStateFields() []StateField {
	return []StateField{{Name: "b", Type: "ByteString", Index: 0}}
}

func encodeStateByteString(payload string) string {
	return SerializeState(byteStringStateFields(), map[string]interface{}{"b": payload})
}

func TestStateByteStringOpNRangeStaysDirectPush(t *testing.T) {
	for n := 1; n <= 16; n++ {
		payload := fmt.Sprintf("%02x", n)
		want := "01" + payload
		if got := encodeStateByteString(payload); got != want {
			t.Errorf("state 1-byte 0x%02x: got %q, want %q (must not collapse to OP_%d)", n, got, want, n)
		}
	}
}

func TestStateByteString0x81IsNotOp1Negate(t *testing.T) {
	if got := encodeStateByteString("81"); got != "0181" {
		t.Errorf("state 1-byte 0x81: got %q, want %q", got, "0181")
	}
}

func TestStateByteStringZeroIsDirectPush(t *testing.T) {
	if got := encodeStateByteString("00"); got != "0100" {
		t.Errorf("state 1-byte 0x00: got %q, want %q", got, "0100")
	}
}

func TestStateByteStringEmptyIsZeroLengthPush(t *testing.T) {
	if got := encodeStateByteString(""); got != "00" {
		t.Errorf("state empty ByteString: got %q, want %q", got, "00")
	}
}

func TestStateByteStringOutsideOpNRangeUnchanged(t *testing.T) {
	if got := encodeStateByteString("11"); got != "0111" {
		t.Errorf("state 1-byte 0x11: got %q, want %q", got, "0111")
	}
	if got := encodeStateByteString("0011"); got != "020011" {
		t.Errorf("state 2-byte 0x0011: got %q, want %q", got, "020011")
	}
}

func TestStateByteStringRoundTripsEverySingleByte(t *testing.T) {
	fields := byteStringStateFields()
	for b := 0; b <= 0xff; b++ {
		payload := fmt.Sprintf("%02x", b)
		encoded := encodeStateByteString(payload)
		decoded := mustDeserializeState(t, fields, encoded)
		got, _ := decoded["b"].(string)
		if got != payload {
			t.Errorf("state roundtrip 0x%02x: encoded=%q -> got %q, want %q", b, encoded, got, payload)
		}
	}
}

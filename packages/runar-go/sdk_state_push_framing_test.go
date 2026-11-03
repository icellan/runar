package runar

import (
	"fmt"
	"strings"
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

// N-044: the compiler's on-chain state reader and writer frame a ByteString
// with an UNSIGNED length — `<len>` below 76, `4c <len8>`, `4d <len16 LE>`,
// `4e <len32 LE>` — and the covenant only accepts a continuation whose state
// bytes equal the SDK's. These are hand-written expected headers at every
// boundary where a signed reading of the length used to differ (0x80, 0x81..,
// 0x8000, 0xffff) and where PUSHDATA4 starts. They pin the SDK side of the
// frame; packages/runar-testing/src/__tests__/n044-state-length-sign-spend
// runs the on-chain side against it on the real Spend engine.
func TestStateByteStringPushDataLengthBoundaries(t *testing.T) {
	cases := []struct {
		n      int
		header string
	}{
		{75, "4b"}, {76, "4c4c"}, {127, "4c7f"}, {128, "4c80"}, {129, "4c81"},
		{255, "4cff"}, {256, "4d0001"}, {32767, "4dff7f"}, {32768, "4d0080"},
		{65535, "4dffff"}, {65536, "4e00000100"},
	}
	fields := byteStringStateFields()
	for _, c := range cases {
		payload := strings.Repeat("ab", c.n)
		encoded := encodeStateByteString(payload)
		if encoded != c.header+payload {
			t.Errorf("len %d: header %q, want %q", c.n, encoded[:len(c.header)], c.header)
			continue
		}
		got, _ := mustDeserializeState(t, fields, encoded)["b"].(string)
		if got != payload {
			t.Errorf("len %d: round-trip returned %d bytes", c.n, len(got)/2)
		}
	}
}

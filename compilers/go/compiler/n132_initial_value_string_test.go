package compiler

import (
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// N-132 — a string `ANFProperty.initialValue` on the `--ir` trust boundary
// ---------------------------------------------------------------------------
//
// The string arm of `initialValue` carries two different things and the
// discriminator is the trailing `n`, exactly as it is for `load_const.value`:
//
//	"42n"       a decimal bigint -> the number 42
//	"deadbeef"  a hex ByteString -> the bytes 0xde 0xad 0xbe 0xef
//
// Go implemented only the second reading here. `decodeConstValue` applies
// `isDecimalBigIntLiteral` to every `load_const`, but `DecodeConstants` never
// walked `program.Properties` at all, so a `"…n"` initialValue reached
// `pushPropertyValue`'s string arm and died in hex decode:
//
//	stack lowering failed: invalid hex string: encoding/hex: invalid byte: U+006E 'n'
//
// That is not an edge case. The TypeScript reference compiler emits `"42n"`
// for EVERY bigint property initializer it writes, whatever the magnitude
// (measured with `--emit-ir`), and Rust / Zig / Java emit the same shape once
// the value passes int64. Go could not consume any of it.
//
// The probe below is a four-byte script — push the property, OP_EQUALVERIFY
// against the parameter — so the assertion is on the property's bytes and
// nothing else.

// n132IR builds the smallest IR that pushes one property's initialValue.
// `initialValue` is spliced in as raw JSON so the test can write a string, a
// number or a literal of any width without a Go type getting an opinion first.
func n132IR(initialValueJSON string) []byte {
	return []byte(fmt.Sprintf(`{
	  "contractName": "InitProbe",
	  "properties": [
	    {"name": "v", "type": "bigint", "readonly": true, "initialValue": %s}
	  ],
	  "methods": [
	    {"name": "constructor", "params": [], "isPublic": false,
	     "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
	    {"name": "check", "params": [{"name": "expected", "type": "bigint"}], "isPublic": true,
	     "body": [
	       {"name": "t0", "value": {"kind": "load_prop", "name": "v"}},
	       {"name": "t1", "value": {"kind": "load_param", "name": "expected"}},
	       {"name": "t2", "value": {"kind": "bin_op", "left": "t0", "op": "===", "right": "t1"}},
	       {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
	     ]}
	  ]
	}`, initialValueJSON))
}

func n132Hex(t *testing.T, initialValueJSON string) string {
	t.Helper()
	art, err := CompileFromIRBytes(n132IR(initialValueJSON))
	if err != nil {
		t.Fatalf("initialValue %s: unexpected error: %v", initialValueJSON, err)
	}
	return art.Script
}

// The `"<decimal>n"` form must lower to the SAME BYTES as the integer it
// spells. "it loaded" is the weaker claim and is satisfiable by a loader that
// read the string as something else entirely.
func TestN132_DecimalBigIntString_MeansTheInteger(t *testing.T) {
	cases := []struct{ str, integer string }{
		{`"42n"`, `42`},
		{`"-3n"`, `-3`},
		{`"0n"`, `0`},
	}
	for _, c := range cases {
		gotStr := n132Hex(t, c.str)
		gotInt := n132Hex(t, c.integer)
		if gotStr != gotInt {
			t.Errorf("initialValue %s produced %s, integer %s produced %s",
				c.str, gotStr, c.integer, gotInt)
		}
	}
}

// 0 is what every fallback path also produces, so the non-zero case above is
// what makes the claim mean something. Pin the literal bytes too.
func TestN132_DecimalBigIntString_ExactBytes(t *testing.T) {
	if got := n132Hex(t, `"42n"`); got != "012a7c9c" {
		t.Errorf(`initialValue "42n": got %s, want 012a7c9c (PUSH 0x2a)`, got)
	}
}

// An over-int64 value is exactly why the string form exists (issue #121): it
// cannot be written as a JSON number without a double-backed reader rounding
// it. secp256k1's group order, minimally encoded, is 33 bytes.
func TestN132_OversizeBigIntString_IsNotTruncated(t *testing.T) {
	const ecN = `"115792089237316195423570985008687907852837564279074904382605163141518161494337n"`
	const want = "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00"
	if got := n132Hex(t, ecN); !strings.Contains(got, want) {
		t.Errorf("oversize initialValue: got %s, want it to contain %s", got, want)
	}
}

// The other half of the discriminator, and the control an over-broad fix
// fails: a bare digit string is HEX. "1000" is 0x10 0x00, not one thousand.
func TestN132_BareDigitString_IsHexNotDecimal(t *testing.T) {
	asHex := n132Hex(t, `"1000"`)
	asDecimal := n132Hex(t, `1000`)
	if asHex != "0210007c9c" {
		t.Errorf(`initialValue "1000": got %s, want 0210007c9c (PUSH 0x10 0x00)`, asHex)
	}
	if asDecimal != "02e8037c9c" {
		t.Errorf("initialValue 1000: got %s, want 02e8037c9c (PUSH 1000)", asDecimal)
	}
	if asHex == asDecimal {
		t.Error(`"1000" and 1000 must not lower to the same bytes`)
	}
}

// The hex arm still works, unchanged.
func TestN132_HexByteString_StillDecodes(t *testing.T) {
	if got := n132Hex(t, `"deadbeef"`); got != "04deadbeef7c9c" {
		t.Errorf(`initialValue "deadbeef": got %s, want 04deadbeef7c9c`, got)
	}
	if got := n132Hex(t, `""`); got != "007c9c" {
		t.Errorf(`initialValue "": got %s, want 007c9c (empty push)`, got)
	}
}

// A string that is neither form is refused. Go already refused all of these —
// the rows are here so that adding the bigint arm cannot quietly widen into
// them, and so the falsification sweep has a Go-side target.
func TestN132_UnreadableString_IsRefused(t *testing.T) {
	for _, bad := range []string{`"zz"`, `"5"`, `"5nn"`, `"1.5n"`, `"n"`, `"-n"`} {
		if _, err := CompileFromIRBytes(n132IR(bad)); err == nil {
			t.Errorf("initialValue %s: expected an error, got none", bad)
		}
	}
}

package compiler

import (
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// N-212 — a bare JSON integer wider than float64's 53-bit mantissa on `--ir`
// ---------------------------------------------------------------------------
//
// Decision R82: every tier parses a bare JSON integer EXACTLY, whatever its
// width. Go, Python and Ruby `--emit-ir` themselves write an oversize property
// initializer as a bare number, so refusing it was not an option.
//
// Go already read `load_const.value` exactly (it keeps the raw token), but
// `ANFProperty.initialValue` is an `interface{}`, which `encoding/json` fills
// with a float64. Measured before the fix:
//
//	initialValue 9007199254740993 (2^53+1)  ->  pushes 2^53      (rounded)
//	initialValue secp256k1 order N          ->  pushes i64::MAX  (saturated)
//
// Both compile with exit 0 to a locking script that compares against a number
// the IR never contained.
//
// What this proves: Go's --ir path pushes the exact integer for a bare
// initialValue of any width, byte-identical to the `"…n"` string form and to
// the same bare literal through load_const. What it does not prove: anything
// about the other six tiers (conformance/negatives/ir-bare-big-integer.test.ts
// grades all seven), or about float-syntax initial values.

const n212Order = "115792089237316195423570985008687907852837564279074904382605163141518161494337"

// n212OrderPush is the minimally-encoded little-endian push of N: 0x21 length
// byte, 32 magnitude bytes, then 0x00 because N's top bit is set.
const n212OrderPush = "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00"

func n212LoadConstHex(t *testing.T, literal string) string {
	t.Helper()
	ir := fmt.Sprintf(`{
	  "contractName": "ConstProbe",
	  "properties": [],
	  "methods": [
	    {"name": "constructor", "params": [], "isPublic": false,
	     "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
	    {"name": "check", "params": [{"name": "expected", "type": "bigint"}], "isPublic": true,
	     "body": [
	       {"name": "t0", "value": {"kind": "load_const", "value": %s}},
	       {"name": "t1", "value": {"kind": "load_param", "name": "expected"}},
	       {"name": "t2", "value": {"kind": "bin_op", "left": "t0", "op": "===", "right": "t1"}},
	       {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
	     ]}
	  ]
	}`, literal)
	art, err := CompileFromIRBytes([]byte(ir))
	if err != nil {
		t.Fatalf("load_const %s: unexpected error: %v", literal, err)
	}
	return art.Script
}

func TestN212_BareBigInitialValue_IsExact(t *testing.T) {
	cases := []struct{ bare, push string }{
		{n212Order, n212OrderPush},
		{"9007199254740993", "0701000000000020"},        // 2^53+1
		{"-9007199254740993", "07010000000000a0"},       // -(2^53+1)
		{"9223372036854775808", "09000000000000008000"}, // 2^63
	}
	for _, c := range cases {
		got := n132Hex(t, c.bare)
		if !strings.HasPrefix(got, c.push) {
			t.Errorf("bare initialValue %s pushed %s, want prefix %s", c.bare, got, c.push)
		}
		if str := n132Hex(t, `"`+c.bare+`n"`); str != got {
			t.Errorf("bare initialValue %s: %s, string form: %s", c.bare, got, str)
		}
		if lc := n212LoadConstHex(t, c.bare); lc != got {
			t.Errorf("bare %s: initialValue %s, load_const %s", c.bare, got, lc)
		}
	}
}

// Control: an initialValue inside the safe range is unchanged.
func TestN212_SafeInitialValue_Unchanged(t *testing.T) {
	if got := n132Hex(t, "9007199254740991"); !strings.HasPrefix(got, "07ffffffffffff1f") {
		t.Errorf("2^53-1 initialValue pushed %s", got)
	}
}

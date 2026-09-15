package compiler

import (
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// N-133 — `loop.start` on the `--ir` trust boundary
// ---------------------------------------------------------------------------
//
// `Loop.start` is `integer | string`, and the string arm is the sanctioned
// `"<decimal>n"` form — the suffix is REQUIRED, which is what Java's loader
// implements and what the schema's other two string-carrying integer fields
// (`load_const.value`, `ANFProperty.initialValue`) mean by a string.
//
// Go's `decodeBigIntFromRaw` stripped the trailing `n` only IF one was there
// and then parsed the rest as decimal either way, so `"5"` read as 5 here —
// while Rust read the same input as 0. Two tiers, two different loops, both
// exit 0. The suffix is the only thing that makes the string arm
// unambiguous, so Go requires it.
//
// The probe is a two-iteration loop summing its iterator, so the start lands
// in the emitted bytes and nothing else does.

func n133IR(startJSON string) []byte {
	return []byte(fmt.Sprintf(`{
	  "contractName": "LoopProbe",
	  "properties": [{"name": "target", "type": "bigint", "readonly": true}],
	  "methods": [
	    {"name": "constructor", "params": [], "isPublic": false,
	     "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
	    {"name": "run", "params": [], "isPublic": true,
	     "body": [
	       {"name": "acc", "value": {"kind": "load_const", "value": 0}},
	       {"name": "t1", "value": {"kind": "loop", "count": 2, "iterVar": "i",
	         "start": %s, "step": 1,
	         "body": [{"name": "acc", "value": {"kind": "bin_op", "left": "acc", "op": "+", "right": "i"}}]}},
	       {"name": "t2", "value": {"kind": "load_prop", "name": "target"}},
	       {"name": "t3", "value": {"kind": "bin_op", "left": "acc", "op": "===", "right": "t2"}},
	       {"name": "t4", "value": {"kind": "assert", "value": "t3"}}
	     ]}
	  ]
	}`, startJSON))
}

func n133Hex(t *testing.T, startJSON string) string {
	t.Helper()
	art, err := CompileFromIRBytes(n133IR(startJSON))
	if err != nil {
		t.Fatalf("loop.start %s: unexpected error: %v", startJSON, err)
	}
	return art.Script
}

// The sanctioned form must lower to the SAME BYTES as the integer it spells.
// Both cases non-zero: 0 is what every fallback path also produces, and it is
// what the loop this probe is modelled on actually carries.
func TestN133_DecimalBigIntStringStart_MeansTheInteger(t *testing.T) {
	for _, c := range []struct{ str, integer, want string }{
		{`"5n"`, `5`, "5b009c"},
		{`"-3n"`, `-3`, "0185009c"},
	} {
		gotStr := n133Hex(t, c.str)
		gotInt := n133Hex(t, c.integer)
		if gotStr != gotInt {
			t.Errorf("start %s produced %s, integer %s produced %s",
				c.str, gotStr, c.integer, gotInt)
		}
		if gotStr != c.want {
			t.Errorf("start %s: got %s, want %s", c.str, gotStr, c.want)
		}
	}
}

// A start Go can represent but that is wider than any tier's native int64.
// Go carries `start` as a *big.Int, so it emits the value.
func TestN133_OverInt64Start_IsNotTruncated(t *testing.T) {
	const want = "0dffffff7fd4dbe98ca039593e19009c"
	if got := n133Hex(t, `"999999999999999999999999999999n"`); got != want {
		t.Errorf("over-int64 start: got %s, want %s", got, want)
	}
}

// Anything that is neither a JSON integer nor the `"<decimal>n"` form is
// refused. `"5"` is the row this change adds: it used to read as 5 here and
// as 0 in Rust.
func TestN133_UnreadableStart_IsRefused(t *testing.T) {
	for _, bad := range []string{`"5"`, `"abc"`, `""`, `"5nn"`, `"n"`, `"-n"`, `"1.5n"`, `true`, `null`} {
		if _, err := CompileFromIRBytes(n133IR(bad)); err == nil {
			t.Errorf("loop.start %s: expected an error, got none", bad)
		}
	}
}

// The start-0 script, so a future fallback has something to collide with:
// every refusal above must NOT be reachable as "exit 0 with these bytes".
func TestN133_ZeroStart_IsItsOwnScript(t *testing.T) {
	if got := n133Hex(t, `0`); got != "008b009c" {
		t.Errorf("start 0: got %s, want 008b009c", got)
	}
	if n133Hex(t, `0`) == n133Hex(t, `5`) {
		t.Error("probe is vacuous: start 0 and start 5 emit the same bytes")
	}
}

package runar

import "testing"

// A mutable `boolean` state field is ONE raw byte — 01 or 00.
//
// The compiler spells the type `boolean`. `bool` appears nowhere in any of the
// seven frontends, so an artifact's stateFields never carries it; the SDKs that
// matched on "bool" alone were matching a spelling no compiler emits, and every
// real boolean field fell through to their push-data default:
//
//	typescript  01           correct
//	ruby        01           correct
//	go          02 74727565  push-framed ASCII "true" — 3 bytes too long
//	java        02 74727565  same
//	python      00           right width, ALWAYS false
//	zig         00           same
//	rust        panic        as_bytes() on a Bool variant
//
// All five are fund-affecting. Go and Java deploy a state tail longer than the
// one the script's own reader rebuilds, so hash256(outputs) can never match and
// the first spend is impossible. Python and Zig deploy a well-formed tail that
// says false whatever the caller passed, so the first call that sets the flag
// builds a continuation the covenant rejects. Rust fails closed.
//
// booleanSpellingGolden is byte-identical across all seven SDKs; every tier
// carries the same literal and the same field list. The trailing bigint is
// load-bearing: a boolean of the wrong WIDTH shifts it, so the record catches a
// length error that a lone boolean field would hide.

func booleanSpellingFields() []StateField {
	return []StateField{
		{Name: "count", Type: "bigint", Index: 0},
		// The canonical spelling — the only one any compiler emits.
		{Name: "flag", Type: "boolean", Index: 1},
		// The alias. Several tiers accepted only this one; it must keep working.
		{Name: "alias", Type: "bool", Index: 2},
		{Name: "tail", Type: "bigint", Index: 3},
	}
}

// booleanSpellingGolden — the one wire record every tier must reproduce.
const booleanSpellingGolden = "0700000000000000" + // bigint 7, NUM2BIN 8
	"01" + //              boolean true  — 1 raw byte
	"00" + //              bool    false — 1 raw byte
	"0100000000000000" //  bigint 1, NUM2BIN 8

const booleanSpellingFlipped = "0700000000000000" + "00" + "01" + "0100000000000000"

func TestBooleanSpellingCrossSdkGoldenSerialize(t *testing.T) {
	if len(booleanSpellingGolden)/2 != 18 {
		t.Fatalf("golden is %d bytes, want 18", len(booleanSpellingGolden)/2)
	}
	got := SerializeState(booleanSpellingFields(), map[string]interface{}{
		"count": int64(7), "flag": true, "alias": false, "tail": int64(1),
	})
	if got != booleanSpellingGolden {
		t.Errorf("cross-SDK state record mismatch:\n got %s\nwant %s", got, booleanSpellingGolden)
	}
}

func TestBooleanSpellingOppositePolarity(t *testing.T) {
	got := SerializeState(booleanSpellingFields(), map[string]interface{}{
		"count": int64(7), "flag": false, "alias": true, "tail": int64(1),
	})
	if got != booleanSpellingFlipped {
		t.Errorf("flipped record mismatch:\n got %s\nwant %s", got, booleanSpellingFlipped)
	}
}

func TestBooleanSpellingCrossSdkGoldenDeserialize(t *testing.T) {
	back := mustDeserializeState(t, booleanSpellingFields(), booleanSpellingGolden)
	if n, _ := back["count"].(int64); n != 7 {
		t.Errorf("count: got %v, want 7", back["count"])
	}
	if b, _ := back["flag"].(bool); !b {
		t.Errorf("flag: got %v, want true", back["flag"])
	}
	if b, _ := back["alias"].(bool); b {
		t.Errorf("alias: got %v, want false", back["alias"])
	}
	if n, _ := back["tail"].(int64); n != 1 {
		t.Errorf("tail: got %v, want 1", back["tail"])
	}
}

func TestBooleanSpellingLoneFieldIsOneByte(t *testing.T) {
	fields := []StateField{{Name: "v", Type: "boolean", Index: 0}}
	for _, c := range []struct {
		in   bool
		want string
	}{{true, "01"}, {false, "00"}} {
		got := SerializeState(fields, map[string]interface{}{"v": c.in})
		if got != c.want {
			t.Errorf("boolean %v: got %q, want %q", c.in, got, c.want)
		}
		if back, _ := mustDeserializeState(t, fields, c.want)["v"].(bool); back != c.in {
			t.Errorf("boolean %v: decoded %v", c.in, back)
		}
	}
}

package runar

// F-238 — readScriptElement must refuse malformed provider-supplied scripts
// instead of silently truncating, mirroring the fix made to the TS reference
// (readScriptElement in packages/runar-sdk/src/script-utils.ts) and the
// Python port (_read_script_element in packages/runar-py).
//
// Before this fix a push whose declared length (a direct push opcode
// 0x01-0x4b, or an OP_PUSHDATA1/2/4 length prefix) ran past the remaining
// bytes silently clamped `end` to len(hexStr) and returned a SHORT dataHex
// instead of erroring — which ExtractConstructorArgs/MatchesArtifact then
// treat as a valid (wrong) element, corrupting every later slot's offset in
// the same walk.
//
// PROVES: ExtractConstructorArgs and MatchesArtifact return a non-nil error
// for every malformed vector in the brief's testable assertion, and still
// decode a valid push of every pushdata flavour unchanged.
// DOES NOT PROVE: fail-closed behaviour of any other script reader in this
// package.

import "testing"

var f238MalformedVectors = []string{
	"",           // no opcode byte at all
	"f",          // odd-length hex, can't even form an opcode byte
	"05aabb",     // direct push declares 5 bytes, only 2 remain
	"4c",         // OP_PUSHDATA1 with no length byte
	"4c05aa",     // OP_PUSHDATA1 declares 5 bytes, only 1 remains
	"4d0100",     // OP_PUSHDATA2 length prefix present, 0 of the 1 declared bytes remain
	"4e01000000", // OP_PUSHDATA4 length prefix present, 0 of the 1 declared bytes remain
}

func f238OneSlotArtifact() *RunarArtifact {
	return makeArtifact("00ac", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "x", Type: "bigint"}}},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	})
}

func TestExtractConstructorArgs_RefusesMalformedScript_F238(t *testing.T) {
	artifact := f238OneSlotArtifact()
	for _, hexStr := range f238MalformedVectors {
		t.Run(hexStr, func(t *testing.T) {
			_, err := ExtractConstructorArgs(artifact, hexStr)
			if err == nil {
				t.Fatalf("ExtractConstructorArgs(%q): want error, got nil", hexStr)
			}
		})
	}
}

func TestMatchesArtifact_RefusesMalformedScript_F238(t *testing.T) {
	artifact := f238OneSlotArtifact()
	for _, hexStr := range f238MalformedVectors {
		t.Run(hexStr, func(t *testing.T) {
			_, err := MatchesArtifact(artifact, hexStr)
			if err == nil {
				t.Fatalf("MatchesArtifact(%q): want error, got nil", hexStr)
			}
		})
	}
}

func TestReadScriptElement_ValidPushesUnchanged_F238(t *testing.T) {
	artifact := makeArtifact("00ac", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "x", Type: "ByteString"}}},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	})

	cases := []struct {
		name   string
		script string
		want   string
	}{
		{"direct push", "012a" + "ac", "2a"},
		{"OP_PUSHDATA1 exact length", "4c012a" + "ac", "2a"},
		{"OP_PUSHDATA2 exact length", "4d01002a" + "ac", "2a"},
		{"OP_PUSHDATA4 exact length", "4e010000002a" + "ac", "2a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args, err := ExtractConstructorArgs(artifact, c.script)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := args["x"]; got != c.want {
				t.Errorf("x = %v, want %v", got, c.want)
			}
		})
	}
}

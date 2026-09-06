package runar

import "testing"

// The issue #106 OR-CHECKSIG gate must recognise BOTH lowerings of `||`.
//
// It went blind once already: it tested for OP_BOOLOR, and NEW-014 stopped the
// compiler emitting that opcode, so the NULLFAIL warning silently never fired.
// These cases pin both forms and the multi-sig exclusion.
func TestIsLikelyOrChecksig(t *testing.T) {
	cases := []struct {
		name string
		asm  string
		want bool
	}{
		{"legacy OP_BOOLOR form", "OP_DUP OP_BOOLOR OP_CHECKSIG", true},
		{"NEW-014 branch form", "OP_IF OP_CHECKSIG OP_ELSE OP_CHECKSIG OP_ENDIF", true},
		{"multi-sig is excluded", "OP_IF OP_CHECKSIG OP_CHECKMULTISIG", false},
		{"branching without CHECKSIG", "OP_IF OP_DUP OP_ELSE OP_DROP OP_ENDIF", false},
		{"CHECKSIG without a choice", "OP_DUP OP_HASH160 OP_CHECKSIG", false},
		{"lowercase asm still matches", "op_if op_checksig op_endif", true},
		{"absent asm cannot claim", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isLikelyOrChecksig(&RunarArtifact{ASM: c.asm})
			if got != c.want {
				t.Fatalf("isLikelyOrChecksig(%q) = %v, want %v", c.asm, got, c.want)
			}
		})
	}
}

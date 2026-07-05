package codegen

import "testing"

// Localized op-count goldens for the must-ship crypto codegen families
// (SHA-256, BLAKE3, EC/secp256k1, NIST P-256/P-384, WOTS+, SLH-DSA).
//
// Go's crypto codegen is verified end-to-end and cross-tier by the
// conformance suite, so a Go-only emit regression cannot ship — it would
// diverge from the other six tiers' goldens. But that signal is whole-suite
// and cross-tier; these unit tests pin the raw (pre-peephole) emit size of
// each family's entry point so a Go-side regression fails *here*, naming the
// offending emitter, instead of only surfacing as an opaque conformance hex
// mismatch. Each Emit* function produces a deterministic constant template
// (no input dependence), so the counts are stable — update them only
// alongside a deliberate codegen change, exactly like the conformance goldens.
func TestCryptoEmitOpCountGoldens(t *testing.T) {
	cases := []struct {
		name string
		emit func(func(StackOp))
		want int
	}{
		{"Sha256Compress", EmitSha256Compress, 21292},
		{"Sha256Finalize", EmitSha256Finalize, 63941},
		{"Blake3Compress", EmitBlake3Compress, 10373},
		{"Blake3Hash", EmitBlake3Hash, 10387},
		{"EcAdd", EmitEcAdd, 8078},
		{"EcMul", EmitEcMul, 63828},
		{"EcMulGen", EmitEcMulGen, 63830},
		{"EcNegate", EmitEcNegate, 945},
		{"EcOnCurve", EmitEcOnCurve, 533},
		{"P256Add", EmitP256Add, 6505},
		{"P256Mul", EmitP256Mul, 73306},
		{"VerifyECDSA_P256", EmitVerifyECDSA_P256, 163589},
		{"P384Add", EmitP384Add, 11311},
		{"P384Mul", EmitP384Mul, 111424},
		{"VerifyWOTS", EmitVerifyWOTS, 5438},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := gatherOps(tc.emit)
			if len(ops) != tc.want {
				t.Fatalf("%s: emitted %d ops, want %d (deliberate codegen change? update the golden)", tc.name, len(ops), tc.want)
			}
			for i, o := range ops {
				if o.Op == "" {
					t.Fatalf("%s: op %d has an empty Op kind (malformed StackOp)", tc.name, i)
				}
			}
		})
	}
}

// SLH-DSA's entry point is parameterised by FIPS-205 parameter set; pin a
// fast (128f) and a small (192s) variant to cover both Winternitz layouts.
func TestSlhdsaEmitOpCountGoldens(t *testing.T) {
	cases := []struct {
		param string
		want  int
	}{
		// BUG-011: each verifySLHDSA_* prologue now emits an OP_SIZE exact-length
		// guard (5 additional ops per parameter set) before the existing FORS /
		// Merkle path expansion.
		{"SHA2_128f", 85766},
		{"SHA2_192s", 41904},
	}
	for _, tc := range cases {
		t.Run(tc.param, func(t *testing.T) {
			ops := gatherOps(func(e func(StackOp)) { EmitVerifySLHDSA(e, tc.param) })
			if len(ops) != tc.want {
				t.Fatalf("SLHDSA %s: emitted %d ops, want %d (deliberate codegen change? update the golden)", tc.param, len(ops), tc.want)
			}
		})
	}
}

package codegen

import "testing"

// countOpTree returns the total number of StackOps in ops, INCLUDING the
// bodies of "if" ops.
//
// A flat len(ops) cannot see inside a branch, so any emitter whose work sits in
// an if body — the scalar ladders emit 257 / 385 conditional additions, WOTS+
// and SLH-DSA are almost entirely conditional — reports a count that barely
// moves no matter what the branch contains. Adding +1.3 KB of script inside the
// ladder's last step left the P256Mul / P384Mul goldens byte-identical.
// Recursing is what makes the golden a gate.
func countOpTree(ops []StackOp) int {
	total := 0
	for _, op := range ops {
		total++
		if op.Op == "if" {
			total += countOpTree(op.Then)
			total += countOpTree(op.Else)
		}
	}
	return total
}

// Localized op-count goldens for the must-ship crypto codegen families
// (SHA-256, BLAKE3, EC/secp256k1, NIST P-256/P-384, WOTS+, SLH-DSA).
//
// Go's crypto codegen is verified end-to-end and cross-tier by the
// conformance suite, so a Go-only emit regression cannot ship — it would
// diverge from the other six tiers' goldens. But that signal is whole-suite
// and cross-tier; these unit tests pin the raw (pre-peephole) emit size of
// each family's entry point — as an op TREE, if bodies included (see
// countOpTree) — so a Go-side regression fails *here*, naming the
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
		{"EcAdd", ecNoOpts(EmitEcAdd), 8223},
		{"EcMul", ecNoOpts(EmitEcMul), 130515},
		{"EcMulGen", ecNoOpts(EmitEcMulGen), 130517},
		{"EcNegate", ecNoOpts(EmitEcNegate), 945},
		{"EcOnCurve", ecNoOpts(EmitEcOnCurve), 533},
		{"P256Add", ecNoOpts(EmitP256Add), 6663},
		{"P256Mul", ecNoOpts(EmitP256Mul), 140036},
		// +58 ops: SEC1 §4.1.4 / FIPS 186-5 input-validation gates on the
		// verifier's untrusted arguments — sig/pubkey length gate
		// (cEmitLengthGate), signature range gate 1<=r,s<=n-1
		// (cEmitSigRangeGate), and the pubkey prefix-byte check folded into
		// cDecompressPubKey's _dk_valid. P-384 carries the identical fix but
		// has no golden entry in this table.
		{"VerifyECDSA_P256", ecNoOpts(EmitVerifyECDSA_P256), 297331},
		{"P384Add", ecNoOpts(EmitP384Add), 11469},
		{"P384Mul", ecNoOpts(EmitP384Mul), 211178},
		{"VerifyWOTS", EmitVerifyWOTS, 15488},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := gatherOps(tc.emit)
			if got := countOpTree(ops); got != tc.want {
				t.Fatalf("%s: emitted %d ops, want %d (deliberate codegen change? update the golden)", tc.name, got, tc.want)
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
		// Counts reflect the SLH-DSA codegen miscompile fix (audit #2): emitSLHHmsg
		// dropped one reversing swap on the final multi-block MGF1 block (-1 op per
		// set with a >1-block digest), and emitSLHFors now sizes the FORS index
		// window to ceil((bitOffset+a)/8) instead of capping at 2 bytes, so a=14
		// sets (192s/256s) emit a 3-byte window on unlucky alignments. Must match
		// the TS peer goldens in slh-dsa-codegen.test.ts.
		//
		// #137 (FIPS-205 conformance) then added, per parameter set, exactly
		// 6 + d ops:
		//   +6 once, in Hmsg — the MGF1 seed must be prefixed with R || PK.seed
		//     (FIPS 205 §11.2.1), costing 2 extra copyToTop (2 ops each) + 2 OP_CAT.
		//   +1 per hypertree layer (d layers) — wots_pkFromSig must restore the key
		//     pair address after setTypeAndClear(WOTS_PK) (FIPS 205 Alg. 8 lines
		//     8-11), so a 1-op 4-zero-byte push becomes a 2-op push-depth + PICK.
		// 128f: d=22 -> 514147 + 6 + 22 = 514175.  192s: d=7 -> 256935 + 6 + 7 = 256948.
		{"SHA2_128f", 514175},
		{"SHA2_192s", 256948},
	}
	for _, tc := range cases {
		t.Run(tc.param, func(t *testing.T) {
			ops := gatherOps(func(e func(StackOp)) { EmitVerifySLHDSA(e, tc.param) })
			if got := countOpTree(ops); got != tc.want {
				t.Fatalf("SLHDSA %s: emitted %d ops, want %d (deliberate codegen change? update the golden)", tc.param, got, tc.want)
			}
		})
	}
}

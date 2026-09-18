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
		// CL-BUG-095 (Point-length validation) deltas below: a Point/pubkey
		// blob was never checked against its defined width, so surplus bytes
		// were silently dropped by decomposePoint / cDecomposePoint. ecAdd,
		// ecMul, ecMulGen, ecNegate, p256Add, p256Mul inherit an abort-form
		// length check (emitPointLenVerify) via decomposePoint; ecOnCurve /
		// p256OnCurve gain a clamp-form length gate (emitPointLengthGate)
		// plus a second BOOLAND; VerifyECDSA_P256 inherits the abort-form
		// check via cDecomposePoint inside cEmitVerifyECDSA's point additions.
		// CL-BUG-096 (affine-adder infinity-operand select, R-053): +50 ops for
		// emitAffineInfinitySelect, which replaces the old cleanup + notinf-only
		// mask tail of affineAdd / cAffineAdd. Same +50 on P256Add, P384Add, and
		// VerifyECDSA_P256 below (VerifyECDSA_P384 has no golden entry here).
		// R-117, the COORDINATE-CANONICITY gate. ecAdd 8279 -> 8297 (+18), ecMul
		// 130518 -> 131073 (+8), ecMulGen +8, ecNegate 948 -> 956 (+8). emitCoordCanonVerify
		// is 8 ops per gated point -- copy x (pick), push p, OP_LESSTHAN, copy y (pick),
		// push p, OP_LESSTHAN, OP_BOOLAND, OP_VERIFY -- and ecAdd gates TWO points, so
		// +18 there rather than +16. The extra two are pick DEPTH, not extra work: this
		// tracker emits OP_DUP / OP_OVER for depth 0 / 1 and `push <n>, OP_PICK` for
		// anything deeper, and in ecAdd's FIRST gate the stack is [px, py, qx, qy], so
		// both of that gate's picks reach depth 3 and cost two ops each. Its second gate
		// sees [px, py, qx, qy] with qx / qy at depth 1, so both are a one-op OP_OVER.
		// 10 + 8 = 18, and ecMul / ecNegate gate a single point off a two-deep stack for
		// a flat 8. ecOnCurve / ecModReduce /
		// ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY are all +0 under
		// R-117. (ecMakePoint DOES move under R-156, which gates its two bigint
		// ARGUMENTS rather than an existing Point's coordinates; this tier pins no
		// ecMakePoint op count, so no row here changes for it.) The
		// predicates must stay TOTAL (they clamp and flag, they do not abort), and the
		// byte accessors have no selector to fool -- each returns a value derived
		// injectively from the bytes, so a non-canonical coordinate yields a DIFFERENT
		// number rather than a colliding one.
		// R-117, the COORDINATE-CANONICITY gate. pNNNAdd +18, pNNNMul +8, pNNNMulGen +8,
		// pNNNNegate +8 -- the same shape as secp256k1's, because cEmitCoordCanonVerify
		// is the same 8 ops (two picks, two pushes of p, two OP_LESSTHANs, OP_BOOLAND,
		// OP_VERIFY) and the Add gates two points. pNNNOnCurve and
		// pNNNEncodeCompressed are +0: the predicate must stay TOTAL. verifyECDSA_*
		// is +0 TOO, and that is the load-bearing part -- cEmitMul takes a
		// verifyCanonical flag that is FALSE on the ECDSA path, because
		// decompressPubKey and cEmitSigRangeGate have already decided attacker-chosen
		// bytes must return false from a total boolean builtin rather than abort.
		{"EcAdd", EmitEcAdd, 8297},
		// R-157, the ecMul ON-CURVE-OR-INFINITY gate: ecMul 130526 -> 131073 (+547),
		// ecMulGen +547. The gate is the whole ecOnCurve body plus a copy/compare against
		// the all-zero blob and an OP_BOOLOR/OP_VERIFY, run once before the ladder. ecAdd
		// / ecNegate / ecOnCurve / ecMakePoint / ecPointX / ecPointY are all +0 — this
		// gate is on the SCALAR LADDER only, because it is the +3n construction inside
		// ecMul whose soundness needs ord(P) | n. affineAdd has no n-dependent trick and
		// is correct on whatever curve its operand lies on, so gating it would cost bytes
		// and break ecAdd(P, O), which R-053 requires.
		// ecMulGen pays the gate too even though its operand is the compiler-pushed
		// generator: it is emitted as `push G; swap; ecMul`, and exempting it would mean a
		// second ecMul spelling whose only difference is a check that can never fail.
		// R-157, the pNNNMul ON-CURVE-OR-INFINITY gate: p256Mul 140047 -> 140620 (+573),
		// p256MulGen +573, p384Mul 211189 -> 211986 (+797), p384MulGen +797. Same shape as
		// secp256k1's, with each curve's own on-curve body; the two curves differ only
		// because their on-curve bodies do. pNNNAdd / pNNNNegate / pNNNOnCurve /
		// pNNNEncodeCompressed are +0, and so is verifyECDSA_pNNN — the gate is at the
		// PUBLIC pNNNMul entry point, NOT inside cEmitMul, because verifyECDSA shares that
		// ladder and must return false rather than abort on attacker-chosen bytes.
		{"EcMul", EmitEcMul, 131073},
		{"EcMulGen", EmitEcMulGen, 131075},
		{"EcNegate", EmitEcNegate, 956},
		{"EcOnCurve", EmitEcOnCurve, 548},
		{"P256Add", EmitP256Add, 6737},
		{"P256Mul", EmitP256Mul, 140620},
		// +58 ops: SEC1 §4.1.4 / FIPS 186-5 input-validation gates on the
		// verifier's untrusted arguments — sig/pubkey length gate
		// (cEmitLengthGate), signature range gate 1<=r,s<=n-1
		// (cEmitSigRangeGate), and the pubkey prefix-byte check folded into
		// cDecompressPubKey's _dk_valid. P-384 carries the identical fix but
		// has no golden entry in this table.
		// +12 more from CL-BUG-095 (Point-length validation, see above).
		{"VerifyECDSA_P256", EmitVerifyECDSA_P256, 297393},
		{"P384Add", EmitP384Add, 11543},
		{"P384Mul", EmitP384Mul, 211986},
		// R-135: +3 ops for the exact-signature-length gate
		// (OP_SIZE, push 2144, OP_EQUALVERIFY). 15488 -> 15491.
		{"VerifyWOTS", EmitVerifyWOTS, 15491},
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

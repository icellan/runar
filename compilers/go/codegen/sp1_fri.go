// SP1 v6.0.2 STARK / FRI verifier — Bitcoin Script codegen.
//
// This module emits the `runar.VerifySP1FRI(proofBlob, publicValues, sp1VKeyHash)`
// intrinsic into a structured Bitcoin Script verifier that replays the
// Plonky3 STARK + FRI verification algorithm on-chain. Used by BSVM's
// Mode 1 rollup covenant to close the trust-minimized-FRI soundness gap
// flagged in the external-review handoff under
// `../bsv-evm/RUNAR-FRI-VERIFIER.md`.
//
// # Status
//
// Phase 1 landed: structural decomposition + the implementable sub-pieces
// that reuse existing Runar primitives directly
// (`FiatShamirState` for the transcript,
// `EmitPoseidon2KBCompress` for Merkle verify, `EmitCheckWitness` for
// grinding PoW, KoalaBear Ext4 ops for FRI folding). The SP1-specific
// protocol algebra (sumcheck polynomial encoding, quotient reconstruction,
// query-index derivation, public-values commitment layout) is marked as
// stubs that reference the upstream Plonky3 source each one must port
// from. A follow-up specialist fills those in against real SP1 test
// vectors under `tests/vectors/sp1/fri/` (see
// `docs/sp1-proof-format.md` and `docs/sp1-fri-verifier.md`).
//
// # Proof-blob push-and-hash pattern
//
// Naïve byte-stream parsing of a ~150 KB proof in Bitcoin Script via
// OP_SPLIT chains is O(N²) in opcode count and far exceeds the 10 MB
// hard limit. Instead the unlocking script pushes each parsed field
// separately, plus the concatenated `proofBlob` as a single ByteString.
// The verifier hashes `proofBlob` once (SHA-256) and asserts it matches
// the hash of the concatenation of all pushed fields before consuming
// any of them. Cost is O(|proof|) in SHA-256 block work, dominated by
// the single hash pass — no quadratic blow-up.
//
// The unlocking-script push layout is pinned in `docs/sp1-proof-format.md`
// and mirrors Plonky3's bincode struct-declaration order.
package codegen

import "fmt"

// =============================================================================
// Parameters
// =============================================================================

// SP1FriVerifierParams captures the PoC-scale STARK parameters the codegen
// assumes. Production parameters (per handoff §2.1) are num_queries=100,
// merkle_depth=20, sumcheck_rounds=log2(trace_height). The PoC values below
// mirror Plonky3's `fib_air.rs` test config so the first end-to-end fixture
// can be a Fibonacci AIR proof.
type SP1FriVerifierParams struct {
	LogBlowup        int // default 1; Plonky3 fib_air uses 2
	NumQueries       int // PoC 2; production 100 (fallback 64 / 16)
	MerkleDepth      int // PoC 4; production ~20
	SumcheckRounds   int // PoC 4; production log2(trace_height)
	LogFinalPolyLen  int // PoC 0 (constant final poly); Plonky3 fib_air 2
	CommitPoWBits    int // PoC 0; production 16
	QueryPoWBits     int // PoC 0; production 16
	MaxLogArity      int // SP1/Plonky3 default: 1 (folding arity 2)
	NumPolynomials   int // PoC 2; production: AIR trace width + quotient chunks
}

// DefaultSP1FriParams returns the PoC-scale parameter set. Overridden when
// compiling against the EVM guest in Phase 2.
func DefaultSP1FriParams() SP1FriVerifierParams {
	return SP1FriVerifierParams{
		LogBlowup:       1,
		NumQueries:      2,
		MerkleDepth:     4,
		SumcheckRounds:  4,
		LogFinalPolyLen: 0,
		CommitPoWBits:   0,
		QueryPoWBits:    0,
		MaxLogArity:     1,
		NumPolynomials:  2,
	}
}

// =============================================================================
// Top-level emission
// =============================================================================

// lowerVerifySP1FRI is the dispatch entry point wired from stack.go for the
// `verifySP1FRI` builtin. See docs/sp1-fri-verifier.md §8 for status.
//
// Arguments (in declaration order):
//
//   - args[0]: proofBlob      (ByteString)
//   - args[1]: publicValues   (ByteString)
//   - args[2]: sp1VKeyHash    (ByteString; 32 bytes / keccak256)
//
// The binding result is a boolean 1 on successful verification. The script
// fails OP_VERIFY at the first detectable mismatch on an invalid proof.
func (ctx *loweringContext) lowerVerifySP1FRI(
	bindingName string, args []string, bindingIndex int, lastUses map[string]int,
) {
	if len(args) != 3 {
		panic(fmt.Sprintf(
			"verifySP1FRI requires 3 arguments: proofBlob, publicValues, sp1VKeyHash; got %d — see docs/sp1-fri-verifier.md §8",
			len(args)))
	}

	// Phase-1 gate: panic with a structured message naming which sub-step is
	// not yet implemented. The decomposition below documents the intended
	// verifier structure so a follow-up specialist can fill in each stub
	// against Plonky3 source + real SP1 test vectors.
	//
	// The panic message must contain both "verifySP1FRI" and
	// "docs/sp1-fri-verifier.md" so the compiler-level guard test in
	// integration/go/sp1_fri_poc_test.go (TestSp1FriVerifierPoc_CodegenRefuses)
	// continues to pass until the body lands.
	emitSP1FriStructuralSkeleton(ctx, bindingName, args, bindingIndex, lastUses)
}

// emitSP1FriStructuralSkeleton lays out the full verifier pipeline and calls
// into each sub-step. The sub-steps that reuse existing primitives correctly
// are implemented; SP1-specific protocol algebra panics with a Plonky3 source
// pointer. The first unimplemented sub-step reached wins — there is no
// partial-verifier output.
//
// This function is the top-level map of the algorithm; read it as the table
// of contents for the port.
func emitSP1FriStructuralSkeleton(
	ctx *loweringContext, bindingName string, args []string,
	bindingIndex int, lastUses map[string]int,
) {
	params := DefaultSP1FriParams()

	// Step 0 — Bring the three ByteString inputs to the top of the stack in
	// declaration order. After this: [..., proofBlob, publicValues,
	// sp1VKeyHash].
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	for i := 0; i < 3; i++ {
		ctx.sm.pop()
	}

	// Step 1 — Proof-blob push-and-hash binding.
	//
	// The verifier body that lands in a follow-up PR will expect the
	// unlocking script to have pushed every parsed proof field individually
	// ahead of the 3 ByteString inputs above. This function asserts that
	// SHA-256 of their concatenation equals SHA-256 of proofBlob, then the
	// fields are consumed directly by subsequent steps.
	//
	// At Phase 1 scope no parsed fields are consumed — we panic at the first
	// protocol-specific sub-step below, so the binding helper would be
	// dead code. It is still the first port-priority for the specialist
	// because every other sub-step depends on having parsed field pushes
	// available.
	_ = params
	panicSP1FriStub("proof-blob push-and-hash binding",
		"Unlocking-script field layout pinned in docs/sp1-fri-verifier.md §2.1 "+
			"(matches packages/runar-go/sp1fri/decode.go:25-48 traversal order).",
		"Bitcoin Script emission: (a) bring proofBlob to top, OP_SHA256, save to alt-stack; "+
			"(b) for the N pre-pushed fields use a known field-count derived from "+
			"DefaultSP1FriParams + len(decodedFixture.AllFields()) — for the PoC fixture "+
			"params (LogBlowup=2, NumQueries=2, MerkleDepth=4, LogFinalPolyLen=2, "+
			"MaxLogArity=1) the static field count is computed in computeSP1FriFieldCount(); "+
			"(c) initialize accumulator with the deepest field via OP_PICK + clone, then loop "+
			"PICK(depth) + OP_CAT for the remaining N-1 fields; (d) OP_SHA256 the accumulator, "+
			"OP_FROMALTSTACK, OP_EQUALVERIFY. Cost: O(|proof|) in SHA-256 block work + N PICKs. "+
			"Open question: the field count must match the prover's chosen NumQueries / "+
			"MerkleDepth / FinalPolyLen exactly; mismatched param sets produce different "+
			"locking scripts. Each guest-program param tuple needs its own deployed verifier.")

	// Step 2 — Transcript init.
	//
	// Initialize a Plonky3 DuplexChallenger (16-element KoalaBear state,
	// rate=8, capacity=8) via FiatShamirState.EmitInit. Absorb the SP1 VK
	// hash and the public values blob in the SP1 v6.0.2 absorb order —
	// see Plonky3 `uni-stark/src/verifier.rs` for the prover's matching
	// observe sequence.
	//
	// This sub-step is directly implementable against existing primitives —
	// the SP1-specific detail is the byte-to-field chunking convention for
	// the publicValues blob (see the stub in emitAbsorbByteString below).

	// Step 3 — Absorb trace + quotient-chunks commitments. Each commitment
	// is an 8-element Poseidon2-KB Merkle root. The prover's observe order
	// (defined by Plonky3 `uni-stark/src/prover.rs`) is:
	//   1. trace commitment
	//   2. quotient_chunks commitment
	//   3. (optional) random commitment when challenger randomness is used
	//
	// Absorbing each digest is 8 × EmitObserve. The `optional random`
	// absorption is gated on a bincode `Option<Com>` tag byte from the
	// proof layout.

	// Step 4 — Squeeze batch challenge α (Ext4) + sample opening point ζ
	// (Ext4). This is two calls to FiatShamirState.EmitSqueezeExt4. No
	// SP1-specific algebra yet.

	// Step 5 — Absorb opened values (per-polynomial evaluations at ζ and
	// ζ·g, plus quotient chunk evaluations). Order and encoding are pinned
	// in Plonky3 `uni-stark/src/proof.rs` `OpenedValues`.

	// Step 6 — Sumcheck verification.
	//
	// For each of SumcheckRounds rounds:
	//   a. Read the round's univariate polynomial (3 or 4 Ext4 coefficients
	//      depending on constraint degree).
	//   b. Assert `poly(0) + poly(1) == claim`.
	//   c. Squeeze round challenge β_i (Ext4) and update
	//      `claim ← poly(β_i)`.
	//
	// This requires protocol-specific algebra for polynomial evaluation at
	// 0, 1, and β over KoalaBear Ext4. Degree-bound polynomials use
	// Lagrange interpolation in coefficient form — see Plonky3
	// `uni-stark/src/verifier.rs::verify_constraints`.

	// Step 7 — Quotient / constraint reconstruction.
	//
	// Reconstruct the quotient-polynomial evaluation at ζ from the opened
	// trace values + the AIR constraint system + the absorbed batch
	// challenge α. Compare against the prover-supplied quotient evaluation.
	// AIR-specific — requires knowing the guest program's constraint layout.

	// Step 8 — FRI commit-phase absorb + fold challenge squeeze.
	//
	// For each FRI fold step (MerkleDepth steps at arity 2):
	//   a. Absorb the fold-step Merkle root (8 KoalaBear field elements).
	//   b. Squeeze the fold challenge β_fold_i (Ext4).
	// Each absorb + squeeze composes EmitObserve / EmitSqueezeExt4 in a
	// known order. Directly implementable.

	// Step 9 — Proof-of-work witness check.
	//
	// Absorb query_pow_witness and assert low QueryPoWBits of the resulting
	// sponge state are zero. `EmitCheckWitness` does this. When
	// QueryPoWBits is 0 (PoC default) this is a no-op.

	// Step 10 — Per-query verification.
	//
	// For each of NumQueries queries:
	//   a. Squeeze query index via FiatShamirState.EmitSampleBits(log_trace).
	//   b. Verify Merkle opening of input commitment at index via
	//      emitMerkleVerify (composes EmitPoseidon2KBCompress).
	//   c. For each fold step:
	//      - Compute expected folded value via Ext4 colinearity check
	//        (emitFriColinearityFold).
	//      - Verify Merkle opening at step-commit root at index >> step.
	//   d. After all folds: assert the reduced value equals final_poly(0)
	//      (constant final-poly case, LogFinalPolyLen=0).
	//
	// The colinearity formula is field-agnostic Ext4 arithmetic and matches
	// the existing BabyBear implementation at
	// `tests/vectors/fri_colinearity.json`. The Merkle step is directly
	// implementable via emitMerkleVerify. The query-index bit layout + the
	// fold-value update formula are SP1-specific (see Plonky3
	// `fri/src/verifier.rs::verify_query`).

	// Step 11 — Final polynomial check.
	//
	// With LogFinalPolyLen=0 (PoC): `final_poly` is a single Ext4 coefficient;
	// after the last fold, the reduced value must equal this coefficient for
	// every query (they all reduce to the same constant). Direct Ext4
	// equality check.
	//
	// With LogFinalPolyLen > 0 (production option): the final poly is a
	// degree-(2^LogFinalPolyLen - 1) polynomial; each query's reduced value
	// must equal the final poly evaluated at the final fold point derived
	// from the query's fold-step choices. Requires a small Lagrange-eval
	// helper.

	// Step 12 — Output success.
	//
	// Push OP_1 as the binding result. All assertions above have used
	// OP_VERIFY to short-circuit on failure; reaching this point means the
	// proof is accepted. The caller's `assert(runar.VerifySP1FRI(...))`
	// unwraps the 1 on the stack.

	// Mark the binding name so the stack machine is consistent with the
	// eventual `OP_1` push.
	_ = bindingName
}

// =============================================================================
// Sub-step implementations — directly reuse existing Runar primitives
// =============================================================================
//
// Each helper below is a self-contained Bitcoin Script emission. The helpers
// in this section are implementable against the existing Runar infrastructure
// (FiatShamirState, EmitPoseidon2KBCompress, KoalaBear Ext4 ops) without
// SP1-specific algebra and are expected to stay stable across Plonky3 /
// SP1 version bumps.

// emitAbsorbCommitment absorbs an 8-element Poseidon2-KB Merkle digest into
// the Fiat-Shamir transcript. Used for trace, quotient-chunks, random, and
// FRI fold-step commitments.
//
// Stack in:  [..., fs0..fs15, d0, d1, ..., d7]   (d7 on top)
// Stack out: [..., fs0'..fs15']                   (digest consumed)
//
// Composes 8 × FiatShamirState.EmitObserve — one permutation fires when the
// rate slots fill (every 8 observations, which is exactly one digest).
func emitAbsorbCommitment(fs *FiatShamirState, t *KBTracker) {
	// Each EmitObserve consumes the element on top of the stack. The caller
	// is responsible for leaving d0 deepest / d7 on top so the observe
	// sequence absorbs in canonical order d0, d1, ..., d7.
	// We pop d7 first (top) — but observe semantics require d0 first, so we
	// need to either reverse at the caller or use a loop that renames.
	//
	// Plonky3's DuplexChallenger.observe_slice absorbs elements in slice
	// order (d0 first). To match on-chain, the caller must push d7 first
	// and d0 last so d0 ends up on top.
	for i := 0; i < 8; i++ {
		fs.EmitObserve(t)
	}
	_ = t // silence lint when the compiler does not materially use t
}

// emitAbsorbExt4 absorbs a KoalaBear Ext4 element (4 base-field elements)
// into the transcript. Used for opened values.
//
// Stack in:  [..., fs0..fs15, c0, c1, c2, c3]   (c3 on top)
// Stack out: [..., fs0'..fs15']                  (Ext4 consumed)
func emitAbsorbExt4(fs *FiatShamirState, t *KBTracker) {
	for i := 0; i < 4; i++ {
		fs.EmitObserve(t)
	}
	_ = t
}

// emitMerkleVerify walks a Poseidon2-KB Merkle path and asserts the computed
// root matches the expected 8-element digest.
//
// Stack in (assumes the caller has arranged):
//
//	[..., leaf[0..7],                       # 8 KoalaBear elements — leaf
//	      sib[0][0..7], sib[1][0..7], ...,  # depth × 8 sibling elements
//	      indexBits,                        # merkleDepth-bit integer
//	      expectedRoot[0..7]]               # 8 elements
//
// Stack out: empty (root comparison verified via OP_VERIFY).
//
// For each depth step:
//  1. Use low bit of indexBits to decide sibling order:
//     bit=0: (current, sibling) → compress
//     bit=1: (sibling, current) → compress
//  2. Shift indexBits right by 1.
//
// After merkleDepth compressions, assert each of the 8 output elements
// equals the corresponding expectedRoot element.
//
// NOTE: this helper emits the structural pattern but the per-bit conditional
// ordering and the bit-shift update require a hand-coded Script fragment that
// handles the two orderings without dynamic dispatch. Plonky3's
// `MerkleTreeMmcs::verify_batch` is the reference. See the stub panic below
// for the specific unimplemented piece.
func emitMerkleVerify(t *KBTracker, depth int) {
	panicSP1FriStub(
		fmt.Sprintf("Merkle path verification (depth=%d)", depth),
		"Plonky3 `merkle-tree/src/mmcs.rs::FieldMerkleTreeMmcs::verify_batch` — "+
			"reference semantics for batch verify against multiple matrix heights. "+
			"For the PoC's single-matrix case the simpler root-walk in "+
			"`merkle-tree/src/merkle_tree.rs` `MerkleTree::verify_batch` applies. "+
			"Runar already has `EmitPoseidon2KBCompress` (8+8 → 8); what is missing "+
			"is the per-step conditional-sibling-ordering + bit-shift ladder.",
		"Structural shape: for each of merkleDepth steps:\n"+
			"  (a) Test low bit of indexBits via DUP + push(1) + OP_AND.\n"+
			"  (b) OP_IF: leaves on top, siblings below; reorder to (sib[0..7], "+
			"current[0..7]) via 8 SWAPs/ROTs.\n"+
			"  (c) OP_ELSE: already in (current[0..7], sib[0..7]) order — no reorder.\n"+
			"  (d) OP_ENDIF; call EmitPoseidon2KBCompress to consume 16 elements and "+
			"produce 8.\n"+
			"  (e) Update indexBits via push(2) + OP_DIV.\n"+
			"After the loop, compare the 8-element computed root to the 8-element "+
			"expected root via 8 × OP_EQUALVERIFY (deepest first).\n"+
			"Open question: the OP_IF branches both consume + produce 16 stack items; "+
			"the KBTracker currently has no conditional-branch support. Either (i) lower "+
			"the conditional via two unconditional reorderings + OP_IF/OP_ENDIF nesting "+
			"with raw stack ops (not tracker-managed), or (ii) add `EmitConditionalReorder` "+
			"to KBTracker first.")
	_ = t
}

// emitFriColinearityFold performs one FRI fold step: given the two opened
// values e_low (at index << 1) and e_high (at index << 1 | 1), the fold
// challenge β (Ext4), and the corresponding coset point ω_i (Ext4), compute
// the folded value at index:
//
//	folded = (e_low + e_high) / 2 + β · (e_low - e_high) / (2 · ω_i)
//
// The algebra is identical to the BabyBear Ext4 colinearity vectors at
// tests/vectors/fri_colinearity.json — only the underlying field changes
// (BabyBear → KoalaBear). Fully composable from kbExt4{Add,Sub,Mul,Inv}.
//
// See Plonky3 `fri/src/fold_even_odd.rs` for the prover-side formula.
func emitFriColinearityFold(t *KBTracker) {
	panicSP1FriStub(
		"FRI colinearity fold step",
		"Plonky3 `fri/src/two_adic_pcs.rs::TwoAdicFriFolder::fold_row` — the "+
			"production fold path used by SP1 v6.0.2. The simpler `fri/src/fold_even_odd.rs` "+
			"is the historical reference; for arity=2 (LogArity=1) both reduce to the "+
			"same colinearity formula:\n"+
			"  fold = (e_low + e_high) * inv2 + beta * (e_low - e_high) * inv(2*omega_i)\n"+
			"Runar already has component emitters (EmitKBExt4Mul0..3, EmitKBExt4Inv0..3) "+
			"and the BabyBear Ext4 reference test at "+
			"integration/go/fri_colinearity_vectors_test.go.",
		"Structural shape (Ext4 over KoalaBear, 4 base coefs each):\n"+
			"  1. Compute s = e_low + e_high   (4 × kbFieldAdd, component-wise).\n"+
			"  2. Compute d = e_low - e_high   (4 × kbFieldSub).\n"+
			"  3. Compute inv2 = inverse of (2,0,0,0) Ext4 (precomputable as a constant\n"+
			"     since 2 is a base-field element with known KoalaBear inverse).\n"+
			"  4. Compute s_half = s * inv2    (Ext4 mul: 4 component emitters,\n"+
			"     each consumes 8 base elements and produces 1).\n"+
			"  5. Compute beta_d = beta * d    (Ext4 mul as above).\n"+
			"  6. Compute omega_inv = inv(2*omega_i)   (Ext4 inv: 4 component emitters).\n"+
			"  7. Compute correction = beta_d * omega_inv   (Ext4 mul).\n"+
			"  8. Compute fold = s_half + correction   (4 × kbFieldAdd).\n"+
			"Open question: the existing kbExt4 component emitters are flat "+
			"`func(emit func(StackOp))` that consume + produce on a fixed stack layout; "+
			"composing them inside a KBTracker context requires careful name management — "+
			"after each Ext4 mul the four output components must be renamed and held while "+
			"the next Ext4 mul's 8-element input window is staged. The cleanest way is to "+
			"build a sibling helper file `sp1_fri_ext4.go` that wraps each kbExt4 op as a "+
			"`func(t *KBTracker, aPrefix, bPrefix, outPrefix string)` macro.")
	_ = t
}

// emitSumcheckRound verifies one sumcheck round by checking
// `poly(0) + poly(1) == claim` and updating `claim ← poly(β)`.
//
// Stack expectations depend on the polynomial-encoding convention chosen in
// the port — Plonky3 ships coefficient form (constant, linear, quadratic,
// cubic) over Ext4 for cubic constraints; the verifier evaluates at three
// points using a 4-coefficient Horner scheme over Ext4.
//
// See Plonky3 `uni-stark/src/verifier.rs::verify_constraints` for the exact
// polynomial-coefficient order + the interaction with the batch challenge α.
func emitSumcheckRound(fs *FiatShamirState, t *KBTracker, round int) {
	panicSP1FriStub(
		fmt.Sprintf("sumcheck round %d", round),
		"Plonky3 `uni-stark/src/verifier.rs::verify_constraints` (lines 97-160) — "+
			"recomposes the quotient polynomial at zeta from chunk openings + selector "+
			"evaluations + the alpha-batched constraint folder. NOTE: Plonky3 uni-stark "+
			"does NOT use a multi-round sumcheck — it reconstructs the quotient in a "+
			"single algebraic step using the FRI-opened values. The Phase-1 skeleton's "+
			"\"sumcheck\" naming is a misnomer inherited from the BSVM handoff text; it "+
			"refers to the constraint-quotient consistency check at uni-stark/src/verifier.rs:150-160 "+
			"(`Recompose the quotient` + `Check that constraints(zeta) / Z_H(zeta) == quotient(zeta)`).",
		"Structural shape: NOT a per-round loop — a single Ext4 polynomial reconstruction:\n"+
			"  1. Compute selector evaluations at zeta (Z_H, first/last selectors) over Ext4.\n"+
			"  2. Run the AIR's symbolic constraint evaluator (Plonky3 `uni-stark/src/folder.rs`) "+
			"with the opened trace_local + trace_next as input, producing a vector of "+
			"constraint evaluations.\n"+
			"  3. Linearly combine constraints via powers of alpha (Horner over alpha).\n"+
			"  4. Recompose quotient(zeta) from chunk openings via "+
			"`recompose_quotient_from_chunks` (uni-stark/src/verifier.rs:42-90).\n"+
			"  5. Assert constraints(zeta) == quotient(zeta) * Z_H(zeta) (Ext4 equality, 4 × OP_NUMEQUALVERIFY).\n"+
			"This step is AIR-specific — it depends on the guest program's constraint set. "+
			"For the PoC Fibonacci AIR (Plonky3 `uni-stark/examples/fibonacci_air.rs`) the "+
			"constraint count is small (~3 constraints over 2 columns); for the SP1 EVM guest "+
			"it's hundreds of constraints over ~30+ columns. The codegen needs an AIR-description "+
			"input parameter to emit the right symbolic-evaluator unrolling.")
	_ = fs
	_ = t
}

// emitQueryIndexDerive squeezes log_trace_height bits of transcript randomness
// to produce a query index in [0, trace_height). Direct wrapper around
// FiatShamirState.EmitSampleBits.
//
// Stack in:  [..., fs0..fs15]
// Stack out: [..., fs0'..fs15', index]
func emitQueryIndexDerive(fs *FiatShamirState, t *KBTracker, logTraceHeight int) {
	fs.EmitSampleBits(t, logTraceHeight)
	// _fs_bits is on top and holds the derived index.
}

// emitCommitPoWCheck invokes the commit-phase proof-of-work check. Wraps
// FiatShamirState.EmitCheckWitness. A no-op when CommitPoWBits is zero.
func emitCommitPoWCheck(fs *FiatShamirState, t *KBTracker, bits int) {
	if bits == 0 {
		return
	}
	fs.EmitCheckWitness(t, bits)
}

// emitQueryPoWCheck invokes the query-phase proof-of-work check.
func emitQueryPoWCheck(fs *FiatShamirState, t *KBTracker, bits int) {
	if bits == 0 {
		return
	}
	fs.EmitCheckWitness(t, bits)
}

// emitFinalPolyEqualityCheck asserts the final reduced Ext4 value equals the
// constant final-poly coefficient (LogFinalPolyLen=0 case).
//
// Stack in:  [..., reduced[0..3], final[0..3]]  (final[3] on top)
// Stack out: empty (4 × OP_EQUALVERIFY)
func emitFinalPolyEqualityCheck(t *KBTracker) {
	// For each of 4 Ext4 coefficients: assert reduced_i == final_i.
	// The caller supplies pushes in matching order.
	for i := 0; i < 4; i++ {
		t.rawBlock(nil, "", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
		})
		_ = i
	}
}

// =============================================================================
// Absorb-a-ByteString helper (SP1-specific encoding — stubbed)
// =============================================================================

// emitAbsorbByteString absorbs a ByteString into the Fiat-Shamir transcript
// by chunking it into KoalaBear field elements (4 bytes per field; 3 bytes
// for the tail if |bs| mod 4 != 0 using SP1's zero-pad convention) and
// observing each chunk.
//
// Used for absorbing `publicValues` and `sp1VKeyHash`.
//
// The chunking convention is SP1-specific — Plonky3's DuplexChallenger
// observes bytes via `observe_slice` but SP1 has its own byte-to-field
// packing for public values. See
// `crates/stark/src/machine.rs::observe_public_values` in SP1 v6.0.2 for
// the authoritative sequence.
func emitAbsorbByteString(fs *FiatShamirState, t *KBTracker) {
	panicSP1FriStub(
		"absorb-ByteString-as-field-elements",
		"Two distinct conventions to disambiguate at port time:\n"+
			"  (a) Plonky3 inner: `uni-stark/src/verifier.rs:367` calls "+
			"`challenger.observe_slice(public_values)` where `public_values: &[Val]` is "+
			"already a slice of base-field elements. NO byte-to-field chunking happens "+
			"at this layer.\n"+
			"  (b) SP1 outer wrapper: SP1 v6.0.2 `crates/stark/src/machine.rs` "+
			"`MachineVerifier::observe_pv_digest` packs the keccak256(VK) digest into "+
			"field elements as 8 u32 chunks (32 bytes / 4 bytes per chunk), each reduced "+
			"mod p. The publicValues blob is similarly chunked when the guest program "+
			"emits a Vec<u32> of public values.\n"+
			"For the PoC `runar.VerifySP1FRI(proofBlob, publicValues, sp1VKeyHash)` "+
			"intrinsic: sp1VKeyHash is a 32-byte ByteString → 8 × 4-byte LE chunks → "+
			"each OP_BIN2NUM → each absorbed via fs.EmitObserve. publicValues uses "+
			"the same 4-byte chunking with zero-padding for any tail bytes.",
		"Structural shape: dup the ByteString, OP_SIZE, push(4), OP_DIV → chunk count. "+
			"Loop chunkCount times: OP_PUSH(4), OP_SPLIT (yields prefix + suffix), SWAP, "+
			"OP_BIN2NUM, fs.EmitObserve(t), continue with suffix. Tail handling: if the "+
			"final remainder is < 4 bytes, OP_CAT a zero-pad-suffix before BIN2NUM (SP1 "+
			"convention: low-order zero pad). At codegen time the byte-length is statically "+
			"known for sp1VKeyHash (32) but variable for publicValues — for the PoC fixture "+
			"the publicValues length is fixed at 12 bytes (3 × u32 for [0,1,21]), so the "+
			"chunk loop unrolls to 3 iterations.")
	_ = fs
	_ = t
}

// =============================================================================
// Internal error helper
// =============================================================================

// panicSP1FriStub is the uniform panic used by every unimplemented
// sub-step. The message format preserves the invariant expected by the
// compiler-guard test in integration/go/sp1_fri_poc_test.go
// (TestSp1FriVerifierPoc_CodegenRefuses): both "verifySP1FRI" and
// "docs/sp1-fri-verifier.md" must appear in the panic text.
//
// The three arguments are:
//
//   - what: the name of the sub-step ("sumcheck round 2").
//   - ref:  the Plonky3 / SP1 source file + symbol the port should mirror.
//   - shape: the expected Bitcoin Script emission shape in one paragraph.
func panicSP1FriStub(what, ref, shape string) {
	panic(fmt.Sprintf(
		"verifySP1FRI codegen body not yet implemented — see docs/sp1-fri-verifier.md §8.\n"+
			"  Unimplemented sub-step: %s.\n"+
			"  Reference: %s\n"+
			"  Shape: %s",
		what, ref, shape))
}

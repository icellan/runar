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
	LogBlowup            int // default 1; Plonky3 fib_air uses 2
	NumQueries           int // PoC 2; production 100 (fallback 64 / 16)
	MerkleDepth          int // PoC 4; production ~20
	SumcheckRounds       int // PoC 4; production log2(trace_height)
	LogFinalPolyLen      int // PoC 0 (constant final poly); Plonky3 fib_air 2
	CommitPoWBits        int // PoC 0; production 16
	QueryPoWBits         int // PoC 0; production 16
	MaxLogArity          int // SP1/Plonky3 default: 1 (folding arity 2)
	NumPolynomials       int // PoC 2; production: AIR trace width + quotient chunks
	PublicValuesByteSize int // bytes; PoC 12 (= 3 × u32 LE for [a, b, fib_n]); SP1 EVM guest 32
	SP1VKeyHashByteSize  int // bytes; 0 disables the outer-wrapper absorb (validated PoC reference); SP1 prod 32

	// DegreeBits is the trace-domain log2-size. For the PoC Fibonacci AIR with
	// 8-row trace this is 3. Observed verbatim into the transcript at the start
	// of verify (sp1fri/verify.go:68-70).
	DegreeBits int
	// BaseDegreeBits is `degreeBits - is_zk` = `degreeBits` for non-ZK configs.
	// Observed at verify.go:69.
	BaseDegreeBits int
	// PreprocessedWidth is 0 when there is no preprocessed trace (Fib AIR);
	// observed at verify.go:70.
	PreprocessedWidth int
}

// DefaultSP1FriParams returns the PoC-scale parameter set. Overridden when
// compiling against the EVM guest in Phase 2. Defaults match the validated
// `packages/runar-go/sp1fri` minimal-guest fixture (no SP1 outer wrapper).
func DefaultSP1FriParams() SP1FriVerifierParams {
	return SP1FriVerifierParams{
		LogBlowup:            2, // matches sp1fri minimalGuestConfig.logBlowup
		NumQueries:           2,
		MerkleDepth:          4,
		SumcheckRounds:       4,
		LogFinalPolyLen:      2, // matches sp1fri minimalGuestConfig.logFinalPolyLen
		CommitPoWBits:        1, // matches sp1fri minimalGuestConfig.commitPowBits
		QueryPoWBits:         1, // matches sp1fri minimalGuestConfig.queryPowBits
		MaxLogArity:          1,
		NumPolynomials:       2,
		PublicValuesByteSize: 12, // [0,1,21] u32-LE-packed = 12 bytes
		SP1VKeyHashByteSize:  0,  // PoC fixture has no SP1 wrapper
		DegreeBits:           3,  // matches sp1fri minimalGuestConfig.degreeBits
		BaseDegreeBits:       3,  // = degreeBits - is_zk (= 0)
		PreprocessedWidth:    0,  // no preprocessed trace
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
	// Step 1 emit helper now exists: see EmitProofBlobBindingHash below. It is
	// validated end-to-end against the canonical fixture by
	// `TestSp1FriVerifier_Step1_ProofBlobBinding_*` in sp1_fri_test.go. The
	// remaining wiring work to land it inside this dispatch:
	//   (a) bring publicValues + sp1VKeyHash to the alt-stack so they don't
	//       interleave with the field pushes;
	//   (b) compute the field count statically from the parameter set
	//       (DefaultSP1FriParams + the fixture's degree_bits / num_queries /
	//       commit_phase_commits.len / final_poly.len — see
	//       packages/runar-go/sp1fri/decode.go:25-48 for the traversal);
	//   (c) call EmitProofBlobBindingHash(emit, fieldCount).
	// We leave the stub in place because the wiring is interlocked with the
	// rest of the verifier: the field-count must match exactly what subsequent
	// sub-steps consume, and steps 2-12 below are still stubs. See
	// docs/sp1-fri-verifier.md §8 for the rollout plan.
	panicSP1FriStub("proof-blob push-and-hash binding wiring",
		"Helper EmitProofBlobBindingHash(emit, numFields) lands in this same file; "+
			"the unlocking-script field layout it consumes is pinned in "+
			"docs/sp1-fri-verifier.md §2.1 (= packages/runar-go/sp1fri/decode.go:25-48 "+
			"traversal order). Test coverage in sp1_fri_test.go validates the helper "+
			"against the real fixture.",
		"Wiring needed: (a) park publicValues + sp1VKeyHash on the alt-stack via "+
			"OP_TOALTSTACK so the field pushes are contiguous below proofBlob; "+
			"(b) compute fieldCount from the pinned PoC params using the "+
			"sp1fri Proof shape (Trace.cap=1, QuotientChunks.cap=1, OpenedValues "+
			"shape from sp1fri/verify.go:48-62, FRI shape from sp1fri/fri.go:25-95) — "+
			"this is mechanical but tedious; (c) call EmitProofBlobBindingHash; "+
			"(d) OP_FROMALTSTACK twice to recover the two ByteString args. Each "+
			"guest-program param tuple needs its own deployed verifier (different "+
			"NumQueries / MerkleDepth / FinalPolyLen → different field count → "+
			"different locking script).")

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

// EmitProofBlobBindingHash emits the Step 1 proof-blob push-and-hash binding.
//
// Stack in (top → bottom):
//
//	proofBlob, fieldN-1, fieldN-2, ..., field1, field0
//	(i.e. fields are deepest, with proofBlob on top — caller has already
//	moved publicValues / sp1VKeyHash out of the way to the alt-stack).
//
// `numFields` is the number of pre-pushed field ByteString items, in the
// declaration order of `docs/sp1-fri-verifier.md` §2.1 (mirroring the Go
// reference decoder's traversal, `packages/runar-go/sp1fri/decode.go:25-48`).
// At entry, field0 sits at depth `numFields` (just below the now-removed
// proofBlob), with subsequent fields shallower.
//
// The emission sequence:
//
//  1. POP `proofBlob`, OP_SHA256, OP_TOALTSTACK — saves the canonical digest.
//  2. PICK field0 (now at depth numFields-1) — start the accumulator.
//  3. For i in 1..numFields-1: PICK field_i (depth numFields-1 always, because
//     the accumulator stays on top), OP_CAT into the accumulator.
//  4. OP_SHA256, OP_FROMALTSTACK, OP_EQUALVERIFY.
//
// Stack out: the original `numFields` field pushes, untouched. The proofBlob
// has been consumed, but every field remains on the main stack in the same
// declaration order ready to be drained by subsequent verifier steps.
//
// Cost: 1 SHA-256 over |proofBlob|, plus N PICKs + (N-1) CATs + 1 SHA-256
// over the concatenated buffer. This is O(|proof|) in SHA-256 block work
// and O(N) in opcode count — far below the O(N^2) cost of OP_SPLIT chain
// parsing. See docs/sp1-fri-verifier.md §2 for the rationale.
//
// References:
//   - docs/sp1-fri-verifier.md §2 + §2.1.
//   - packages/runar-go/sp1fri/decode.go:25-48 (canonical traversal order).
func EmitProofBlobBindingHash(emit func(StackOp), numFields int) {
	if numFields < 1 {
		panic(fmt.Sprintf("EmitProofBlobBindingHash: numFields must be >= 1, got %d", numFields))
	}

	// Step 1a: hash proofBlob (currently on top), park digest on alt-stack.
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})

	// Step 1b: pick field0 to seed the accumulator. After the proofBlob pop,
	// field0 is at the bottom; field_{numFields-1} is at depth 0 (top). So
	// field0 is at depth numFields-1.
	field0Depth := numFields - 1
	emit(StackOp{Op: "push", Value: bigIntPush(int64(field0Depth))})
	emit(StackOp{Op: "pick", Depth: field0Depth})

	// Step 1c: walk forward through the fields, picking each and CAT-ing into
	// the accumulator. With the accumulator sitting one slot above the
	// original fields, the depth of field_i is (numFields-1-i) + 1 = numFields-i.
	// OP_CAT pops the top two and pushes `deeper||shallower`; since we PICK
	// field_i to the top after the accumulator, the result is acc || field_i,
	// preserving canonical declaration order in the digest.
	for i := 1; i < numFields; i++ {
		depth := numFields - i
		emit(StackOp{Op: "push", Value: bigIntPush(int64(depth))})
		emit(StackOp{Op: "pick", Depth: depth})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	}

	// Step 1d: hash the accumulator and assert against the saved proofBlob hash.
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"})
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
}

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

// (Refined Plonky3 / sp1fri pointers for downstream sub-step ports.)
//
// Step 2 (transcript init + outer SP1 absorbs):
//   - sp1fri/verify.go:67-76 is the canonical observe order:
//       chal.Observe(degreeBits)
//       chal.Observe(baseDegreeBits)
//       chal.Observe(preprocessedWidth)
//       chal.ObserveDigest(canonicalKbDigest(commitments.trace[i]))
//       chal.ObserveSlice(publicValues)
//   - On-chain: FiatShamirState.EmitInit(t), then for the three usize-as-F
//     observations push the canonical value (each is a small int <= p) and
//     fs.EmitObserve(t). For the digest, the 8 base-field elements are
//     pushed by the unlocking script in declaration order — call EmitObserve
//     8 times. publicValues is already 3 base-field elements (3 u32 reduced
//     mod p) — also 3 EmitObserve calls.
//
// Step 3 (alpha, quotient absorb):
//   - sp1fri/verify.go:79-82.
//   - On-chain: fs.EmitSqueezeExt4(t) for alpha, then 8 EmitObserves for the
//     quotient_chunks digest.
//
// Step 4 (zeta + zeta_next):
//   - sp1fri/verify.go:85-89.
//   - On-chain: fs.EmitSqueezeExt4(t) for zeta. zeta_next is computed off-chain
//     via Ext4ScalarMul(zeta, h) — for a STATELESS verifier, h is a constant
//     derived from degree_bits (KbTwoAdicGenerator); this can be computed at
//     codegen time and pushed as a constant.
//
// Step 5 (opened-values absorb):
//   - sp1fri/verify.go:98-106.
//   - Order: chal.ObserveExt4Slice(traceLocal); chal.ObserveExt4Slice(traceNext);
//     for each quotient_chunk: chal.ObserveExt4Slice(quotChunks[i]).
//   - On-chain: each Ext4 = 4 base elements; absorb in coefficient order
//     c0..c3 — call fs.EmitObserve 4 times per Ext4.
//
// Step 6/7 (alpha-batched constraint reconstruction — NOT a sumcheck):
//   - sp1fri/verify.go:144-176 (recomposeQuotient + EvalFibonacciConstraints).
//   - Mirrors uni-stark/src/verifier.rs::verify_with_preprocessed lines 442-490.
//   - AIR-specific. For the FibAir fixture: see sp1fri/air_fib.go for the
//     exact constraint set (3 constraints over 2 columns) and the Lagrange
//     selectors at zeta. The recompose helper is a single-chunk specialisation
//     where zps[0] = 1 — reduces to a degree-3 polynomial sum over Ext4.
//
// Step 8 (FRI commit-phase absorb + fold challenge squeeze + commit-PoW):
//   - sp1fri/fri.go:60-71. Per-round: 8 EmitObserves, then EmitCheckWitness
//     (commit_pow_bits = 1 for the fixture), then EmitSqueezeExt4 for beta.
//   - Then sp1fri/fri.go:73-79: assert finalPoly length, ObserveExt4Slice the
//     final poly (4 ext4 elements for log_final_poly_len = 2).
//
// Step 9 (PoW witness for query phase):
//   - sp1fri/fri.go:86-93. Observe each logArity, then EmitCheckWitness with
//     query_pow_bits = 1.
//
// Step 10 (per-query loop — densest):
//   - sp1fri/fri.go:97-131. For each of NumQueries queries:
//       index = chal.SampleBits(logGlobalMaxHeight)            → EmitSampleBits
//       openInput → reduced openings (sp1fri/fri.go:147-257)   → MMCS verify
//       verifyQuery → fold chain (sp1fri/fri.go:262-336)       → MMCS verify
//                                                                + foldRow
//       final-poly Horner eval at x = g^revBits(domainIndex, logGlobalMaxHeight)
//   - On-chain: this composes EmitPoseidon2KBCompress (per Merkle step) +
//     EmitKBExt4Mul/Inv (for foldRow's lagrangeInterpolateAt) + 4×OP_NUMEQUALVERIFY
//     for the final equality. The Merkle-step sibling-ordering ladder is
//     emitMerkleVerify below.
//
// Step 11 (final-poly Horner eval):
//   - sp1fri/fri.go:120-130. Embedded inside the per-query loop above.
//
// Step 12 — push OP_1 for the binding result.
//
// PRE-EXISTING DIVERGENCE FROM sp1fri REFERENCE — must be addressed before
// any squeeze-using sub-step lands. See:
//
//   - Plonky3 challenger/src/duplex_challenger.rs CanSample::sample (lines
//     196-216) and the validated port at sp1fri/challenger.go:103-112: each
//     Sample() pops the **back** of the rate window (`outputBuffer[len-1]`),
//     so the canonical squeeze order is rate[7], rate[6], ..., rate[0].
//   - The on-chain FiatShamirState.EmitSqueeze (fiat_shamir_kb.go:201-215)
//     reads from the **front** of the rate window (squeezePos starts at 0
//     and increments), producing rate[0], rate[1], ..., rate[7].
//
// As a result, fs.EmitSqueezeExt4 currently produces (rate[0], rate[1], rate[2],
// rate[3]) but the prover's transcript expects (rate[7], rate[6], rate[5], rate[4]).
// Every alpha/zeta/beta/query-index challenge will therefore disagree with
// the off-chain DuplexChallenger, breaking every downstream consistency
// check. Fix by either (a) inverting the squeezePos walk inside
// EmitSqueeze, or (b) inverting the rate-fill ordering inside emitPermute
// — option (a) is local to fiat_shamir_kb.go and preserves test-vector
// compatibility for any other consumer that has already pinned the wrong
// order (none yet shipped — fiat_shamir_kb_test.go only checks counts and
// stack manipulation, not concrete sponge outputs).

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
// Steps 2-5 emission — transcript init through opened-values absorb
// =============================================================================
//
// These helpers translate the Go-reference verifier's transcript replay at
// `packages/runar-go/sp1fri/verify.go:60-110` into Bitcoin Script. Each
// helper is a thin codegen wrapper around the existing `FiatShamirState`
// observe/squeeze primitives (`fiat_shamir_kb.go`).
//
// Stack convention (mirrors existing FS helpers):
//
//   - The 16-element sponge state lives on the main stack as fs0..fs15
//     (fs0 deepest, fs15 just below any caller-pushed values). It is put
//     there by `FiatShamirState.EmitInit`.
//   - All caller-supplied values are pushed THROUGH the tracker so the
//     tracker's name table stays in sync with the runtime stack. Raw
//     `pushBytes` outside the tracker WILL desync the tracker; callers
//     must use `t.pushInt` / `tracker.pushInt` for KB elements and the
//     tracker-aware `trackerPushBytes` helper below for ByteString blobs.
//   - During permutation (auto-fired by EmitObserve when the rate fills)
//     the prime is parked on the alt-stack via PushPrimeCache. Any value
//     that the caller has temporarily stashed on the alt-stack must be
//     POPPED before the next observation. Helpers below stay on the main
//     stack throughout.

// trackerPushBytes pushes a raw byte literal through the tracker so the name
// table stays in sync. Used for chunked-byte-string absorption tests where
// the value originates as a ByteString rather than a KB element.
func trackerPushBytes(t *KBTracker, name string, b []byte) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: append([]byte(nil), b...)}})
	t.nm = append(t.nm, name)
}

// trackerSplit performs OP_SPLIT on the top of the stack: consumes
// [bytes, n] and produces [prefix, suffix] (suffix on top). Updates the
// tracker name table accordingly.
//
// Mirrors the BSV semantics: OP_SPLIT pops the split-position `n` and
// the byte string, pushes the first `n` bytes (prefix) deeper and the
// remaining bytes (suffix) on top.
func trackerSplit(t *KBTracker, prefixName, suffixName string) {
	// Pop the integer split-position and the byte string from tracker.
	if len(t.nm) >= 2 {
		t.nm = t.nm[:len(t.nm)-2]
	}
	t.e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	t.nm = append(t.nm, prefixName)
	t.nm = append(t.nm, suffixName)
}

// emitObserveByteString absorbs a ByteString into the Fiat-Shamir transcript
// by chunking it into KoalaBear field elements (4 bytes per field; tail
// padded with low-order zero bytes if |bs| mod 4 != 0) and observing each
// chunk in declaration (left-to-right) order.
//
// Used for absorbing `sp1VKeyHash` (32 bytes → 8 chunks) and `publicValues`
// (variable length; for the PoC fixture 12 bytes → 3 chunks).
//
// Convention: matches the SP1 outer-wrapper byte-to-field packing per
// `docs/sp1-fri-verifier.md` §3.1 — each 4-byte LE chunk is interpreted
// as a little-endian unsigned u32 and absorbed as a base-field element.
// Mirrors `packages/runar-go/sp1fri/challenger.go::ObserveSlice`
// composed with the wrapper-layer u32 packing.
//
// Stack in:  [..., fs0..fs15, bs]      (bs is byteSize bytes long)
// Stack out: [..., fs0'..fs15']         (bs and any chunks consumed)
func emitObserveByteString(fs *FiatShamirState, t *KBTracker, byteSize int) {
	if byteSize == 0 {
		// Empty ByteString — drop and return; nothing to absorb.
		t.drop()
		return
	}
	if byteSize < 0 {
		panic(fmt.Sprintf("emitObserveByteString: byteSize must be non-negative, got %d", byteSize))
	}
	numChunks := (byteSize + 3) / 4
	tail := byteSize - 4*(numChunks-1) // bytes in the last chunk (1..4)

	// Name the input so the tracker can track it through splits.
	t.rename("_obs_bs_remain")

	// Phase 1: extract the first numChunks-1 4-byte chunks as canonical u32s
	// onto the stack, named _obs_chunk_0 ... _obs_chunk_{N-2}. After each
	// extraction _obs_bs_remain is shorter by 4 bytes and stays on top.
	for i := 0; i < numChunks-1; i++ {
		// Push 4, OP_SPLIT → prefix(4), suffix(remain - 4).
		t.pushInt("_obs_split_n", 4)
		trackerSplit(t, fmt.Sprintf("_obs_chunk_%d_bytes", i), "_obs_bs_remain")

		// Bring the prefix bytes to the top to convert.
		t.toTop(fmt.Sprintf("_obs_chunk_%d_bytes", i))

		// Pad with one zero byte (sign byte) and OP_BIN2NUM to interpret as
		// LE unsigned. The 0x00 sign byte ensures values >= 2^31 are still
		// treated as positive.
		chunkName := fmt.Sprintf("_obs_chunk_%d", i)
		t.rawBlock([]string{fmt.Sprintf("_obs_chunk_%d_bytes", i)}, chunkName, func(e func(StackOp)) {
			e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
			e(StackOp{Op: "opcode", Code: "OP_CAT"})
			e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		})

		// After the conversion the chunk number is on top; _obs_bs_remain is
		// just below it. Swap so _obs_bs_remain is back on top for the next
		// iteration. (For the final iteration we keep _obs_bs_remain below
		// to convert it; see Phase 2.)
		t.swap()
	}

	// Phase 2: convert the last chunk (_obs_bs_remain). If tail < 4, we pad
	// the high bytes with zeros to make a 5-byte LE unsigned representation.
	// SP1 convention: low-order zero pad in LE means HIGH-byte position
	// (the bytes that come AFTER the actual data in LE order) gets zeros.
	t.toTop("_obs_bs_remain")
	chunkName := fmt.Sprintf("_obs_chunk_%d", numChunks-1)
	t.rawBlock([]string{"_obs_bs_remain"}, chunkName, func(e func(StackOp)) {
		// Pad bytes: (4 - tail) zero bytes to fill the chunk + 1 sign byte.
		padLen := (4 - tail) + 1
		pad := make([]byte, padLen)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: pad}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Phase 3: absorb the chunks in declaration order (chunk_0 first).
	// Each EmitObserve consumes the top of the stack and may trigger a
	// permutation (when absorbPos hits 8). Bring chunk_i to the top
	// individually so we don't have to worry about which chunks remain
	// after intermediate observations.
	for i := 0; i < numChunks; i++ {
		t.toTop(fmt.Sprintf("_obs_chunk_%d", i))
		fs.EmitObserve(t)
	}
}

// emitObserveDigest absorbs an 8-element Poseidon2-KB digest into the
// transcript in canonical order (d0 first, d7 last).
//
// Mirrors `packages/runar-go/sp1fri/challenger.go::ObserveDigest`.
//
// Stack in:  [..., fs0..fs15, d0, d1, ..., d7]   (d7 on top, d0 deepest of
//                                                 the digest block)
// Stack out: [..., fs0'..fs15']                   (digest fully consumed)
//
// Caller must have pushed the 8 elements through the tracker with names
// `digestNames[0..7]` so the tracker can locate each by name. We use a
// fixed naming scheme to match the test harness: `_obs_dig_<i>`.
func emitObserveDigest(fs *FiatShamirState, t *KBTracker) {
	for i := 0; i < 8; i++ {
		t.toTop(fmt.Sprintf("_obs_dig_%d", i))
		fs.EmitObserve(t)
	}
}

// emitObserveExt4 absorbs an Ext4 element (4 base coefficients) into the
// transcript in coefficient order (c0 first, c3 last).
//
// Mirrors `packages/runar-go/sp1fri/challenger.go::ObserveExt4`.
//
// Stack in:  [..., fs0..fs15, c0, c1, c2, c3]   (c3 on top)
// Stack out: [..., fs0'..fs15']
//
// Caller must have named the 4 coefficients via the `extNames` slice.
func emitObserveExt4Named(fs *FiatShamirState, t *KBTracker, extNames [4]string) {
	for i := 0; i < 4; i++ {
		t.toTop(extNames[i])
		fs.EmitObserve(t)
	}
}

// emitObserveOpenedValues absorbs all opened values in the canonical
// Plonky3 emit order. For the PoC minimal-guest fixture
// (`packages/runar-go/sp1fri/verify.go:98-106`) this is:
//   - 2 trace_local Ext4 elements
//   - 2 trace_next Ext4 elements
//   - 1 quotient_chunks batch of 1 chunk × 4 Ext4 elements
//
// (preprocessed_local/_next and random are typically None for the PoC.)
//
// All Ext4 elements use the same coefficient-order convention as
// `emitObserveExt4Named`. The caller must have named them
// `_obs_open_<group>_<idx>_c<coef>` per the scheme below.
//
// Naming scheme (matches the test harness pushOpenedValues):
//   - trace_local Ext4 i (0..1):   _obs_open_tl_<i>_c<j>   for j in 0..3
//   - trace_next  Ext4 i (0..1):   _obs_open_tn_<i>_c<j>
//   - quotient_chunks Ext4 i (0..3): _obs_open_qc_<i>_c<j>
//
// Stack convention: caller has pushed all 4 + 4 + 4 = 12 Ext4 values =
// 48 base-field KB elements ahead of this call. We absorb them in the
// canonical order; the tracker's `toTop` finds each by name.
func emitObserveOpenedValues(fs *FiatShamirState, t *KBTracker, params SP1FriVerifierParams) {
	_ = params // PoC fixture is hard-coded; future versions parameterise.

	// trace_local: 2 Ext4 elements.
	for i := 0; i < 2; i++ {
		var names [4]string
		for j := 0; j < 4; j++ {
			names[j] = fmt.Sprintf("_obs_open_tl_%d_c%d", i, j)
		}
		emitObserveExt4Named(fs, t, names)
	}
	// trace_next: 2 Ext4 elements.
	for i := 0; i < 2; i++ {
		var names [4]string
		for j := 0; j < 4; j++ {
			names[j] = fmt.Sprintf("_obs_open_tn_%d_c%d", i, j)
		}
		emitObserveExt4Named(fs, t, names)
	}
	// quotient_chunks: 1 batch × 4 Ext4 elements (Challenge::DIMENSION = 4).
	for i := 0; i < 4; i++ {
		var names [4]string
		for j := 0; j < 4; j++ {
			names[j] = fmt.Sprintf("_obs_open_qc_%d_c%d", i, j)
		}
		emitObserveExt4Named(fs, t, names)
	}
}

// emitTranscriptInit orchestrates Steps 2-5 of the SP1 FRI verifier:
// transcript initialisation, sp1VKeyHash absorb, publicValues absorb,
// trace-commitment absorb, alpha squeeze, quotient-commitment absorb,
// zeta squeeze, opened-values absorb.
//
// Mirrors the canonical Plonky3 + SP1-outer-wrapper sequence per
// `docs/sp1-fri-verifier.md` §3 with the byte-to-field packing for
// sp1VKeyHash and publicValues per §3.1. The validated Go-reference
// `packages/runar-go/sp1fri/verify.go:60-110` is the post-wrapper
// equivalent (the regen Rust binary does not produce a sp1VKeyHash so
// the reference verifier omits it).
//
// Stack in (top → bottom): the caller has pushed every observed value
// through the tracker with the canonical naming scheme:
//
//   - sp1VKeyHash (ByteString):           _obs_sp1_vk_hash
//   - publicValues (ByteString):          _obs_public_values
//   - trace digest (8 KB elements):       _obs_dig_0 .. _obs_dig_7
//   - quotient digest (8 KB elements):    _obs_qdig_0 .. _obs_qdig_7
//   - opened values (Ext4 components):    _obs_open_*_c*  (see
//                                          emitObserveOpenedValues)
//
// The SP1FriVerifierParams.PublicValuesByteSize and SP1VKeyHashByteSize
// fields control the chunking lengths.
//
// Stack out: the sponge state fs0..fs15 on top (with alpha + zeta values
// also live as `_fs_alpha_<i>` / `_fs_zeta_<i>` named slots above the
// sponge state). Subsequent Steps 6+ consume these.
func emitTranscriptInit(fs *FiatShamirState, t *KBTracker, params SP1FriVerifierParams) {
	// Step 2a — Initialise the sponge state on the main stack.
	fs.EmitInit(t)

	// Step 2b — Absorb sp1VKeyHash bytes (outer SP1 wrapper layer per
	// docs/sp1-fri-verifier.md §3). Caller-supplied byte length controls
	// the chunk count. For the canonical Plonky3 fixture (no SP1 wrapper)
	// callers pass SP1VKeyHashByteSize=0 and the helper is a no-op.
	if params.SP1VKeyHashByteSize > 0 {
		t.toTop("_obs_sp1_vk_hash")
		emitObserveByteString(fs, t, params.SP1VKeyHashByteSize)
	}

	// Step 2c — Absorb instance metadata (sp1fri/verify.go:67-70). Each is a
	// canonical KB element (small ints fit trivially). These are codegen-time
	// constants for a given param tuple, so we push them inline. Without these
	// the on-chain transcript diverges from the prover's at the very first
	// SampleExt4, breaking all PoW witness checks downstream.
	t.pushInt("_obs_meta_dbits", int64(params.DegreeBits))
	fs.EmitObserve(t)
	t.pushInt("_obs_meta_bdbits", int64(params.BaseDegreeBits))
	fs.EmitObserve(t)
	t.pushInt("_obs_meta_pwidth", int64(params.PreprocessedWidth))
	fs.EmitObserve(t)

	// Step 3 — Absorb the trace commitment (8-element Poseidon2 digest).
	// Order matches verify.go:71-74 (digest BEFORE publicValues).
	emitObserveDigest(fs, t)

	// Step 4 — Absorb publicValues bytes (verify.go:76).
	t.toTop("_obs_public_values")
	emitObserveByteString(fs, t, params.PublicValuesByteSize)

	// Step 5 — Squeeze alpha (Ext4) — produces _fs_ext4_0.._fs_ext4_3 on top.
	fs.EmitSqueezeExt4(t)
	// Rename the 4 squeeze outputs so subsequent squeezes (e.g. zeta) don't
	// overwrite the names.
	t.rename("_fs_alpha_3")
	t.toTop("_fs_ext4_2")
	t.rename("_fs_alpha_2")
	t.toTop("_fs_ext4_1")
	t.rename("_fs_alpha_1")
	t.toTop("_fs_ext4_0")
	t.rename("_fs_alpha_0")

	// Step 6 — Absorb the quotient_chunks commitment (8-element digest).
	for i := 0; i < 8; i++ {
		// Re-target the digest helper at the quotient-digest names.
		// We inline rather than call emitObserveDigest because the names differ.
		t.toTop(fmt.Sprintf("_obs_qdig_%d", i))
		fs.EmitObserve(t)
	}

	// Step 7 — Squeeze zeta (Ext4).
	fs.EmitSqueezeExt4(t)
	t.rename("_fs_zeta_3")
	t.toTop("_fs_ext4_2")
	t.rename("_fs_zeta_2")
	t.toTop("_fs_ext4_1")
	t.rename("_fs_zeta_1")
	t.toTop("_fs_ext4_0")
	t.rename("_fs_zeta_0")

	// Step 8 — Absorb opened values in Plonky3 emit order.
	emitObserveOpenedValues(fs, t, params)
}

// =============================================================================
// Step 8 — FRI commit-phase absorbs + beta squeezes + final-poly absorb +
//          query-PoW witness check.
// =============================================================================
//
// Mirrors `packages/runar-go/sp1fri/fri.go::verifyFri` (lines 20-93) for the
// PoC minimal-guest config. Layout:
//
//   1. Squeeze alpha_fri (Ext4)                                  — fri.go:25
//   2. For each FRI commit round r in 0..MerkleDepth (cap_height=0 → 1
//      digest per round):
//        a. ObserveDigest(commit[r])                              — fri.go:63-65
//        b. Observe(commit_pow_witness[r]) + CheckWitness(commit_pow_bits)
//                                                                 — fri.go:66-69
//        c. Squeeze beta_r (Ext4)                                 — fri.go:70
//   3. ObserveExt4Slice(final_poly)                              — fri.go:79
//   4. For each round r: Observe(uint32(logArity_r))             — fri.go:87-89
//   5. Observe(query_pow_witness) + CheckWitness(query_pow_bits) — fri.go:90-93
//
// The four fields with "(squeeze)" semantics are renamed into stable slot
// names so subsequent steps (FRI per-query verify) can reference them.
//
// The unlocking script must have pre-pushed every absorbed value through the
// tracker with the canonical naming scheme below; see the Step 8 test harness
// for the layout the helper consumes.
//
// Naming scheme (mirrors emitObserveDigest / emitObserveExt4Named):
//   - FRI digest at round r:   _obs_fri_dig_{r}_<i>        for i in 0..7
//   - commit_pow_witness[r]:   _obs_fri_cpw_{r}
//   - final_poly Ext4 i:       _obs_fri_fp_{i}_c<j>        for j in 0..3
//   - logArity at round r:     _obs_fri_la_{r}
//   - query_pow_witness:       _obs_fri_qpw
//
// Squeeze outputs (renamed onto stable slots above the sponge):
//   - alpha_fri Ext4:          _fs_alpha_fri_<i>            for i in 0..3
//   - beta at round r Ext4:    _fs_beta_{r}_<i>             for i in 0..3
//
// At entry the sponge state fs0..fs15 is on top of all caller-pushed slots,
// and the caller has positioned every named field below. At exit, fs0..fs15
// remains on top with all squeezed challenges renamed below it.

// emitFriCommitPhaseAbsorb performs Step 8 of the SP1 FRI verifier.
//
// Mirrors `verifyFri` (sp1fri/fri.go:20-93). For the PoC minimal-guest config
// `MerkleDepth` (= number of FRI commit-phase rounds) is determined by the
// fixture's `total_log_reduction = sum(log_arity_r)`. With `LogFinalPolyLen=2`
// and `LogBlowup=2` and trace `degreeBits=3`:
//
//   logGlobalMaxHeight = degreeBits + LogBlowup = 5
//   logFinalHeight     = LogBlowup + LogFinalPolyLen = 4
//   total_log_reduction = logGlobalMaxHeight - logFinalHeight = 1
//
// At max_log_arity = 1 (binary folding), total_log_reduction = 1 means there is
// exactly ONE FRI commit-phase round.
//
// `numRounds` is the static count of commit-phase rounds (MerkleDepth here),
// `finalPolyLen` is the static count of Ext4 coefficients in final_poly
// (= 1 << LogFinalPolyLen). Both are codegen-time constants for a given param
// tuple — they're plumbed in explicitly to keep the helper's stack contract
// auditable.
func emitFriCommitPhaseAbsorb(fs *FiatShamirState, t *KBTracker, params SP1FriVerifierParams, numRounds, finalPolyLen int) {
	if numRounds < 1 {
		panic(fmt.Sprintf("emitFriCommitPhaseAbsorb: numRounds must be >= 1, got %d", numRounds))
	}
	if finalPolyLen < 1 {
		panic(fmt.Sprintf("emitFriCommitPhaseAbsorb: finalPolyLen must be >= 1, got %d", finalPolyLen))
	}

	// 1. Squeeze alpha_fri (the per-height batching scalar inside FRI). This is
	//    the SECOND Ext4 squeeze of the AIR/FRI verifier (the first was the
	//    outer-stark `alpha` in Step 5). See sp1fri/fri.go:25.
	fs.EmitSqueezeExt4(t)
	t.rename("_fs_alpha_fri_3")
	t.toTop("_fs_ext4_2")
	t.rename("_fs_alpha_fri_2")
	t.toTop("_fs_ext4_1")
	t.rename("_fs_alpha_fri_1")
	t.toTop("_fs_ext4_0")
	t.rename("_fs_alpha_fri_0")

	// 2. Per-round: digest absorb, PoW witness check, beta squeeze.
	for r := 0; r < numRounds; r++ {
		// 2a. ObserveDigest(commit[r]) — 8 base-field elements named
		// _obs_fri_dig_{r}_<i>, absorbed in canonical i=0..7 order.
		// Note: cap_height=0 ⇒ exactly one digest per MerkleCap.
		for i := 0; i < 8; i++ {
			t.toTop(fmt.Sprintf("_obs_fri_dig_%d_%d", r, i))
			fs.EmitObserve(t)
		}

		// 2b. Observe(commit_pow_witness[r]) + CheckWitness(commit_pow_bits).
		// EmitCheckWitness is a no-op when bits == 0 (handled by the caller's
		// conditional below). For the PoC fixture commit_pow_bits = 1.
		t.toTop(fmt.Sprintf("_obs_fri_cpw_%d", r))
		if params.CommitPoWBits > 0 {
			fs.EmitCheckWitness(t, params.CommitPoWBits)
		} else {
			// Even with no bits the witness must be observed (Plonky3's
			// CheckWitness returns true immediately for bits=0 WITHOUT
			// observing — sp1fri/challenger.go:144-146). So in the
			// bits==0 case we must drop the pushed witness. To keep the
			// helper's stack contract clean for both branches, callers
			// should not push a witness when CommitPoWBits == 0; this
			// branch panics defensively.
			panic("emitFriCommitPhaseAbsorb: bits==0 path not exercised by PoC; " +
				"unlocking script must omit _obs_fri_cpw_* pushes when CommitPoWBits == 0")
		}

		// 2c. Squeeze beta_r (Ext4) and rename into stable slots so later FRI
		// per-query steps can reference _fs_beta_{r}_<i>.
		fs.EmitSqueezeExt4(t)
		t.rename(fmt.Sprintf("_fs_beta_%d_3", r))
		t.toTop("_fs_ext4_2")
		t.rename(fmt.Sprintf("_fs_beta_%d_2", r))
		t.toTop("_fs_ext4_1")
		t.rename(fmt.Sprintf("_fs_beta_%d_1", r))
		t.toTop("_fs_ext4_0")
		t.rename(fmt.Sprintf("_fs_beta_%d_0", r))
	}

	// 3. ObserveExt4Slice(final_poly). final_poly has finalPolyLen Ext4 elements
	// (= 1 << LogFinalPolyLen for the PoC = 4). Each is absorbed coefficient-
	// by-coefficient in canonical order; sp1fri/challenger.go:84-95.
	for i := 0; i < finalPolyLen; i++ {
		var names [4]string
		for j := 0; j < 4; j++ {
			names[j] = fmt.Sprintf("_obs_fri_fp_%d_c%d", i, j)
		}
		emitObserveExt4Named(fs, t, names)
	}

	// 4. For each round, Observe(uint32(logArity_r)). Mirrors sp1fri/fri.go:87-89.
	// The logArity values are pushed by the unlocking script as canonical KB
	// elements (any value <= max_log_arity = 1 fits trivially).
	for r := 0; r < numRounds; r++ {
		t.toTop(fmt.Sprintf("_obs_fri_la_%d", r))
		fs.EmitObserve(t)
	}

	// 5. Observe(query_pow_witness) + CheckWitness(query_pow_bits). Same shape
	// as step 2b. For the PoC fixture query_pow_bits = 1.
	t.toTop("_obs_fri_qpw")
	if params.QueryPoWBits > 0 {
		fs.EmitCheckWitness(t, params.QueryPoWBits)
	} else {
		panic("emitFriCommitPhaseAbsorb: bits==0 path not exercised by PoC; " +
			"unlocking script must omit _obs_fri_qpw push when QueryPoWBits == 0")
	}
}

// =============================================================================
// Step 6 — Fibonacci AIR symbolic constraint evaluator (refined stub)
// =============================================================================
//
// Mirrors `packages/runar-go/sp1fri/air_fib.go::EvalFibonacciConstraints` +
// `SelectorsAtPoint`. Implementation is deferred behind a panic until the
// Ext4 macro layer (sp1_fri_ext4.go) lands: each Ext4 mul/inv/sub composes
// the existing flat `EmitKBExt4Mul0..3` / `EmitKBExt4Inv0..3` emitters with
// careful 8-element input window staging via the tracker.
//
// At entry the named slots present (from emitTranscriptInit + Step 8):
//
//   - _fs_alpha_0.._fs_alpha_3       (outer-stark batch challenge)
//   - _fs_zeta_0.._fs_zeta_3         (out-of-domain point)
//   - _fs_alpha_fri_0.._fs_alpha_fri_3  (FRI batching scalar)
//   - _fs_beta_<r>_<i>               (per-round FRI fold challenges)
//   - _obs_open_tl_<i>_c<j>          (trace_local, 2 Ext4)
//   - _obs_open_tn_<i>_c<j>          (trace_next, 2 Ext4)
//   - _obs_open_qc_<i>_c<j>          (quotient_chunks, 4 Ext4)
//
// Public values [a, b, x] are not re-pushed — they were absorbed as bytes
// in Step 4 but the constraint evaluator needs them as canonical KB ints.
// Caller must push them through the tracker as `_pis_a`, `_pis_b`, `_pis_x`
// (each as a base-field element lifted into Ext4 by setting only c0).
//
// At exit the alpha-folded constraint accumulator sits on top as
// `_fold_acc_0`, `_fold_acc_1`, `_fold_acc_2`, `_fold_acc_3`.
func emitFibAirConstraintEval(fs *FiatShamirState, t *KBTracker, params SP1FriVerifierParams) {
	panicSP1FriStub(
		"verifySP1FRI Step 6 (Fibonacci AIR constraint evaluation at zeta)",
		"sp1fri/air_fib.go::EvalFibonacciConstraints + SelectorsAtPoint (lines 41-123). "+
			"Selectors at zeta require Ext4 operations: z_h = zeta^|H| - 1 (logSize=3 squarings), "+
			"is_first_row = z_h / (zeta - 1), is_last_row = z_h / (zeta - h_inv), "+
			"is_transition = (zeta - h_inv), inv_vanishing = 1/z_h. The constraint folder "+
			"runs 5 alpha-folds: acc = acc * alpha + selector * (left|right - target). Each "+
			"Ext4 mul/inv composes 4 calls to EmitKBExt4Mul0..3 / EmitKBExt4Inv0..3.",
		"Structural shape: implementable as a sequence of macro calls once the Ext4 macro "+
			"layer (sp1_fri_ext4.go) lands. The macro `kbExt4MulMacro(t, aPrefix, bPrefix, outPrefix)` "+
			"would: (a) for each component i in 0..3, copyToTop the 8 named inputs in canonical "+
			"order (a0..a3, b0..b3), call EmitKBExt4Mul[i] which consumes 8 and produces 1, "+
			"rename the result to outPrefix_<i>; (b) skip the cleanup-drop inside the existing "+
			"helper since copyToTop preserves originals. Estimate: each Ext4 mul = ~4 × 800 = "+
			"3200 ops; the 5-constraint Fib AIR eval needs ~10 Ext4 muls + 4 Ext4 invs + 4 Ext4 "+
			"subs = ~50K ops + ~30K ops + 16 ops = ~80K ops added on top of the Step 8 "+
			"baseline (~250K ops).")
	_ = fs
	_ = t
	_ = params
}

// =============================================================================
// Step 7 — Quotient recompose + OOD constraint check (refined stub)
// =============================================================================
//
// Mirrors `packages/runar-go/sp1fri/verify.go::recomposeQuotient` (lines 250-283)
// + the final equality at lines 172-174. For the PoC's single quotient chunk
// (numQuotientChunks=1), zps[0] = 1 (empty product), so the recompose collapses to:
//
//   quotient = sum over e in 0..3 of basisExt4(e) * chunk[e]
//
// Where basisExt4(e) is the e-th unit vector. This is just a polynomial-shift
// (mul by X^e) followed by Ext4 sum. Because X^4 = W = 3 in the binomial
// extension, mul-by-X^e is a pure permutation + scale-by-W:
//
//   chunk[0]: identity (no shift)
//   chunk[1] * X:    (c0,c1,c2,c3) → (W*c3, c0, c1, c2)
//   chunk[2] * X^2:  (c0,c1,c2,c3) → (W*c2, W*c3, c0, c1)
//   chunk[3] * X^3:  (c0,c1,c2,c3) → (W*c1, W*c2, W*c3, c0)
//
// Sum 4 Ext4s component-wise. Then the final check:
//
//   assert(folded_constraints * inv_vanishing == quotient)   (Ext4 equality)
//
// Which requires one full Ext4 mul (sum of 4 EmitKBExt4Mul calls) + 4 ×
// OP_NUMEQUALVERIFY against the recomposed quotient.
func emitQuotientRecompose(fs *FiatShamirState, t *KBTracker, params SP1FriVerifierParams) {
	panicSP1FriStub(
		"verifySP1FRI Step 7 (quotient recompose + OOD equality check)",
		"sp1fri/verify.go::recomposeQuotient (lines 243-283) + final equality at 172-174. "+
			"For numQuotientChunks=1 the recompose collapses to: "+
			"quotient = chunk[0] + chunk[1]*X + chunk[2]*X^2 + chunk[3]*X^3 mod (X^4 - W) "+
			"with W = 3. Each X^e multiplication is a pure permutation + scale-by-W on the "+
			"4 Ext4 coefficients (no Ext4 mul needed for the recompose). The final equality "+
			"check `folded * inv_vanishing == quotient` does need one full Ext4 mul.",
		"Structural shape: (a) recompose is component-wise — for the 4 output coefficients, "+
			"compute r0 = chunk[0]_c0 + W*chunk[1]_c3 + W*chunk[2]_c2 + W*chunk[3]_c1 (5 adds + 3 muls-by-3); "+
			"r1 = chunk[0]_c1 + chunk[1]_c0 + W*chunk[2]_c3 + W*chunk[3]_c2 (5 adds + 2 muls-by-3); "+
			"r2 = chunk[0]_c2 + chunk[1]_c1 + chunk[2]_c0 + W*chunk[3]_c3 (5 adds + 1 mul-by-3); "+
			"r3 = chunk[0]_c3 + chunk[1]_c2 + chunk[2]_c1 + chunk[3]_c0 (5 adds). "+
			"Each base-field add/mul-by-W goes through kbFieldAdd/kbFieldMulConst — "+
			"~50 ops per coefficient, ~200 ops total for the recompose. (b) Ext4 mul of "+
			"folded * inv_vanishing: 4 × kbExt4MulComponent ≈ 4 × 800 = 3200 ops. (c) Final "+
			"equality: copyToTop each component pair, OP_NUMEQUAL + OP_VERIFY × 4. Total Step 7 "+
			"~3500 ops added on top of Step 6 output.")
	_ = fs
	_ = t
	_ = params
}

// =============================================================================
// Absorb-a-ByteString helper (deprecated stub — superseded by
// emitObserveByteString above; kept for documentation cross-reference).
// =============================================================================

// emitAbsorbByteString is the original, never-implemented stub. Use
// emitObserveByteString instead. Kept only so the panic-string regression
// tests that look for the old reference-pointer text still pass; will be
// removed once all step ports are wired through emitObserveByteString.
func emitAbsorbByteString(fs *FiatShamirState, t *KBTracker) {
	_ = fs
	_ = t
	panicSP1FriStub(
		"absorb-ByteString-as-field-elements (legacy)",
		"superseded by emitObserveByteString in this same file; see "+
			"docs/sp1-fri-verifier.md §3.1 for the byte-to-field convention.",
		"Caller migration: replace emitAbsorbByteString(fs, t) with "+
			"emitObserveByteString(fs, t, byteSize) where byteSize is the "+
			"static length of the ByteString.")
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

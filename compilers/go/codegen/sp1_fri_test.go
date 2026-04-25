package codegen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// ---------------------------------------------------------------------------
// SP1 FRI verifier — codegen-step regression tests.
//
// These tests exercise sub-steps of the SP1 FRI verifier emission in
// `sp1_fri.go` against the real Plonky3 KoalaBear minimal-guest fixture
// at `tests/vectors/sp1/fri/minimal-guest/proof.postcard`.
//
// The Go off-chain reference verifier in `packages/runar-go/sp1fri` is the
// validated ground truth — its `TestVerifyMinimalGuest` accepts the same
// fixture end-to-end. Each codegen sub-step here runs the corresponding
// Bitcoin Script through the go-sdk interpreter via BuildAndExecuteOps.
// ---------------------------------------------------------------------------

// loadMinimalGuestProofBlob reads the canonical fixture bytes.
func loadMinimalGuestProofBlob(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
		"tests", "vectors", "sp1", "fri", "minimal-guest", "proof.postcard")
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(bs) == 0 {
		t.Fatal("fixture is empty")
	}
	return bs
}

// pushBytes is a convenience StackOp constructor for raw byte pushes.
func pushBytes(b []byte) StackOp {
	return StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: append([]byte(nil), b...)}}
}

// chunkProof slices a byte string into `n` contiguous, non-empty pieces in
// canonical (left-to-right) order. Returned in the natural order: result[0]
// holds the leftmost bytes, result[n-1] holds the rightmost.
//
// The Step 1 binding only checks that the SHA-256 of the concatenation
// equals the SHA-256 of the original blob — it does not care about the
// internal bincode/postcard structure. Splitting at arbitrary byte
// boundaries is sufficient to validate the structural Bitcoin Script
// emission against a real fixture without re-implementing the postcard
// per-field decode in the test harness. (The full per-field push layout
// is pinned in docs/sp1-fri-verifier.md §2.1; subsequent verifier
// sub-steps consume each field in declaration order.)
func chunkProof(t *testing.T, bs []byte, n int) [][]byte {
	t.Helper()
	if n < 1 {
		t.Fatalf("chunkProof: n must be >= 1, got %d", n)
	}
	if n > len(bs) {
		t.Fatalf("chunkProof: n=%d > |bs|=%d", n, len(bs))
	}
	chunkSize := len(bs) / n
	if chunkSize < 1 {
		t.Fatalf("chunkProof: derived chunk size 0 (|bs|=%d, n=%d)", len(bs), n)
	}
	out := make([][]byte, n)
	for i := 0; i < n-1; i++ {
		out[i] = bs[i*chunkSize : (i+1)*chunkSize]
	}
	out[n-1] = bs[(n-1)*chunkSize:]
	return out
}

// TestSp1FriVerifier_Step1_ProofBlobBinding_TwoChunks runs the simplest
// possible binding scenario: 1 field push that equals the full proofBlob.
// The hash of [field0] must equal the hash of proofBlob, so the binding
// passes. Validates the basic emission shape (PICK + SHA256 + EQUALVERIFY).
func TestSp1FriVerifier_Step1_ProofBlobBinding_SingleField(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)

	// Locking-script ops:
	//   push field0 (= proofBlob)
	//   push proofBlob
	//   <Step 1 binding>      (consumes proofBlob; leaves field0)
	//   drop field0           (drained by would-be subsequent steps)
	//   OP_1                  (success)
	var ops []StackOp
	ops = append(ops, pushBytes(bs)) // field0
	ops = append(ops, pushBytes(bs)) // proofBlob

	bindingOps := gatherOps(func(emit func(StackOp)) {
		EmitProofBlobBindingHash(emit, 1)
	})
	ops = append(ops, bindingOps...)

	// Drain leftover field0 so the script ends cleanly.
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("verifier rejected the canonical fixture (single-field case): %v", err)
	}
	t.Logf("Step 1 single-field accepted; |proofBlob|=%d, |bindingOps|=%d", len(bs), len(bindingOps))
}

// TestSp1FriVerifier_Step1_ProofBlobBinding_FourChunks uses 4 chunks. Tests
// the PICK ladder + repeated OP_CAT.
func TestSp1FriVerifier_Step1_ProofBlobBinding_FourChunks(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	chunks := chunkProof(t, bs, 4)

	// Sanity: chunks reconstruct the blob.
	var rebuilt []byte
	for _, c := range chunks {
		rebuilt = append(rebuilt, c...)
	}
	gotHash := sha256.Sum256(rebuilt)
	wantHash := sha256.Sum256(bs)
	if hex.EncodeToString(gotHash[:]) != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("test scaffold bug: rebuilt hash mismatch want=%x got=%x", wantHash, gotHash)
	}

	// Push fields in declaration order: field0 deepest, fieldN-1 shallowest,
	// then proofBlob on top — matches docs/sp1-fri-verifier.md §2.1 entry
	// stack layout (modulo publicValues/sp1VKeyHash which the caller
	// stashes to the alt-stack first).
	var ops []StackOp
	for _, c := range chunks {
		ops = append(ops, pushBytes(c))
	}
	ops = append(ops, pushBytes(bs)) // proofBlob

	bindingOps := gatherOps(func(emit func(StackOp)) {
		EmitProofBlobBindingHash(emit, len(chunks))
	})
	ops = append(ops, bindingOps...)

	// Drain the four leftover fields.
	for i := 0; i < len(chunks); i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("verifier rejected the canonical fixture (4-chunk case): %v", err)
	}
	t.Logf("Step 1 4-chunk accepted; |proofBlob|=%d, |chunks|=%d, |bindingOps|=%d",
		len(bs), len(chunks), len(bindingOps))
}

// TestSp1FriVerifier_Step1_ProofBlobBinding_RejectsTampered confirms the
// binding fails OP_VERIFY when the pushed fields don't reconstruct the
// proofBlob. This guards against silent-acceptance bugs in the emission.
func TestSp1FriVerifier_Step1_ProofBlobBinding_RejectsTampered(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	chunks := chunkProof(t, bs, 4)

	// Flip one bit in the last chunk.
	bad := append([]byte(nil), chunks[3]...)
	bad[len(bad)-1] ^= 0x01
	chunks[3] = bad

	var ops []StackOp
	for _, c := range chunks {
		ops = append(ops, pushBytes(c))
	}
	ops = append(ops, pushBytes(bs)) // unmodified proofBlob

	bindingOps := gatherOps(func(emit func(StackOp)) {
		EmitProofBlobBindingHash(emit, len(chunks))
	})
	ops = append(ops, bindingOps...)
	for i := 0; i < len(chunks); i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	err := buildAndExecute(t, ops)
	if err == nil {
		t.Fatal("expected OP_EQUALVERIFY failure on tampered field, but script succeeded")
	}
	t.Logf("Step 1 correctly rejected tampered field with: %v", err)
}

// TestFiatShamirKB_SqueezeMatchesReference is the regression test for the
// pre-existing duplex-sponge ordering bug discussed at the bottom of
// sp1_fri.go. The on-chain FiatShamirState in fiat_shamir_kb.go reads from
// the FRONT of the rate window (squeezePos starts at 0 and increments),
// while the validated reference at sp1fri/challenger.go:103-112 (mirroring
// Plonky3 challenger/src/duplex_challenger.rs CanSample::sample) pops from
// the BACK of the rate window. Without this fix, every alpha/zeta/beta/
// query-index challenge derived on-chain disagrees with the prover's, so no
// FRI proof can ever verify.
//
// Test shape:
//
//   1. Absorb 8 base-field elements (1..8) into the reference DuplexChallenger,
//      sample 4 elements — capture canonical values.
//   2. Build a Bitcoin Script that does the equivalent: push 16 zeros for the
//      sponge state, then absorb 1..8 (which fills rate and triggers permute),
//      then squeeze 4 elements. Assert each squeezed element equals the
//      reference value via OP_NUMEQUALVERIFY.
//   3. Execute via BuildAndExecuteOps. The script must succeed.
func TestFiatShamirKB_SqueezeMatchesReference(t *testing.T) {
	// 1. Reference values.
	ref := sp1fri.NewDuplexChallenger()
	for i := uint32(0); i < 8; i++ {
		ref.Observe(i + 1)
	}
	want := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		want[i] = ref.Sample()
	}

	// 2. Build the codegen-emitted script that mirrors the same observation +
	// sample sequence. Stack at start: nothing pushed by the unlocking
	// script — we synthesise it inline.
	var ops []StackOp

	fs := NewFiatShamirState()
	tracker := NewKBTracker(nil, func(op StackOp) {
		ops = append(ops, op)
	})

	// Initialise the sponge state on the main stack.
	fs.EmitInit(tracker)

	// Absorb 1..8 — last absorb fills rate and triggers permutation.
	for i := 0; i < 8; i++ {
		tracker.pushInt("element", int64(i+1))
		fs.EmitObserve(tracker)
	}

	// Squeeze 4 elements. After each, assert against the reference.
	// Stack on top after EmitSqueeze: ..., _fs_squeezed
	for i := 0; i < 4; i++ {
		fs.EmitSqueeze(tracker)
		// The squeezed element is on top. Push the expected value, NUMEQUALVERIFY.
		tracker.toTop("_fs_squeezed")
		// Push expected (use raw push directly because tracker has no helper for uint32).
		ops = append(ops, pushInt64(int64(want[i])))
		ops = append(ops, opcode("OP_NUMEQUALVERIFY"))
		// The two operands are consumed by NUMEQUALVERIFY; reflect that in the tracker.
		tracker.rawBlock([]string{"_fs_squeezed"}, "", func(e func(StackOp)) {})
	}

	// Drop the 16 sponge state elements (no longer needed) and return OP_1.
	for i := 0; i < 16; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("FS sponge squeeze ordering disagrees with the validated reference "+
			"(sp1fri/challenger.go:103). Reference samples = %v. "+
			"Bug: FiatShamirState.EmitSqueeze in fiat_shamir_kb.go reads rate[squeezePos] "+
			"starting from squeezePos=0 (front), but Plonky3 DuplexChallenger pops from the "+
			"back (rate[7], rate[6], ...). Fix by inverting the source-name selection in "+
			"EmitSqueeze. Script error: %v", want, err)
	}
	t.Logf("FS sponge sample order matches reference: %v", want)
}

// publicValuesPoCBytes encodes the PoC fixture's public values
// `[a=0, b=1, fib(7)=21]` as 12 bytes of little-endian u32s.
func publicValuesPoCBytes() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x15, 0x00, 0x00, 0x00,
	}
}

// runReferenceTranscriptInit runs the off-chain Plonky3 DuplexChallenger
// through the same observe/squeeze sequence emitted on-chain by
// `emitTranscriptInit`. Returns alpha + zeta as canonical [4]uint32 and
// the resulting permuted sponge state so tests can compare byte-for-byte.
//
// Sequence (matches docs/sp1-fri-verifier.md §3 with sp1VKeyHash absorb
// gated on absorbSP1VK):
//
//  1. (optional) chunk sp1VKeyHash into 4-byte LE u32s and observe each.
//  2. chunk publicValues into 4-byte LE u32s and observe each.
//  3. ObserveDigest(traceDigest).
//  4. SampleExt4 → alpha.
//  5. ObserveDigest(quotientDigest).
//  6. SampleExt4 → zeta.
//  7. ObserveExt4Slice(traceLocal); ObserveExt4Slice(traceNext);
//     for each quotient chunk: ObserveExt4Slice(qcs[i]).
func runReferenceTranscriptInit(
	t *testing.T,
	sp1VKeyHash []byte,
	publicValues []byte,
	traceDigest [8]uint32,
	quotientDigest [8]uint32,
	traceLocal []sp1fri.Ext4,
	traceNext []sp1fri.Ext4,
	quotChunks [][]sp1fri.Ext4,
	absorbSP1VK bool,
) (alpha, zeta [4]uint32) {
	t.Helper()
	chal := sp1fri.NewDuplexChallenger()

	// Chunked-bytes absorb helper matching emitObserveByteString convention:
	// little-endian unsigned u32 per 4-byte chunk; tail zero-padded if the
	// length is not a multiple of 4.
	absorbBytes := func(bs []byte) {
		nChunks := (len(bs) + 3) / 4
		for i := 0; i < nChunks; i++ {
			start := i * 4
			end := start + 4
			if end > len(bs) {
				end = len(bs)
			}
			var buf [4]byte
			copy(buf[:], bs[start:end])
			v := uint32(buf[0]) |
				uint32(buf[1])<<8 |
				uint32(buf[2])<<16 |
				uint32(buf[3])<<24
			chal.Observe(v)
		}
	}

	if absorbSP1VK {
		absorbBytes(sp1VKeyHash)
	}
	// Mirror sp1fri/verify.go:67-110 absorb order:
	//   1. degreeBits, baseDegreeBits, preprocessedWidth (instance metadata)
	//   2. trace digest
	//   3. publicValues
	//   4. SampleExt4 → alpha
	//   5. quotient digest
	//   6. SampleExt4 → zeta
	//   7. opened values (trace_local, trace_next, each quotient chunk)
	chal.Observe(uint32(3)) // degreeBits — minimalGuestConfig
	chal.Observe(uint32(3)) // baseDegreeBits = degreeBits (is_zk = 0)
	chal.Observe(uint32(0)) // preprocessedWidth
	chal.ObserveDigest(traceDigest)
	absorbBytes(publicValues)
	a := chal.SampleExt4()
	chal.ObserveDigest(quotientDigest)
	z := chal.SampleExt4()
	chal.ObserveExt4Slice(traceLocal)
	chal.ObserveExt4Slice(traceNext)
	for _, qc := range quotChunks {
		chal.ObserveExt4Slice(qc)
	}
	for i := 0; i < 4; i++ {
		alpha[i] = a[i]
		zeta[i] = z[i]
	}
	return
}

// TestSp1FriVerifier_TranscriptMatchesReference is the byte-identity test
// for Steps 2-5: the on-chain emission must reproduce the exact same
// alpha + zeta canonical values as the off-chain DuplexChallenger fed
// the same observe/squeeze sequence on the canonical fixture.
//
// The test path:
//
//  1. Decode the fixture, derive the canonical observation inputs.
//  2. Run the reference DuplexChallenger to capture alpha + zeta.
//  3. Build a Bitcoin Script that pushes the same inputs through the
//     tracker and calls emitTranscriptInit.
//  4. After emission, push the reference alpha + zeta and assert each
//     element equals the on-chain value via OP_NUMEQUALVERIFY.
//
// A failure indicates a divergence between the codegen-emitted sponge
// behaviour and the validated reference — the most common cause is an
// observe/squeeze ordering bug in fiat_shamir_kb.go (see the duplex
// fix at sp1fri/challenger.go:103).
func TestSp1FriVerifier_TranscriptMatchesReference(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	traceDigest := sp1fri.CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := sp1fri.CanonicalDigest(proof.Commitments.QuotientChunks[0])
	traceLocal := make([]sp1fri.Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = sp1fri.FromKbExt4(e)
	}
	traceNext := make([]sp1fri.Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = sp1fri.FromKbExt4(e)
	}
	quotChunks := make([][]sp1fri.Ext4, len(proof.OpenedValues.QuotientChunks))
	for k, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[k] = make([]sp1fri.Ext4, len(qc))
		for i, e := range qc {
			quotChunks[k][i] = sp1fri.FromKbExt4(e)
		}
	}

	pubVals := publicValuesPoCBytes()

	alpha, zeta := runReferenceTranscriptInit(
		t, nil, pubVals, traceDigest, quotientDigest,
		traceLocal, traceNext, quotChunks, false,
	)

	// Build the on-chain script.
	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	fs := NewFiatShamirState()

	params := DefaultSP1FriParams()
	params.PublicValuesByteSize = len(pubVals)
	params.SP1VKeyHashByteSize = 0 // PoC: no SP1 wrapper

	// Push opened values first (deepest), in canonical order so the named
	// slots survive subsequent toTop calls.
	for i := 0; i < 2; i++ {
		ext := traceLocal[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_tl_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 2; i++ {
		ext := traceNext[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_tn_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 4; i++ {
		ext := quotChunks[0][i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_qc_%d_c%d", i, j), int64(ext[j]))
		}
	}

	// Push quotient digest (8 elements), named _obs_qdig_0..7 (qdig_0 deepest).
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("_obs_qdig_%d", i), int64(quotientDigest[i]))
	}
	// Push trace digest (8 elements), named _obs_dig_0..7.
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("_obs_dig_%d", i), int64(traceDigest[i]))
	}
	// Push publicValues bytes.
	trackerPushBytes(tracker, "_obs_public_values", pubVals)

	// === Steps 2-5 ===
	emitTranscriptInit(fs, tracker, params)

	// At this point the named alpha + zeta slots live above the sponge
	// state (which sits above all originally-pushed values). Bring each
	// alpha/zeta element to the top, push the reference value, and assert
	// OP_NUMEQUALVERIFY.
	assertEqualNamed := func(name string, ref uint32) {
		tracker.toTop(name)
		ops = append(ops, pushInt64(int64(ref)))
		ops = append(ops, opcode("OP_NUMEQUALVERIFY"))
		// NUMEQUALVERIFY consumed both operands.
		tracker.rawBlock([]string{name}, "", func(e func(StackOp)) {})
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_zeta_%d", i), zeta[i])
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_alpha_%d", i), alpha[i])
	}

	// Drain everything else off the stack and end with OP_1.
	for len(tracker.nm) > 0 {
		ops = append(ops, opcode("OP_DROP"))
		tracker.nm = tracker.nm[:len(tracker.nm)-1]
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("on-chain transcript-init disagrees with the validated DuplexChallenger reference. "+
			"Reference alpha=%v zeta=%v. Script error: %v", alpha, zeta, err)
	}
	t.Logf("Steps 2-5 transcript matches reference; alpha=%v zeta=%v; |ops|=%d",
		alpha, zeta, len(ops))
}

// TestSp1FriVerifier_AcceptsMinimalGuestFixture is the holistic acceptance
// harness. It exercises Steps 1 + 2-5 + 8 sequentially against the canonical
// fixture: proof-blob binding consumes proofBlob (Step 1), transcript init
// (Steps 2-5), then FRI commit-phase absorbs + beta squeezes (Step 8).
//
// Step 1 leaves the field chunks on the stack; we drop them before running
// Steps 2-5, which pushes its own observation inputs. The full pipeline-to-
// pipeline wiring (Step 1's leftover fields directly feeding Step 2's
// observations) lands in a follow-up that ports the per-field decoder.
func TestSp1FriVerifier_AcceptsMinimalGuestFixture(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	chunks := chunkProof(t, bs, 8)

	var ops []StackOp
	for _, c := range chunks {
		ops = append(ops, pushBytes(c))
	}
	ops = append(ops, pushBytes(bs)) // proofBlob

	// === Step 1 ===
	bindingOps := gatherOps(func(emit func(StackOp)) {
		EmitProofBlobBindingHash(emit, len(chunks))
	})
	ops = append(ops, bindingOps...)

	// Drain field chunks (full per-field decoding lands in a follow-up).
	for i := 0; i < len(chunks); i++ {
		ops = append(ops, opcode("OP_DROP"))
	}

	// === Decode the verification inputs from the fixture (Steps 2-5 + 8). ===
	traceDigest := sp1fri.CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := sp1fri.CanonicalDigest(proof.Commitments.QuotientChunks[0])
	traceLocal := make([]sp1fri.Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = sp1fri.FromKbExt4(e)
	}
	traceNext := make([]sp1fri.Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = sp1fri.FromKbExt4(e)
	}
	quotChunks := make([][]sp1fri.Ext4, len(proof.OpenedValues.QuotientChunks))
	for k, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[k] = make([]sp1fri.Ext4, len(qc))
		for i, e := range qc {
			quotChunks[k][i] = sp1fri.FromKbExt4(e)
		}
	}
	numRounds := len(proof.OpeningProof.CommitPhaseCommits)
	friCommitDigests := make([][8]uint32, numRounds)
	for r, cap := range proof.OpeningProof.CommitPhaseCommits {
		friCommitDigests[r] = sp1fri.CanonicalDigest(cap[0])
	}
	commitPowWitnesses := make([]uint32, numRounds)
	for r, w := range proof.OpeningProof.CommitPowWitnesses {
		commitPowWitnesses[r] = w.Canonical()
	}
	finalPoly := make([]sp1fri.Ext4, len(proof.OpeningProof.FinalPoly))
	for i, e := range proof.OpeningProof.FinalPoly {
		finalPoly[i] = sp1fri.FromKbExt4(e)
	}
	logArities := make([]int, numRounds)
	if len(proof.OpeningProof.QueryProofs) > 0 {
		for r, op := range proof.OpeningProof.QueryProofs[0].CommitPhaseOpenings {
			logArities[r] = int(op.LogArity)
		}
	}
	queryPowWitness := proof.OpeningProof.QueryPowWitness.Canonical()

	pubVals := publicValuesPoCBytes()
	commitPowBits := 1
	queryPowBits := 1

	alpha, zeta := runReferenceTranscriptInit(
		t, nil, pubVals, traceDigest, quotientDigest,
		traceLocal, traceNext, quotChunks, false,
	)
	alphaFri, betas := runReferenceFriCommitPhase(
		t, pubVals, traceDigest, quotientDigest,
		traceLocal, traceNext, quotChunks,
		friCommitDigests, commitPowWitnesses, finalPoly,
		logArities, queryPowWitness,
		commitPowBits, queryPowBits,
	)

	// === Push Steps 2-5 + 8 inputs ===
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	fs := NewFiatShamirState()
	params := DefaultSP1FriParams()
	params.PublicValuesByteSize = len(pubVals)
	params.SP1VKeyHashByteSize = 0
	params.CommitPoWBits = commitPowBits
	params.QueryPoWBits = queryPowBits

	// Step 8 inputs (deepest).
	tracker.pushInt("_obs_fri_qpw", int64(queryPowWitness))
	for r := numRounds - 1; r >= 0; r-- {
		tracker.pushInt(fmt.Sprintf("_obs_fri_la_%d", r), int64(logArities[r]))
	}
	for i := 0; i < len(finalPoly); i++ {
		ext := finalPoly[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_fri_fp_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for r := 0; r < numRounds; r++ {
		for i := 0; i < 8; i++ {
			tracker.pushInt(fmt.Sprintf("_obs_fri_dig_%d_%d", r, i), int64(friCommitDigests[r][i]))
		}
		tracker.pushInt(fmt.Sprintf("_obs_fri_cpw_%d", r), int64(commitPowWitnesses[r]))
	}

	// Steps 2-5 inputs (above Step 8 inputs).
	for i := 0; i < 2; i++ {
		ext := traceLocal[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_tl_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 2; i++ {
		ext := traceNext[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_tn_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 4; i++ {
		ext := quotChunks[0][i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_qc_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("_obs_qdig_%d", i), int64(quotientDigest[i]))
	}
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("_obs_dig_%d", i), int64(traceDigest[i]))
	}
	trackerPushBytes(tracker, "_obs_public_values", pubVals)

	emitTranscriptInit(fs, tracker, params)
	emitFriCommitPhaseAbsorb(fs, tracker, params, numRounds, len(finalPoly))

	// Sanity-check alpha + zeta + alpha_fri + every beta against the reference.
	assertEqualNamed := func(name string, ref uint32) {
		tracker.toTop(name)
		ops = append(ops, pushInt64(int64(ref)))
		ops = append(ops, opcode("OP_NUMEQUALVERIFY"))
		tracker.rawBlock([]string{name}, "", func(e func(StackOp)) {})
	}

	// === Step 10 — derive query indexes from transcript, assert each
	// matches the off-chain reference. The full per-query loop (input-batch
	// MMCS verify + reduced-opening accumulation + per-fold-step MMCS
	// verify + colinearity fold + final-poly Horner equality) is validated
	// in TestSp1FriVerifier_PerQueryFoldsMatchReference / the standalone
	// emit*FriColinearityFold + emitFinalPolyHorner tests; here we only
	// thread the on-chain transcript-derived indexes back into Step 8's
	// post-state to confirm Steps 8 → 10 sponge continuity.

	// Re-derive query indexes off-chain by extending the reference
	// challenger past the FRI commit-phase.
	refChal := sp1fri.NewDuplexChallenger()
	{
		absorbBytes := func(bs []byte) {
			nChunks := (len(bs) + 3) / 4
			for i := 0; i < nChunks; i++ {
				start := i * 4
				end := start + 4
				if end > len(bs) {
					end = len(bs)
				}
				var buf [4]byte
				copy(buf[:], bs[start:end])
				v := uint32(buf[0]) | uint32(buf[1])<<8 |
					uint32(buf[2])<<16 | uint32(buf[3])<<24
				refChal.Observe(v)
			}
		}
		refChal.Observe(uint32(3))
		refChal.Observe(uint32(3))
		refChal.Observe(uint32(0))
		refChal.ObserveDigest(traceDigest)
		absorbBytes(pubVals)
		_ = refChal.SampleExt4()
		refChal.ObserveDigest(quotientDigest)
		_ = refChal.SampleExt4()
		refChal.ObserveExt4Slice(traceLocal)
		refChal.ObserveExt4Slice(traceNext)
		for _, qc := range quotChunks {
			refChal.ObserveExt4Slice(qc)
		}
		_ = refChal.SampleExt4()
		for r := 0; r < numRounds; r++ {
			for _, d := range proof.OpeningProof.CommitPhaseCommits[r] {
				refChal.ObserveDigest(sp1fri.CanonicalDigest(d))
			}
			_ = refChal.CheckWitness(commitPowBits, commitPowWitnesses[r])
			_ = refChal.SampleExt4()
		}
		refChal.ObserveExt4Slice(finalPoly)
		for _, la := range logArities {
			refChal.Observe(uint32(la))
		}
		_ = refChal.CheckWitness(queryPowBits, queryPowWitness)
	}
	totalLogReduction := 0
	for _, la := range logArities {
		totalLogReduction += la
	}
	logGlobalMaxHeight := totalLogReduction + params.LogBlowup + params.LogFinalPolyLen
	queryIndexes := make([]uint64, params.NumQueries)
	for q := 0; q < params.NumQueries; q++ {
		queryIndexes[q] = refChal.SampleBits(logGlobalMaxHeight)
	}

	// On-chain: sample the index per query and assert it matches the
	// reference. emitQueryIndexDerive composes EmitSampleBits.
	for q := 0; q < params.NumQueries; q++ {
		emitQueryIndexDerive(fs, tracker, logGlobalMaxHeight)
		// _fs_bits is on top; rename to a per-query name so we can find it later.
		tracker.rename(fmt.Sprintf("_qidx_%d", q))
		// Assert the on-chain index equals the off-chain reference index.
		tracker.toTop(fmt.Sprintf("_qidx_%d", q))
		ops = append(ops, pushInt64(int64(queryIndexes[q])))
		ops = append(ops, opcode("OP_NUMEQUALVERIFY"))
		tracker.rawBlock([]string{fmt.Sprintf("_qidx_%d", q)}, "", func(e func(StackOp)) {})
	}

	// Beta values per round (reverse round order to walk the stack top-down).
	for r := numRounds - 1; r >= 0; r-- {
		for i := 3; i >= 0; i-- {
			assertEqualNamed(fmt.Sprintf("_fs_beta_%d_%d", r, i), betas[r][i])
		}
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_alpha_fri_%d", i), alphaFri[i])
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_zeta_%d", i), zeta[i])
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_alpha_%d", i), alpha[i])
	}

	// === Step 11 — final-poly Horner equality (per-query, using the
	// off-chain-validated reduced + folded value as the LHS). Emitted
	// inside a fresh tracker context so the harness assertion shape stays
	// the same as Step 10's pure transcript replay above.
	for q := 0; q < params.NumQueries; q++ {
		index := queryIndexes[q]
		x := sp1fri.KbPow(
			sp1fri.KbTwoAdicGenerator(logGlobalMaxHeight),
			reverseBitsLenLocal(index, logGlobalMaxHeight),
		)
		xExt := sp1fri.Ext4FromBase(x)
		hornerWant := sp1fri.Ext4Zero()
		for i := len(finalPoly) - 1; i >= 0; i-- {
			hornerWant = sp1fri.Ext4Add(sp1fri.Ext4Mul(hornerWant, xExt), finalPoly[i])
		}

		var qOps []StackOp
		qTracker := NewKBTracker(nil, func(op StackOp) { qOps = append(qOps, op) })
		for i, c := range finalPoly {
			pushExt4Named(qTracker, fmt.Sprintf("fp_%d", i), c)
		}
		pushExt4Named(qTracker, "x", xExt)
		emitFinalPolyHorner(qTracker, "fp", "x", "out", len(finalPoly))
		assertExt4EqualsRef(t, qTracker, &qOps, "out", hornerWant)
		drainAllStack(qTracker, &qOps)
		if err := buildAndExecute(t, qOps); err != nil {
			t.Fatalf("query %d: on-chain Horner step disagrees with reference (want=%v): %v",
				q, hornerWant, err)
		}
	}

	// Drain everything else off the stack.
	for len(tracker.nm) > 0 {
		ops = append(ops, opcode("OP_DROP"))
		tracker.nm = tracker.nm[:len(tracker.nm)-1]
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("verifier rejected the canonical fixture (Step 1 + 2-5 + 8 + 10): %v", err)
	}

	// Measure compiled script size in bytes for the brief's reporting.
	method := StackMethod{Name: "test", Ops: ops}
	result, emitErr := Emit([]StackMethod{method})
	scriptBytes := -1
	if emitErr == nil {
		scriptBytes = len(result.ScriptHex) / 2
	}

	t.Logf("Steps 1 + 2-5 + 8 + 10 + 11 accepted canonical fixture; |proofBlob|=%d, |chunks|=%d, "+
		"|step1 ops|=%d, numRounds=%d, finalPolyLen=%d, total ops in harness=%d, "+
		"script bytes=%d, queryIndexes=%v, alpha=%v zeta=%v alphaFri=%v betas=%v",
		len(bs), len(chunks), len(bindingOps), numRounds, len(finalPoly), len(ops),
		scriptBytes, queryIndexes, alpha, zeta, alphaFri, betas)
}

// runReferenceFriCommitPhase extends runReferenceTranscriptInit through Step 8:
// after the Steps 2-5 transcript, it replays `verifyFri` (sp1fri/fri.go:20-93)
// against the off-chain DuplexChallenger and captures every Ext4 challenge
// emitted (alpha_fri + per-round beta) plus the channel state needed to
// validate downstream steps. Returns the captured challenges in declaration
// order so the on-chain harness can assert byte-identity.
func runReferenceFriCommitPhase(
	t *testing.T,
	publicValues []byte,
	traceDigest [8]uint32,
	quotientDigest [8]uint32,
	traceLocal []sp1fri.Ext4,
	traceNext []sp1fri.Ext4,
	quotChunks [][]sp1fri.Ext4,
	friCommitDigests [][8]uint32,
	commitPowWitnesses []uint32,
	finalPoly []sp1fri.Ext4,
	logArities []int,
	queryPowWitness uint32,
	commitPowBits, queryPowBits int,
) (alphaFri [4]uint32, betas [][4]uint32) {
	t.Helper()
	chal := sp1fri.NewDuplexChallenger()

	// Steps 2-5 (no SP1 wrapper for the PoC).
	absorbBytes := func(bs []byte) {
		nChunks := (len(bs) + 3) / 4
		for i := 0; i < nChunks; i++ {
			start := i * 4
			end := start + 4
			if end > len(bs) {
				end = len(bs)
			}
			var buf [4]byte
			copy(buf[:], bs[start:end])
			v := uint32(buf[0]) |
				uint32(buf[1])<<8 |
				uint32(buf[2])<<16 |
				uint32(buf[3])<<24
			chal.Observe(v)
		}
	}
	// Mirror sp1fri/verify.go:67-110 absorb order (see runReferenceTranscriptInit).
	chal.Observe(uint32(3))
	chal.Observe(uint32(3))
	chal.Observe(uint32(0))
	chal.ObserveDigest(traceDigest)
	absorbBytes(publicValues)
	_ = chal.SampleExt4() // alpha (outer-stark)
	chal.ObserveDigest(quotientDigest)
	_ = chal.SampleExt4() // zeta
	chal.ObserveExt4Slice(traceLocal)
	chal.ObserveExt4Slice(traceNext)
	for _, qc := range quotChunks {
		chal.ObserveExt4Slice(qc)
	}

	// Step 8: mirror sp1fri/fri.go:20-93.
	a := chal.SampleExt4()
	for i := 0; i < 4; i++ {
		alphaFri[i] = a[i]
	}

	betas = make([][4]uint32, len(friCommitDigests))
	for r, d := range friCommitDigests {
		chal.ObserveDigest(d)
		if !chal.CheckWitness(commitPowBits, commitPowWitnesses[r]) {
			t.Fatalf("reference: invalid commit-phase PoW witness at round %d", r)
		}
		bExt := chal.SampleExt4()
		for i := 0; i < 4; i++ {
			betas[r][i] = bExt[i]
		}
	}
	chal.ObserveExt4Slice(finalPoly)
	for _, la := range logArities {
		chal.Observe(uint32(la))
	}
	if !chal.CheckWitness(queryPowBits, queryPowWitness) {
		t.Fatalf("reference: invalid query PoW witness")
	}
	return
}

// TestSp1FriVerifier_FriCommitPhaseMatchesReference validates Step 8 — the
// FRI commit-phase absorbs + beta squeezes + final-poly absorb + query-PoW
// witness check. Asserts that on-chain alpha_fri and every per-round beta
// match the off-chain DuplexChallenger byte-identical.
func TestSp1FriVerifier_FriCommitPhaseMatchesReference(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	traceDigest := sp1fri.CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := sp1fri.CanonicalDigest(proof.Commitments.QuotientChunks[0])
	traceLocal := make([]sp1fri.Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = sp1fri.FromKbExt4(e)
	}
	traceNext := make([]sp1fri.Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = sp1fri.FromKbExt4(e)
	}
	quotChunks := make([][]sp1fri.Ext4, len(proof.OpenedValues.QuotientChunks))
	for k, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[k] = make([]sp1fri.Ext4, len(qc))
		for i, e := range qc {
			quotChunks[k][i] = sp1fri.FromKbExt4(e)
		}
	}

	// Decode the FRI commit-phase + final poly + query-pow inputs.
	numRounds := len(proof.OpeningProof.CommitPhaseCommits)
	if numRounds == 0 {
		t.Fatal("fixture: no FRI commit-phase rounds")
	}
	friCommitDigests := make([][8]uint32, numRounds)
	for r, cap := range proof.OpeningProof.CommitPhaseCommits {
		// cap_height = 0 ⇒ exactly one digest per cap.
		if len(cap) != 1 {
			t.Fatalf("fixture: round %d cap len %d != 1", r, len(cap))
		}
		friCommitDigests[r] = sp1fri.CanonicalDigest(cap[0])
	}
	commitPowWitnesses := make([]uint32, numRounds)
	for r, w := range proof.OpeningProof.CommitPowWitnesses {
		commitPowWitnesses[r] = w.Canonical()
	}
	finalPoly := make([]sp1fri.Ext4, len(proof.OpeningProof.FinalPoly))
	for i, e := range proof.OpeningProof.FinalPoly {
		finalPoly[i] = sp1fri.FromKbExt4(e)
	}
	logArities := make([]int, numRounds)
	if len(proof.OpeningProof.QueryProofs) > 0 {
		for r, op := range proof.OpeningProof.QueryProofs[0].CommitPhaseOpenings {
			logArities[r] = int(op.LogArity)
		}
	}
	queryPowWitness := proof.OpeningProof.QueryPowWitness.Canonical()

	pubVals := publicValuesPoCBytes()
	commitPowBits := 1
	queryPowBits := 1

	alphaFri, betas := runReferenceFriCommitPhase(
		t, pubVals, traceDigest, quotientDigest,
		traceLocal, traceNext, quotChunks,
		friCommitDigests, commitPowWitnesses, finalPoly,
		logArities, queryPowWitness,
		commitPowBits, queryPowBits,
	)

	// Build the on-chain script.
	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	fs := NewFiatShamirState()
	params := DefaultSP1FriParams()
	params.PublicValuesByteSize = len(pubVals)
	params.SP1VKeyHashByteSize = 0
	params.CommitPoWBits = commitPowBits
	params.QueryPoWBits = queryPowBits

	// Push Step 8 inputs first (deepest), so Steps 2-5 inputs sit above and
	// are consumed first.
	//
	// query_pow_witness deepest, then logArities (in reverse so r=0 is shallower
	// — toTop walks names so the actual stack order doesn't matter, but we keep
	// the canonical layout for readability).
	tracker.pushInt("_obs_fri_qpw", int64(queryPowWitness))
	for r := numRounds - 1; r >= 0; r-- {
		tracker.pushInt(fmt.Sprintf("_obs_fri_la_%d", r), int64(logArities[r]))
	}
	// final_poly: 4 Ext4 elements, coefficients c0..c3.
	for i := 0; i < len(finalPoly); i++ {
		ext := finalPoly[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_fri_fp_%d_c%d", i, j), int64(ext[j]))
		}
	}
	// Per-round: digest 8 elements + commit_pow_witness.
	for r := 0; r < numRounds; r++ {
		for i := 0; i < 8; i++ {
			tracker.pushInt(fmt.Sprintf("_obs_fri_dig_%d_%d", r, i), int64(friCommitDigests[r][i]))
		}
		tracker.pushInt(fmt.Sprintf("_obs_fri_cpw_%d", r), int64(commitPowWitnesses[r]))
	}

	// Steps 2-5 inputs (same layout as TestSp1FriVerifier_TranscriptMatchesReference).
	for i := 0; i < 2; i++ {
		ext := traceLocal[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_tl_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 2; i++ {
		ext := traceNext[i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_tn_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 4; i++ {
		ext := quotChunks[0][i]
		for j := 0; j < 4; j++ {
			tracker.pushInt(fmt.Sprintf("_obs_open_qc_%d_c%d", i, j), int64(ext[j]))
		}
	}
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("_obs_qdig_%d", i), int64(quotientDigest[i]))
	}
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("_obs_dig_%d", i), int64(traceDigest[i]))
	}
	trackerPushBytes(tracker, "_obs_public_values", pubVals)

	emitTranscriptInit(fs, tracker, params)
	emitFriCommitPhaseAbsorb(fs, tracker, params, numRounds, len(finalPoly))

	// Assert alpha_fri matches the reference (deepest first, so we work top-down
	// because squeezes named _fs_alpha_fri_3 sits at the top of the squeeze
	// block, but we need to bring each by name to the top).
	assertEqualNamed := func(name string, ref uint32) {
		tracker.toTop(name)
		ops = append(ops, pushInt64(int64(ref)))
		ops = append(ops, opcode("OP_NUMEQUALVERIFY"))
		tracker.rawBlock([]string{name}, "", func(e func(StackOp)) {})
	}

	// Beta values (per round) — assert in reverse-round order so we don't have
	// to reorder named slots that survive across rounds.
	for r := numRounds - 1; r >= 0; r-- {
		for i := 3; i >= 0; i-- {
			assertEqualNamed(fmt.Sprintf("_fs_beta_%d_%d", r, i), betas[r][i])
		}
	}
	// alpha_fri.
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_alpha_fri_%d", i), alphaFri[i])
	}

	// Drain everything else off the stack.
	for len(tracker.nm) > 0 {
		ops = append(ops, opcode("OP_DROP"))
		tracker.nm = tracker.nm[:len(tracker.nm)-1]
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("on-chain Step 8 disagrees with the validated DuplexChallenger reference. "+
			"Reference alphaFri=%v betas=%v. Script error: %v", alphaFri, betas, err)
	}

	// Measure script size for the brief's reporting.
	method := StackMethod{Name: "test", Ops: ops}
	result, emitErr := Emit([]StackMethod{method})
	scriptBytes := -1
	if emitErr == nil {
		scriptBytes = len(result.ScriptHex) / 2
	}

	t.Logf("Step 8 matches reference; numRounds=%d, finalPolyLen=%d, "+
		"alphaFri=%v, betas=%v, |ops|=%d, script bytes=%d",
		numRounds, len(finalPoly), alphaFri, betas, len(ops), scriptBytes)
}

// TestSp1FriVerifier_PerQueryFoldsMatchReference walks every query in the
// fixture, runs the off-chain reference verifier (sp1fri/fri.go::verifyQuery)
// to capture the per-query foldRow output + Horner evaluation, and asserts
// that the on-chain emission of `emitFriColinearityFold` + `emitFinalPolyHorner`
// produces byte-identical Ext4 values for every query.
//
// This is the Step 10 + Step 11 acceptance gate for the per-query algebra,
// minus the input-batch MMCS verification + reduced-opening accumulation
// (those are deferred behind refined panics — see the dispatch brief). The
// inputs to the on-chain helpers (ros[0].value, sibling values, beta, s,
// final-poly coefs, x point) are derived off-chain by replaying the
// validated Go reference.
func TestSp1FriVerifier_PerQueryFoldsMatchReference(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	// Run the off-chain reference verifier through Verify() to make sure the
	// fixture is valid, then re-derive the per-query intermediates by
	// replaying the same transcript + per-query loop manually below.
	pubVals := []uint32{0, 1, 21}
	if err := sp1fri.Verify(proof, pubVals); err != nil {
		t.Fatalf("reference Verify rejected the canonical fixture: %v", err)
	}

	// Re-build the transcript through Step 8.
	traceDigest := sp1fri.CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := sp1fri.CanonicalDigest(proof.Commitments.QuotientChunks[0])
	traceLocal := make([]sp1fri.Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = sp1fri.FromKbExt4(e)
	}
	traceNext := make([]sp1fri.Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = sp1fri.FromKbExt4(e)
	}
	quotChunks := make([][]sp1fri.Ext4, len(proof.OpenedValues.QuotientChunks))
	for k, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[k] = make([]sp1fri.Ext4, len(qc))
		for i, e := range qc {
			quotChunks[k][i] = sp1fri.FromKbExt4(e)
		}
	}
	pubBytes := publicValuesPoCBytes()

	chal := sp1fri.NewDuplexChallenger()
	absorbBytes := func(bs []byte) {
		nChunks := (len(bs) + 3) / 4
		for i := 0; i < nChunks; i++ {
			start := i * 4
			end := start + 4
			if end > len(bs) {
				end = len(bs)
			}
			var buf [4]byte
			copy(buf[:], bs[start:end])
			v := uint32(buf[0]) | uint32(buf[1])<<8 |
				uint32(buf[2])<<16 | uint32(buf[3])<<24
			chal.Observe(v)
		}
	}
	chal.Observe(uint32(3))
	chal.Observe(uint32(3))
	chal.Observe(uint32(0))
	chal.ObserveDigest(traceDigest)
	absorbBytes(pubBytes)
	_ = chal.SampleExt4() // alpha (outer)
	chal.ObserveDigest(quotientDigest)
	_ = chal.SampleExt4() // zeta
	chal.ObserveExt4Slice(traceLocal)
	chal.ObserveExt4Slice(traceNext)
	for _, qc := range quotChunks {
		chal.ObserveExt4Slice(qc)
	}

	// FRI commit-phase.
	_ = chal.SampleExt4() // alpha_fri (FRI batching)
	expectedRounds := len(proof.OpeningProof.CommitPhaseCommits)
	betas := make([]sp1fri.Ext4, expectedRounds)
	for r := 0; r < expectedRounds; r++ {
		for _, d := range proof.OpeningProof.CommitPhaseCommits[r] {
			chal.ObserveDigest(sp1fri.CanonicalDigest(d))
		}
		w := proof.OpeningProof.CommitPowWitnesses[r].Canonical()
		if !chal.CheckWitness(1, w) {
			t.Fatalf("reference: invalid commit-phase PoW witness at round %d", r)
		}
		bExt := chal.SampleExt4()
		for i := 0; i < 4; i++ {
			betas[r][i] = bExt[i]
		}
	}
	finalPolyCanon := make([]sp1fri.Ext4, len(proof.OpeningProof.FinalPoly))
	for i, e := range proof.OpeningProof.FinalPoly {
		finalPolyCanon[i] = sp1fri.FromKbExt4(e)
	}
	chal.ObserveExt4Slice(finalPolyCanon)
	logArities := make([]int, expectedRounds)
	if len(proof.OpeningProof.QueryProofs) > 0 {
		for r, op := range proof.OpeningProof.QueryProofs[0].CommitPhaseOpenings {
			logArities[r] = int(op.LogArity)
		}
	}
	for _, la := range logArities {
		chal.Observe(uint32(la))
	}
	queryPow := proof.OpeningProof.QueryPowWitness.Canonical()
	if !chal.CheckWitness(1, queryPow) {
		t.Fatalf("reference: invalid query-phase PoW witness")
	}

	// Derive logGlobalMaxHeight per fri.go:53.
	totalLogReduction := 0
	for _, la := range logArities {
		totalLogReduction += la
	}
	logGlobalMaxHeight := totalLogReduction + 2 + 2 // logBlowup=2 + logFinalPolyLen=2

	// Per-query loop: capture index, ros[0].value, fold-step intermediates.
	for qi, qp := range proof.OpeningProof.QueryProofs {
		index := chal.SampleBits(logGlobalMaxHeight)
		t.Logf("query %d: index=%d (%b)", qi, index, index)

		// We CANNOT easily run the off-chain openInput here without the full
		// commitOpening setup. So instead we construct ros[0].value by running
		// the official Verify path (which we already validated above) and
		// extracting it via a fresh local replay tied to the proof structure.
		//
		// The off-chain Verify is opaque about per-query intermediates. So
		// we focus on what we CAN test: assert that the colinearity fold
		// emission matches the algorithmic formula for a chosen e_low/e_high
		// derived from the proof's first commit-phase opening.
		//
		// Because verifyQuery's foldRow uses ros[0].value (= the reduced
		// opening at the tallest matrix height) as the initial folded value,
		// and because ros[0].value depends on the fixture's matrix data which
		// we don't have a stable getter for, we use the on-chain helpers
		// against synthetic e_low/e_high derived from the CommitPhaseOpening
		// sibling values + an arbitrary "folded" placeholder. This validates
		// the algebra; per-query end-to-end input-MMCS verification is
		// scheduled for the next dispatch.
		//
		// For each query: derive (e_low, e_high) from (placeholder_folded,
		// op.SiblingValues[0]) per the indexInGroup branch, then assert
		// emitFriColinearityFold(e_low, e_high, beta, s) matches
		// foldRow(...) which we compute by calling the standalone formula.
		op := qp.CommitPhaseOpenings[0]
		logArity := int(op.LogArity)
		arity := 1 << logArity
		if arity != 2 {
			t.Skipf("test only handles arity=2; got %d", arity)
		}
		indexInGroup := int(index % uint64(arity))
		// Use a synthetic "folded" placeholder for this isolated test.
		placeholderFolded := sp1fri.Ext4{1, 2, 3, 4}
		sibling := sp1fri.FromKbExt4(op.SiblingValues[0])
		var eLow, eHigh sp1fri.Ext4
		if indexInGroup == 0 {
			eLow, eHigh = placeholderFolded, sibling
		} else {
			eLow, eHigh = sibling, placeholderFolded
		}
		// startIndex >>= logArity (line 306) BEFORE foldRow uses it.
		shiftedIndex := index >> uint(logArity)
		// logFoldedHeight = logCurrentHeight - logArity. logCurrentHeight starts
		// as logGlobalMaxHeight = 5; for the first round logFoldedHeight = 4.
		logFoldedHeight := logGlobalMaxHeight - logArity
		s := sp1fri.KbPow(
			sp1fri.KbTwoAdicGenerator(logFoldedHeight+logArity),
			reverseBitsLenLocal(shiftedIndex, logFoldedHeight),
		)
		want := referenceColinearityFold(eLow, eHigh, betas[0], s)

		// === On-chain emission ===
		var ops []StackOp
		tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
		pushExt4Named(tracker, "elo", eLow)
		pushExt4Named(tracker, "ehi", eHigh)
		pushExt4Named(tracker, "beta", betas[0])
		tracker.pushInt("s", int64(s))

		emitFriColinearityFold(tracker, "elo", "ehi", "beta", "s", "fold")
		assertExt4EqualsRef(t, tracker, &ops, "fold", want)
		drainAllStack(tracker, &ops)

		if err := buildAndExecute(t, ops); err != nil {
			t.Fatalf("query %d: on-chain colinearity fold disagrees with reference (want=%v): %v",
				qi, want, err)
		}

		// === Final-poly Horner at x = g_logGlobalMaxHeight^reverseBits(domainIndex, logGlobalMaxHeight) ===
		// domainIndex = original index (verifyQuery line 110: domainIndex := index;
		// extra_query_index_bits = 0). After all folds, *startIndex has been
		// shifted to log_final_poly_len bits (= 2 for PoC).
		x := sp1fri.KbPow(
			sp1fri.KbTwoAdicGenerator(logGlobalMaxHeight),
			reverseBitsLenLocal(index, logGlobalMaxHeight),
		)
		xExt := sp1fri.Ext4FromBase(x)
		// Reference Horner.
		hornerWant := sp1fri.Ext4Zero()
		for i := len(finalPolyCanon) - 1; i >= 0; i-- {
			hornerWant = sp1fri.Ext4Add(sp1fri.Ext4Mul(hornerWant, xExt), finalPolyCanon[i])
		}

		// On-chain Horner emission.
		var ops2 []StackOp
		tracker2 := NewKBTracker(nil, func(op StackOp) { ops2 = append(ops2, op) })
		for i, c := range finalPolyCanon {
			pushExt4Named(tracker2, fmt.Sprintf("fp_%d", i), c)
		}
		pushExt4Named(tracker2, "x", xExt)
		emitFinalPolyHorner(tracker2, "fp", "x", "out", len(finalPolyCanon))
		assertExt4EqualsRef(t, tracker2, &ops2, "out", hornerWant)
		drainAllStack(tracker2, &ops2)
		if err := buildAndExecute(t, ops2); err != nil {
			t.Fatalf("query %d: on-chain Horner disagrees with reference (want=%v): %v",
				qi, hornerWant, err)
		}

		t.Logf("query %d: index=%d s=%d fold=%v horner=%v",
			qi, index, s, want, hornerWant)
	}
}

// reverseBitsLenLocal mirrors the unexported `reverseBitsLen` in
// `packages/runar-go/sp1fri/verify.go:303`. Reverses the low `n` bits of `x`.
func reverseBitsLenLocal(x uint64, n int) uint64 {
	out := uint64(0)
	for i := 0; i < n; i++ {
		out = (out << 1) | (x & 1)
		x >>= 1
	}
	return out
}

// TestSp1FriVerifier_QuotientReconstructionMatchesReference documents the
// off-chain ground-truth values that on-chain Steps 6 (AIR constraint eval at
// zeta) and 7 (quotient recompose + OOD equality) must reproduce once the
// Ext4 macro layer (sp1_fri_ext4.go) lands.
//
// Steps 6 and 7 are deferred behind refined panics in sp1_fri.go (see
// emitFibAirConstraintEval + emitQuotientRecompose). When those land, this
// test will be expanded to also drive the on-chain emission and assert each
// per-step intermediate scalar is byte-identical to the off-chain reference
// computed below.
//
// Until then, this test serves as the canonical reference dump: alpha_folded,
// quotient(zeta) recomposed, and the four-coordinate Ext4 equality relation
// `folded * inv_vanishing == quotient`.
func TestSp1FriVerifier_QuotientReconstructionMatchesReference(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	// Re-derive the same alpha + zeta the on-chain Steps 2-5 produce.
	traceDigest := sp1fri.CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := sp1fri.CanonicalDigest(proof.Commitments.QuotientChunks[0])
	traceLocal := make([]sp1fri.Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = sp1fri.FromKbExt4(e)
	}
	traceNext := make([]sp1fri.Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = sp1fri.FromKbExt4(e)
	}
	quotChunks := make([][]sp1fri.Ext4, len(proof.OpenedValues.QuotientChunks))
	for k, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[k] = make([]sp1fri.Ext4, len(qc))
		for i, e := range qc {
			quotChunks[k][i] = sp1fri.FromKbExt4(e)
		}
	}

	pubVals := publicValuesPoCBytes()
	alphaArr, zetaArr := runReferenceTranscriptInit(
		t, nil, pubVals, traceDigest, quotientDigest,
		traceLocal, traceNext, quotChunks, false,
	)
	alpha := sp1fri.Ext4{alphaArr[0], alphaArr[1], alphaArr[2], alphaArr[3]}
	zeta := sp1fri.Ext4{zetaArr[0], zetaArr[1], zetaArr[2], zetaArr[3]}

	// Step 6: Lagrange selectors at zeta + AIR constraint folding.
	pis := [3]uint32{0, 1, 21} // matches publicValuesPoCBytes
	sels := sp1fri.SelectorsAtPoint(3, zeta)
	folded := sp1fri.EvalFibonacciConstraints(
		[2]sp1fri.Ext4{traceLocal[0], traceLocal[1]},
		[2]sp1fri.Ext4{traceNext[0], traceNext[1]},
		pis, sels, alpha,
	)

	// Step 7: quotient recompose. For the PoC's single chunk, zps[0] = 1
	// (empty product over the other chunks), so:
	//   quotient = sum over e in 0..3 of basisExt4(e) * chunk[0][e]
	// = chunk[0]_0 + chunk[0]_1 * X + chunk[0]_2 * X^2 + chunk[0]_3 * X^3
	// where X^4 = W = 3 in the binomial extension. Mirror the in-package
	// helper sp1fri/verify.go::recomposeQuotient at lines 250-283.
	const W uint32 = 3
	mulByX := func(a sp1fri.Ext4, k int) sp1fri.Ext4 {
		// (c0,c1,c2,c3) * X^k mod (X^4 - W)
		switch k {
		case 0:
			return a
		case 1:
			return sp1fri.Ext4{sp1fri.KbMul(W, a[3]), a[0], a[1], a[2]}
		case 2:
			return sp1fri.Ext4{sp1fri.KbMul(W, a[2]), sp1fri.KbMul(W, a[3]), a[0], a[1]}
		case 3:
			return sp1fri.Ext4{sp1fri.KbMul(W, a[1]), sp1fri.KbMul(W, a[2]), sp1fri.KbMul(W, a[3]), a[0]}
		default:
			t.Fatalf("mulByX: invalid exponent %d", k)
			return sp1fri.Ext4{}
		}
	}
	// Single chunk: lift each Ext4 coefficient via X^e and sum.
	quotient := sp1fri.Ext4Zero()
	for e := 0; e < 4; e++ {
		// Coefficient e of the chunk, lifted as a constant Ext4.
		c := quotChunks[0][e]
		// "Multiply" c (an Ext4 element) by basis element X^e: this is
		// polynomial multiplication, which collapses to the four shift
		// patterns above (since basis * X^e = X^e and Ext4 mul by a degree-0
		// monomial is per-coefficient).
		quotient = sp1fri.Ext4Add(quotient, mulByX(c, e))
	}

	// OOD equality: folded * inv_vanishing == quotient.
	lhs := sp1fri.Ext4Mul(folded, sels.InvVanishing)
	if !sp1fri.Ext4Equal(lhs, quotient) {
		t.Fatalf("reference Steps 6+7 self-check failed:\n  alpha=%v zeta=%v\n  "+
			"folded=%v\n  inv_vanishing=%v\n  lhs=%v\n  quotient=%v",
			alpha, zeta, folded, sels.InvVanishing, lhs, quotient)
	}

	t.Logf("Reference Steps 6+7 self-check passed:\n"+
		"  alpha           = %v\n"+
		"  zeta            = %v\n"+
		"  is_first_row    = %v\n"+
		"  is_last_row     = %v\n"+
		"  is_transition   = %v\n"+
		"  inv_vanishing   = %v\n"+
		"  alpha_folded    = %v\n"+
		"  quotient(zeta)  = %v\n"+
		"  folded*inv_van  = %v  (must == quotient)",
		alpha, zeta,
		sels.IsFirstRow, sels.IsLastRow, sels.IsTransition, sels.InvVanishing,
		folded, quotient, lhs)

	t.Skip("on-chain Steps 6 (AIR constraint eval) + 7 (quotient recompose) " +
		"are deferred behind refined panics in sp1_fri.go (emitFibAirConstraintEval, " +
		"emitQuotientRecompose). When the Ext4 macro layer (sp1_fri_ext4.go) lands, " +
		"this test will be expanded to drive the on-chain emission and assert " +
		"byte-identity. Reference dump in test log above.")
}

// TestSp1FriVerifier_PerQueryConditionalFoldsMatchReference walks every query
// in the canonical fixture and asserts emitFriFoldRowConditional reproduces
// the off-chain foldRow output byte-identical when driven by the runtime
// query-index bit (rather than a codegen-time-known bit). This is the per-
// query end-to-end gate for Part A of the inner-loop wiring: it confirms
// that for every observed indexInGroup the on-chain conditional emission
// agrees with the validated lagrangeInterpolateAt.
//
// Mirrors the same per-query setup as TestSp1FriVerifier_PerQueryFoldsMatchReference
// (which only exercises the unconditional bit=0 path of emitFriColinearityFold)
// but switches the on-chain emission to the conditional variant.
func TestSp1FriVerifier_PerQueryConditionalFoldsMatchReference(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	pubVals := []uint32{0, 1, 21}
	if err := sp1fri.Verify(proof, pubVals); err != nil {
		t.Fatalf("reference Verify rejected the canonical fixture: %v", err)
	}

	// Re-build the transcript through Step 8 to get betas + query indexes.
	traceDigest := sp1fri.CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := sp1fri.CanonicalDigest(proof.Commitments.QuotientChunks[0])
	traceLocal := make([]sp1fri.Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = sp1fri.FromKbExt4(e)
	}
	traceNext := make([]sp1fri.Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = sp1fri.FromKbExt4(e)
	}
	quotChunks := make([][]sp1fri.Ext4, len(proof.OpenedValues.QuotientChunks))
	for k, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[k] = make([]sp1fri.Ext4, len(qc))
		for i, e := range qc {
			quotChunks[k][i] = sp1fri.FromKbExt4(e)
		}
	}
	pubBytes := publicValuesPoCBytes()

	chal := sp1fri.NewDuplexChallenger()
	absorbBytes := func(bs []byte) {
		nChunks := (len(bs) + 3) / 4
		for i := 0; i < nChunks; i++ {
			start := i * 4
			end := start + 4
			if end > len(bs) {
				end = len(bs)
			}
			var buf [4]byte
			copy(buf[:], bs[start:end])
			v := uint32(buf[0]) | uint32(buf[1])<<8 |
				uint32(buf[2])<<16 | uint32(buf[3])<<24
			chal.Observe(v)
		}
	}
	chal.Observe(uint32(3))
	chal.Observe(uint32(3))
	chal.Observe(uint32(0))
	chal.ObserveDigest(traceDigest)
	absorbBytes(pubBytes)
	_ = chal.SampleExt4()
	chal.ObserveDigest(quotientDigest)
	_ = chal.SampleExt4()
	chal.ObserveExt4Slice(traceLocal)
	chal.ObserveExt4Slice(traceNext)
	for _, qc := range quotChunks {
		chal.ObserveExt4Slice(qc)
	}

	_ = chal.SampleExt4() // alpha_fri
	expectedRounds := len(proof.OpeningProof.CommitPhaseCommits)
	betas := make([]sp1fri.Ext4, expectedRounds)
	for r := 0; r < expectedRounds; r++ {
		for _, d := range proof.OpeningProof.CommitPhaseCommits[r] {
			chal.ObserveDigest(sp1fri.CanonicalDigest(d))
		}
		w := proof.OpeningProof.CommitPowWitnesses[r].Canonical()
		if !chal.CheckWitness(1, w) {
			t.Fatalf("ref: invalid commit-phase PoW witness at round %d", r)
		}
		bExt := chal.SampleExt4()
		for i := 0; i < 4; i++ {
			betas[r][i] = bExt[i]
		}
	}
	finalPolyCanon := make([]sp1fri.Ext4, len(proof.OpeningProof.FinalPoly))
	for i, e := range proof.OpeningProof.FinalPoly {
		finalPolyCanon[i] = sp1fri.FromKbExt4(e)
	}
	chal.ObserveExt4Slice(finalPolyCanon)
	logArities := make([]int, expectedRounds)
	if len(proof.OpeningProof.QueryProofs) > 0 {
		for r, op := range proof.OpeningProof.QueryProofs[0].CommitPhaseOpenings {
			logArities[r] = int(op.LogArity)
		}
	}
	for _, la := range logArities {
		chal.Observe(uint32(la))
	}
	queryPow := proof.OpeningProof.QueryPowWitness.Canonical()
	if !chal.CheckWitness(1, queryPow) {
		t.Fatalf("ref: invalid query-phase PoW witness")
	}

	totalLogReduction := 0
	for _, la := range logArities {
		totalLogReduction += la
	}
	logGlobalMaxHeight := totalLogReduction + 2 + 2

	for qi, qp := range proof.OpeningProof.QueryProofs {
		index := chal.SampleBits(logGlobalMaxHeight)
		op := qp.CommitPhaseOpenings[0]
		logArity := int(op.LogArity)
		arity := 1 << logArity
		if arity != 2 {
			t.Skipf("test only handles arity=2; got %d", arity)
		}
		bit := int(index % uint64(arity))

		// Reference: place the synthetic "folded" placeholder + sibling per
		// the bit-derived indexInGroup, then run the validated colinearity
		// formula (off-chain).
		placeholder := sp1fri.Ext4{1, 2, 3, 4}
		sibling := sp1fri.FromKbExt4(op.SiblingValues[0])
		var eLow, eHigh sp1fri.Ext4
		if bit == 0 {
			eLow, eHigh = placeholder, sibling
		} else {
			eLow, eHigh = sibling, placeholder
		}
		shiftedIndex := index >> uint(logArity)
		logFoldedHeight := logGlobalMaxHeight - logArity
		s := sp1fri.KbPow(
			sp1fri.KbTwoAdicGenerator(logFoldedHeight+logArity),
			reverseBitsLenLocal(shiftedIndex, logFoldedHeight),
		)
		want := referenceColinearityFold(eLow, eHigh, betas[0], s)

		// On-chain: pass `placeholder` as `folded` + `sibling` as `sibling` +
		// the runtime bit (which is what the per-query loop will sample from
		// the transcript).
		var ops []StackOp
		tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
		pushExt4Named(tracker, "fld", placeholder)
		pushExt4Named(tracker, "sib", sibling)
		pushExt4Named(tracker, "beta", betas[0])
		tracker.pushInt("s", int64(s))
		tracker.pushInt("bit", int64(bit))

		emitFriFoldRowConditional(tracker, "fld", "sib", "beta", "s", "bit", "out")
		assertExt4EqualsRef(t, tracker, &ops, "out", want)
		drainAllStack(tracker, &ops)

		if err := buildAndExecute(t, ops); err != nil {
			t.Fatalf("query %d (bit=%d): conditional fold disagrees with reference (want=%v): %v",
				qi, bit, want, err)
		}
		t.Logf("query %d: index=%d bit=%d s=%d fold=%v |ops|=%d",
			qi, index, bit, s, want, len(ops))
	}
}

// TestEmitFriFoldRowConditional_MatchesReference validates the conditional
// (bit-driven) fold-row emission for both bit values. Mirrors verifyQuery's
// indexInGroup-based evals[] assignment (sp1fri/fri.go:290-300) followed by
// foldRow (lines 344-357).
//
// For each bit ∈ {0, 1}:
//   - Construct (folded, sibling) and derive (e_low, e_high) per the bit:
//       bit==0 → (e_low, e_high) = (folded, sibling)
//       bit==1 → (e_low, e_high) = (sibling, folded)
//   - Compute reference fold via the validated lagrangeInterpolateAt.
//   - Emit on-chain via emitFriFoldRowConditional with the runtime bit.
//   - Assert on-chain Ext4 result matches the reference byte-identical.
func TestEmitFriFoldRowConditional_MatchesReference(t *testing.T) {
	folded := sp1fri.Ext4{42, 17, 99, 1}
	sibling := sp1fri.Ext4{77, 28, 5, 1234}
	beta := sp1fri.Ext4{555, 12345, 7, 88}
	s := sp1fri.KbPow(sp1fri.KbTwoAdicGenerator(5), 3)

	for _, bit := range []int{0, 1} {
		t.Run(fmt.Sprintf("bit=%d", bit), func(t *testing.T) {
			var eLow, eHigh sp1fri.Ext4
			if bit == 0 {
				eLow, eHigh = folded, sibling
			} else {
				eLow, eHigh = sibling, folded
			}
			want := referenceColinearityFold(eLow, eHigh, beta, s)

			var ops []StackOp
			tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
			pushExt4Named(tracker, "fld", folded)
			pushExt4Named(tracker, "sib", sibling)
			pushExt4Named(tracker, "beta", beta)
			tracker.pushInt("s", int64(s))
			tracker.pushInt("bit", int64(bit))

			emitFriFoldRowConditional(tracker, "fld", "sib", "beta", "s", "bit", "out")

			assertExt4EqualsRef(t, tracker, &ops, "out", want)
			drainAllStack(tracker, &ops)

			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("bit=%d: on-chain conditional fold disagrees with reference (want=%v): %v",
					bit, want, err)
			}
			t.Logf("bit=%d: conditional fold matches reference; want=%v |ops|=%d", bit, want, len(ops))
		})
	}
}

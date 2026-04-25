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
	absorbBytes(publicValues)
	chal.ObserveDigest(traceDigest)
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
// harness. It exercises Steps 1 + 2-5 sequentially: first the proof-blob
// binding (Step 1) consumes proofBlob and verifies the field-push
// reconstruction; then the transcript init (Steps 2-5) runs against
// canonical-observation inputs.
//
// The two halves are independent in this PR — Step 1 leaves the field
// chunks on the stack; we drop them before running Steps 2-5, which
// pushes its own observation inputs. The full pipeline-to-pipeline
// wiring (where Step 1's leftover fields directly feed Step 2's
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

	// === Steps 2-5 ===
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

	// Build a separate tracker for Steps 2-5 starting from an empty stack
	// (the script is the same flat ops slice — the tracker just tracks the
	// suffix of the stack we manage from this point on).
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	fs := NewFiatShamirState()
	params := DefaultSP1FriParams()
	params.PublicValuesByteSize = len(pubVals)
	params.SP1VKeyHashByteSize = 0

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

	// Sanity-check alpha + zeta against the reference.
	assertEqualNamed := func(name string, ref uint32) {
		tracker.toTop(name)
		ops = append(ops, pushInt64(int64(ref)))
		ops = append(ops, opcode("OP_NUMEQUALVERIFY"))
		tracker.rawBlock([]string{name}, "", func(e func(StackOp)) {})
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_zeta_%d", i), zeta[i])
	}
	for i := 3; i >= 0; i-- {
		assertEqualNamed(fmt.Sprintf("_fs_alpha_%d", i), alpha[i])
	}

	// Drain everything else off the stack.
	for len(tracker.nm) > 0 {
		ops = append(ops, opcode("OP_DROP"))
		tracker.nm = tracker.nm[:len(tracker.nm)-1]
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("verifier rejected the canonical fixture (Step 1 + 2-5): %v", err)
	}

	// Measure compiled script size in bytes for the brief's reporting.
	method := StackMethod{Name: "test", Ops: ops}
	result, emitErr := Emit([]StackMethod{method})
	scriptBytes := -1
	if emitErr == nil {
		scriptBytes = len(result.ScriptHex) / 2
	}

	t.Logf("Steps 1 + 2-5 accepted canonical fixture; |proofBlob|=%d, |chunks|=%d, "+
		"|step1 ops|=%d, total ops in harness=%d, script bytes=%d, "+
		"alpha=%v zeta=%v",
		len(bs), len(chunks), len(bindingOps), len(ops), scriptBytes, alpha, zeta)
}

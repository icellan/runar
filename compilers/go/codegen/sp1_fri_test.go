package codegen

import (
	"crypto/sha256"
	"encoding/hex"
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

// TestSp1FriVerifier_AcceptsMinimalGuestFixture is the holistic acceptance
// harness referenced by the porting brief. It currently exercises Step 1
// only — the deeper steps still panic in `lowerVerifySP1FRI`, so the
// holistic flow is gated to the binding sub-step until subsequent sub-step
// implementations land.
//
// As each sub-step is filled in, this test should grow to invoke the
// matching emit helpers in order. When all 12 steps land, replace the
// inlined Step 1 call below with the top-level `lowerVerifySP1FRI` body.
func TestSp1FriVerifier_AcceptsMinimalGuestFixture(t *testing.T) {
	bs := loadMinimalGuestProofBlob(t)

	// For now: split into 8 chunks and exercise only Step 1. As later steps
	// land, append the Step 2..12 emit helpers here in declaration order
	// (see emitSP1FriStructuralSkeleton in sp1_fri.go for the planned shape).
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

	// === Steps 2-12 not yet emitted (panicSP1FriStub in sp1_fri.go). ===
	// Drain leftover fields so the harness is self-contained.
	for i := 0; i < len(chunks); i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("verifier rejected the canonical fixture (Step 1 only): %v", err)
	}

	// Measurements (Step 1 in isolation).
	t.Logf("Step 1 accepted canonical fixture; |proofBlob|=%d, |chunks|=%d, "+
		"|step1 ops|=%d, total ops in harness=%d",
		len(bs), len(chunks), len(bindingOps), len(ops))
}

package codegen

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// ---------------------------------------------------------------------------
// SP1 FRI verifier — NEGATIVE tests (rejection paths).
//
// The positive-path tests in sp1_fri_test.go prove the verifier ACCEPTS the
// canonical minimal-guest fixture. On their own they prove nothing about
// soundness: a verifier that accepted everything would pass all of them.
// These tests close that gap by driving the corruption fixtures under
// `tests/vectors/sp1/fri/corruptions/` (produced by that directory's
// `gen.go`) through the validated off-chain reference verifier and asserting
// (a) that each is rejected, and (b) WHERE it is rejected.
//
// Asserting the exact rejection message matters: a corruption that is
// rejected by an accidental parse error instead of the cryptographic check it
// was designed to trip provides no evidence that the check works. Every
// expectation below is the *observed* detection point; where it diverges from
// the matrix documented in docs/sp1-fri-verifier.md §6 that divergence is
// called out explicitly in the case's `divergence` field and in the fixture's
// own README.
// ---------------------------------------------------------------------------

// corruptionsDir resolves tests/vectors/sp1/fri/corruptions/ hermetically.
func corruptionsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
		"tests", "vectors", "sp1", "fri", "corruptions")
}

// minimalGuestDir resolves tests/vectors/sp1/fri/minimal-guest/.
func minimalGuestDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
		"tests", "vectors", "sp1", "fri", "minimal-guest")
}

// readPublicValues parses a `public_values.hex` file into the []uint32 the
// reference verifier consumes. The on-wire encoding is little-endian u32s,
// matching `ParamSet.PublicValuesByteSize` (12 bytes = 3 values).
func readPublicValues(t *testing.T, path string) []uint32 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	bs, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(bs)%4 != 0 {
		t.Fatalf("%s: %d bytes is not a whole number of u32s", path, len(bs))
	}
	out := make([]uint32, len(bs)/4)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(bs[i*4 : i*4+4])
	}
	return out
}

// TestSp1FriVerifier_PositiveFixtureStillVerifies is the NON-VACUITY control
// for every negative test in this file.
//
// If the reference verifier rejected everything, all the rejection assertions
// below would pass while proving nothing. This test pins the other side: the
// unmodified base fixture — the exact bytes every corruption is derived from,
// paired with the public values checked in beside it — must still be
// ACCEPTED. A regression that breaks acceptance fails here first, and the
// negative results in this file must then be treated as meaningless until it
// is green again.
func TestSp1FriVerifier_PositiveFixtureStillVerifies(t *testing.T) {
	dir := minimalGuestDir(t)
	bs, err := os.ReadFile(filepath.Join(dir, "proof.postcard"))
	if err != nil {
		t.Fatalf("read base fixture: %v", err)
	}
	proof, err := sp1fri.DecodeProof(bs)
	if err != nil {
		t.Fatalf("base fixture failed to decode: %v", err)
	}
	pis := readPublicValues(t, filepath.Join(dir, "public_values.hex"))
	if err := sp1fri.Verify(proof, pis); err != nil {
		t.Fatalf("reference verifier REJECTED the canonical minimal-guest fixture: %v\n"+
			"Every negative assertion in this file is vacuous until this passes.", err)
	}
	t.Logf("non-vacuity control OK: base fixture (%d bytes, pis=%v) accepted", len(bs), pis)
}

// corruptionCase describes one negative fixture and the precise point the
// verifier is expected to reject it at.
type corruptionCase struct {
	dir string

	// wantErrContains is a substring of the rejection message that uniquely
	// identifies the detection point. Asserting on it — rather than merely
	// "err != nil" — is what makes the test evidence rather than noise.
	wantErrContains string

	// rejectedAtDecode is true when the fixture never reaches the verifier
	// because the postcard decoder rejects it first.
	rejectedAtDecode bool

	// docPoint is the detection point claimed by docs/sp1-fri-verifier.md §6.
	docPoint string

	// divergence is non-empty when the observed detection point differs from
	// docPoint, and explains why. An empty string means observed == documented.
	divergence string

	// singleByteFrom, when non-empty, names the base file this fixture must
	// differ from in exactly one byte. This pins fixture provenance: it proves
	// the corruption really is the documented minimal mutation and not a
	// wholesale replacement that would reject for uninteresting reasons.
	singleByteFrom string
}

var sp1FriCorruptionCases = []corruptionCase{
	{
		dir:             "bad_merkle",
		wantErrContains: "input MMCS verify (batch 0): verify_batch: cap mismatch",
		docPoint:        "Merkle root recompute",
		singleByteFrom:  "proof.postcard",
	},
	{
		dir:             "bad_folding",
		wantErrContains: "round 0 MMCS: verify_batch: cap mismatch",
		docPoint:        "Colinearity check",
		divergence: "Rejected at the FRI commit-phase MMCS opening, not at a colinearity " +
			"check. Plonky3 FRI has no standalone colinearity assertion — every value " +
			"the fold consumes is Merkle-committed, so VerifyBatchExt fires before any " +
			"folding arithmetic runs.",
		singleByteFrom: "proof.postcard",
	},
	{
		dir:             "bad_final_poly",
		wantErrContains: "input MMCS verify (batch 0): verify_batch: cap mismatch",
		docPoint:        "Final-poly equality",
		divergence: "Rejected at the input-MMCS Merkle check, not at final-poly equality. " +
			"final_poly is absorbed into the transcript before the query indices are " +
			"sampled, so mutating it re-randomises every query index and the Merkle " +
			"proof authenticates the wrong leaf. The 'final_poly mismatch' branch is " +
			"unreachable by byte-level corruption.",
		singleByteFrom: "proof.postcard",
	},
	{
		dir:             "wrong_public_values",
		wantErrContains: "commit-phase round 0 invalid PoW witness",
		docPoint:        "Transcript divergence",
		singleByteFrom:  "public_values.hex",
	},
	{
		dir:             "wrong_program",
		wantErrContains: "invalid query PoW witness",
		docPoint:        "Transcript divergence",
		divergence: "Mutation deviates from the documented one: the matrix specifies an " +
			"EVM-guest VK hash, but no VK hash exists in this fixture tree (see " +
			"corruptions/bad_vk/README.md). Program identity is bound through the " +
			"public values instead. The detection point itself matches.",
	},
	{
		dir:              "truncated",
		wantErrContains:  "postcard: unexpected EOF",
		rejectedAtDecode: true,
		docPoint:         "Push-and-hash binding",
		divergence: "Off-chain there is no push-and-hash step: the postcard decoder hits EOF " +
			"before the verifier runs. The documented on-chain detection point is " +
			"asserted separately by TestSp1FriVerifier_TruncatedFailsPushAndHashBinding.",
	},
	{
		dir:              "all_zeros",
		wantErrContains:  "trailing bytes after top-level decode",
		rejectedAtDecode: true,
		docPoint:         "bincode length / hash",
	},
}

// TestSp1FriVerifier_RejectsCorruptionFixtures drives every generated
// corruption fixture through the reference verifier and asserts both THAT it
// is rejected and WHERE.
func TestSp1FriVerifier_RejectsCorruptionFixtures(t *testing.T) {
	root := corruptionsDir(t)
	baseDir := minimalGuestDir(t)

	for _, tc := range sp1FriCorruptionCases {
		t.Run(tc.dir, func(t *testing.T) {
			dir := filepath.Join(root, tc.dir)

			proofBytes, err := os.ReadFile(filepath.Join(dir, "proof.postcard"))
			if err != nil {
				t.Fatalf("read fixture proof: %v (run tests/vectors/sp1/fri/corruptions/gen.go)", err)
			}
			pis := readPublicValues(t, filepath.Join(dir, "public_values.hex"))

			// Provenance: the corruption must be exactly the documented
			// minimal mutation of the base fixture.
			if tc.singleByteFrom != "" {
				assertSingleByteDiff(t,
					filepath.Join(baseDir, tc.singleByteFrom),
					filepath.Join(dir, tc.singleByteFrom))
			}

			proof, decErr := sp1fri.DecodeProof(proofBytes)
			if tc.rejectedAtDecode {
				if decErr == nil {
					t.Fatalf("expected the postcard decoder to reject %s, but it decoded cleanly", tc.dir)
				}
				assertDetectionPoint(t, tc, decErr.Error(), "decode")
				return
			}

			if decErr != nil {
				t.Fatalf("fixture %s was expected to reach the verifier but failed to decode: %v\n"+
					"A decode error here means the corruption is testing the parser, not the "+
					"cryptographic check it was designed to trip.", tc.dir, decErr)
			}

			verErr := sp1fri.Verify(proof, pis)
			if verErr == nil {
				t.Fatalf("VERIFIER ACCEPTED CORRUPTION %s — expected rejection at %q", tc.dir, tc.docPoint)
			}
			assertDetectionPoint(t, tc, verErr.Error(), "verify")
		})
	}
}

// assertDetectionPoint checks the rejection happened at the expected point and
// logs the documented-vs-observed comparison.
func assertDetectionPoint(t *testing.T, tc corruptionCase, got, stage string) {
	t.Helper()
	if !strings.Contains(got, tc.wantErrContains) {
		t.Fatalf("rejected at the WRONG point.\n  documented: %s\n  want substring: %q\n  got (%s): %s",
			tc.docPoint, tc.wantErrContains, stage, got)
	}
	if tc.divergence == "" {
		t.Logf("rejected at the documented point (%s): %s", tc.docPoint, got)
		return
	}
	t.Logf("rejected, but NOT at the documented point.\n  documented: %s\n  observed (%s): %s\n  why: %s",
		tc.docPoint, stage, got, tc.divergence)
}

// assertSingleByteDiff fails unless `mutated` differs from `base` in exactly
// one byte and has the same length.
func assertSingleByteDiff(t *testing.T, basePath, mutatedPath string) {
	t.Helper()
	base, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read base %s: %v", basePath, err)
	}
	mut, err := os.ReadFile(mutatedPath)
	if err != nil {
		t.Fatalf("read mutated %s: %v", mutatedPath, err)
	}
	// public_values.hex is text; compare the decoded bytes so a trailing
	// newline difference is not counted as a mutation.
	if strings.HasSuffix(basePath, ".hex") {
		base = decodeHexOrFail(t, base)
		mut = decodeHexOrFail(t, mut)
	}
	if len(base) != len(mut) {
		t.Fatalf("fixture provenance broken: length changed %d -> %d (expected a single-byte mutation)",
			len(base), len(mut))
	}
	diffs := 0
	firstAt := -1
	for i := range base {
		if base[i] != mut[i] {
			diffs++
			if firstAt < 0 {
				firstAt = i
			}
		}
	}
	if diffs != 1 {
		t.Fatalf("fixture provenance broken: %d bytes differ from the base fixture, want exactly 1", diffs)
	}
	t.Logf("provenance OK: single-byte mutation at offset %d (0x%02x -> 0x%02x)",
		firstAt, base[firstAt], mut[firstAt])
}

func decodeHexOrFail(t *testing.T, raw []byte) []byte {
	t.Helper()
	bs, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return bs
}

// TestSp1FriVerifier_TruncatedFailsPushAndHashBinding asserts the `truncated/`
// fixture at ITS DOCUMENTED on-chain detection point: the Step 1 push-and-hash
// binding (docs/sp1-fri-verifier.md §2).
//
// The on-chain verifier has no postcard decoder — it consumes pre-pushed
// fields and binds them to the single `proofBlob` ByteString with one SHA-256
// equality. So the on-chain analogue of "the proof was truncated" is: the
// unlocking script pushes chunks that no longer reconstruct the proofBlob the
// covenant committed to. This drives the real `EmitProofBlobBindingHash`
// emission through the go-sdk script interpreter and requires OP_EQUALVERIFY
// to fail.
func TestSp1FriVerifier_TruncatedFailsPushAndHashBinding(t *testing.T) {
	full := loadMinimalGuestProofBlob(t)
	truncated, err := os.ReadFile(filepath.Join(corruptionsDir(t), "truncated", "proof.postcard"))
	if err != nil {
		t.Fatalf("read truncated fixture: %v", err)
	}
	if len(truncated) >= len(full) {
		t.Fatalf("truncated fixture is not shorter than the base: %d vs %d", len(truncated), len(full))
	}
	if !bytes.Equal(truncated, full[:len(truncated)]) {
		t.Fatal("truncated fixture is not a prefix of the base fixture")
	}

	// Chunks come from the truncated blob; the covenant-bound proofBlob is
	// the full one. sha256(concat(chunks)) != sha256(proofBlob).
	chunks := chunkProof(t, truncated, 4)

	var ops []StackOp
	for _, c := range chunks {
		ops = append(ops, pushBytes(c))
	}
	ops = append(ops, pushBytes(full)) // proofBlob the covenant committed to

	ops = append(ops, gatherOps(func(emit func(StackOp)) {
		EmitProofBlobBindingHash(emit, len(chunks))
	})...)
	for range chunks {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Fatal("push-and-hash binding ACCEPTED a truncated proof body; expected OP_EQUALVERIFY failure")
	} else {
		t.Logf("truncated proof correctly rejected at the push-and-hash binding: %v", err)
	}

	// Non-vacuity twin: the same emission with honest chunks must ACCEPT.
	honest := chunkProof(t, full, 4)
	var okOps []StackOp
	for _, c := range honest {
		okOps = append(okOps, pushBytes(c))
	}
	okOps = append(okOps, pushBytes(full))
	okOps = append(okOps, gatherOps(func(emit func(StackOp)) {
		EmitProofBlobBindingHash(emit, len(honest))
	})...)
	for range honest {
		okOps = append(okOps, opcode("OP_DROP"))
	}
	okOps = append(okOps, opcode("OP_1"))
	if err := buildAndExecute(t, okOps); err != nil {
		t.Fatalf("push-and-hash binding rejected the honest chunking: %v\n"+
			"The negative assertion above is vacuous until this passes.", err)
	}
	t.Logf("non-vacuity control OK: honest chunking of the same blob accepted")
}

// TestSp1FriVerifier_BadVkCorruptionIsDocumentedAbsent pins the one row of the
// §6 matrix that has no fixture and no test.
//
// `bad_vk` cannot be produced: minimal-guest is a raw Plonky3 proof with no
// SP1 outer wrapper, hence no verifying key and no VK hash to corrupt. The
// validated PoC parameter set encodes exactly that — SP1VKeyHashByteSize == 0,
// at which the sp1VKeyHash argument is dropped by the compiler and never
// absorbed into the transcript, so no VK hash value can change any verifier
// decision AT THIS TUPLE.
//
// Scope note (R-057). "At this tuple" is load-bearing and did not used to be.
// The verifying key reached no transcript at ANY parameter set: the Step 2b
// absorb in emitTranscriptInit looked up an `_obs_sp1_vk_hash` slot that
// sp1FriPrePushedFieldNames never allocated, so SP1VKeyHashByteSize > 0
// panicked the compiler instead of binding the key, and every named preset
// leaves the field at 0. SP1VKeyHashByteSize > 0 now absorbs the contract's
// readonly Sp1VKeyHash property — a locking-script constant — at the head of
// the transcript; the adversarial proof of that lives in
// compilers/go/compiler.TestSp1FriVerifier_VerifyingKeyBindsTheProgram.
//
// So the assertion below is NOT "the VK is unbindable". It is "the PoC tuple
// used by the fixtures in this directory is VK-blind, which is why a bad_vk
// fixture would be inert here".
//
// This test exists so the gap stays honest in both directions: it fails if
// someone drops fixture bytes into bad_vk/ without wiring a real assertion,
// and it fails if the explanatory README disappears.
func TestSp1FriVerifier_BadVkCorruptionIsDocumentedAbsent(t *testing.T) {
	dir := filepath.Join(corruptionsDir(t), "bad_vk")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read bad_vk dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "README.md" {
			t.Fatalf("bad_vk/ contains %q. If a real VK-bound fixture now exists, add a "+
				"test that asserts the verifier rejects it and update this test plus "+
				"docs/sp1-fri-verifier.md §6.", e.Name())
		}
	}

	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatalf("bad_vk/README.md missing: %v — the gap must stay documented", err)
	}
	if !strings.Contains(string(readme), "SP1VKeyHashByteSize") {
		t.Fatal("bad_vk/README.md no longer explains why the fixture cannot exist")
	}

	// The claim above is only true while the PoC parameter set really does
	// disable the VK-hash absorb. Pin it.
	if got := DefaultSP1FriParams().SP1VKeyHashByteSize; got != 0 {
		t.Fatalf("DefaultSP1FriParams().SP1VKeyHashByteSize == %d, not 0. The PoC tuple now "+
			"binds a VK hash, so bad_vk/ is testable — generate the fixture and assert rejection.", got)
	}
	t.Log("bad_vk correctly absent: SP1VKeyHashByteSize==0 means no VK hash is bound at the PoC " +
		"parameter set (SP1VKeyHashByteSize>0 does bind one — see " +
		"compiler.TestSp1FriVerifier_VerifyingKeyBindsTheProgram)")
}

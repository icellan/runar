package compiler

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// ---------------------------------------------------------------------------
// SP1 FRI verifier — ON-CHAIN negative tests.
//
// docs/sp1-fri-verifier.md §6 states that every corruption "must fail
// OP_VERIFY on regtest". The reference-verifier negatives in
// compilers/go/codegen/sp1_fri_negative_test.go prove the ALGORITHM rejects
// each fixture; they say nothing about the emitted Bitcoin Script. These
// tests close that second gap: they compile the real PoC covenant, build a
// well-formed unlocking script around a CORRUPTED proof, and require the
// go-sdk script interpreter to reject the spend.
//
// "Well-formed" is the important part. Each unlocking script is encoded from
// the corrupted proof itself, so the Step 1 SHA-256 push-and-hash binding
// SUCCEEDS — the pre-pushed fields honestly reconstruct the (corrupted)
// proofBlob. The rejection therefore comes from the cryptographic body of the
// verifier, not from a trivially malformed witness.
// ---------------------------------------------------------------------------

func sp1FixturesRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
		"tests", "vectors", "sp1", "fri")
}

func sp1PocContractPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
		"integration", "go", "contracts", "Sp1FriVerifierPoc.runar.go")
}

// readPublicValuesBytes returns the raw little-endian u32 public-values blob
// (the ByteString the unlocking script pushes) plus the decoded []uint32.
func readPublicValuesBytes(t *testing.T, path string) ([]byte, []uint32) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	bs, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	vals := make([]uint32, len(bs)/4)
	for i := range vals {
		vals[i] = binary.LittleEndian.Uint32(bs[i*4 : i*4+4])
	}
	return bs, vals
}

// compilePocLockingScript lowers the PoC covenant once and returns its
// locking script. SP1VKeyHashByteSize == 0 for the PoC parameter set, so the
// single ByteString constructor slot's OP_0 placeholder already equals
// EncodePushData("") — no constructor splicing is required.
//
// F-007: CompileFromSource now always refuses verifySP1FRI, so the script is
// produced by the test-only lowerSP1FriPocBypassingRefusal (byte-identical to
// what CompileFromSource emitted before the refusal became unconditional).
func compilePocLockingScript(t *testing.T) *script.Script {
	t.Helper()
	path := sp1PocContractPath(t)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("PoC contract not found at %s: %v", path, err)
	}
	res := lowerSP1FriPocBypassingRefusal(t, nil)
	if res.ScriptHex == "" {
		t.Fatal("lowering produced no locking script")
	}
	s, err := script.NewFromHex(res.ScriptHex)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	return s
}

// runSpend executes [unlocking][locking] under the same interpreter flags the
// positive end-to-end test uses.
func runSpend(lock *script.Script, unlockingBytes []byte) error {
	return interpreter.NewEngine().Execute(
		interpreter.WithScripts(lock, script.NewFromBytes(unlockingBytes)),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}

// sp1OnChainCase is one (proof, publicValues) pair fed to the compiled
// covenant.
type sp1OnChainCase struct {
	name string
	// proofDir supplies proof.postcard; pubDir supplies public_values.hex.
	// Splitting them lets wrong_public_values / wrong_program pair the honest
	// proof with a different program's public values.
	proofDir string
	pubDir   string
	// wantAccept was true only for the canonical control. F-007: no case
	// sets it any more — the emitted body is fail-closed and accepts nothing.
	wantAccept bool
	docPoint   string

	// knownGap, when non-empty, records a corruption that the OFF-CHAIN
	// reference verifier rejects but the CURRENTLY EMITTED locking script
	// ACCEPTS. See the KNOWN GAP block on
	// TestSp1FriVerifier_OnChainRejectsCorruptions. These cases assert the
	// present behaviour so the hole is machine-visible; when the missing
	// emission lands the assertion flips and this test tells the maintainer
	// to clear the field.
	knownGap string
}

// onChainMerkleGap is the shared explanation for every corruption that the
// emitted script fails to catch.
const onChainMerkleGap = "the emitted verifier body derives each query index and DROPS it " +
	"(codegen/sp1_fri.go, Step 10: \"For the deployable verifier we sample-and-drop\"), so the " +
	"input-batch MMCS verify, the FRI fold chain and the final-poly Horner equality are never " +
	"emitted. Any corruption that only breaks a Merkle opening is therefore invisible on-chain."

// TestSp1FriVerifier_OnChainRejectsCorruptions is the on-chain counterpart to
// TestSp1FriVerifier_RejectsCorruptionFixtures.
//
// The first case WAS the non-vacuity control (canonical fixture ACCEPTED).
// F-007: the v1 body is fail-closed, so it now expects the canonical fixture
// to be REJECTED too. Consequence, stated plainly: every rejection below is
// now produced by the fail-closed abort, so this test no longer shows that
// any individual check works — only that nothing is accepted.
//
// ---------------------------------------------------------------------------
// KNOWN GAP — the emitted script is NOT yet a sound proof verifier.
//
// Three of the five corruptions below (bad_merkle, bad_folding,
// bad_final_poly) are rejected by the off-chain reference verifier but
// ACCEPTED by the compiled locking script. The cause is not a subtle bug: the
// deployable body emitted by EmitFullSP1FriVerifierBody samples each FRI query
// index and immediately drops it, so none of the per-query Merkle-authentication,
// folding or final-poly checks reach the script at all. Only the transcript-bound
// checks (the commit-phase and query-phase grinding witnesses) are emitted, which
// is why the two transcript-divergence corruptions ARE caught.
//
// Consequence: at the PoC parameter set a spender can supply forged Merkle
// openings — arbitrary opened values with arbitrary authentication paths — and
// the covenant will accept. Soundness currently rests entirely on the
// Fiat-Shamir transcript, not on the proof.
//
// This test pins that reality rather than hiding it. It is deliberately NOT a
// skip: the gap stays in the test output on every run.
// ---------------------------------------------------------------------------
func TestSp1FriVerifier_OnChainRejectsCorruptions(t *testing.T) {
	root := sp1FixturesRoot(t)
	lock := compilePocLockingScript(t)
	params := sp1fri.MinimalGuestParams()

	cases := []sp1OnChainCase{
		// F-007: rewritten to expect rejection — the emitted body is fail-closed for v1 (was canonical_control_accepts).
		{
			name:     "canonical_control_rejected_fail_closed",
			proofDir: "minimal-guest",
			pubDir:   "minimal-guest",
			docPoint: "F-007 fail-closed abort (OP_0 OP_VERIFY)",
		},
		{
			name:     "bad_merkle",
			proofDir: "corruptions/bad_merkle",
			pubDir:   "corruptions/bad_merkle",
			docPoint: "Merkle root recompute",
			knownGap: onChainMerkleGap,
		},
		{
			name:     "bad_folding",
			proofDir: "corruptions/bad_folding",
			pubDir:   "corruptions/bad_folding",
			docPoint: "FRI commit-phase MMCS opening",
			knownGap: onChainMerkleGap,
		},
		{
			name:     "bad_final_poly",
			proofDir: "corruptions/bad_final_poly",
			pubDir:   "corruptions/bad_final_poly",
			docPoint: "transcript divergence -> input MMCS",
			knownGap: onChainMerkleGap,
		},
		{
			name:     "wrong_public_values",
			proofDir: "minimal-guest",
			pubDir:   "corruptions/wrong_public_values",
			docPoint: "transcript divergence",
		},
		{
			name:     "wrong_program",
			proofDir: "minimal-guest",
			pubDir:   "corruptions/wrong_program",
			docPoint: "transcript divergence",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proofBytes, err := os.ReadFile(filepath.Join(root, tc.proofDir, "proof.postcard"))
			if err != nil {
				t.Fatalf("read proof: %v", err)
			}
			pubBytes, pubVals := readPublicValuesBytes(t,
				filepath.Join(root, tc.pubDir, "public_values.hex"))
			if len(pubBytes) != params.PublicValuesByteSize {
				t.Fatalf("public values are %d bytes, ParamSet expects %d",
					len(pubBytes), params.PublicValuesByteSize)
			}

			proof, err := sp1fri.DecodeProof(proofBytes)
			if err != nil {
				t.Fatalf("decode proof: %v (this case must reach the script, not die in the decoder)", err)
			}

			// The unlocking script is encoded from the SAME bytes the covenant
			// is asked to accept, so the Step 1 push-and-hash binding holds and
			// any rejection comes from the verifier body.
			unlocking, err := sp1fri.EncodeUnlockingScript(proof, nil, pubBytes, nil, params)
			if err != nil {
				t.Fatalf("EncodeUnlockingScript: %v", err)
			}

			// Cross-check against the off-chain reference verifier so the two
			// layers cannot silently disagree about this fixture.
			refErr := sp1fri.Verify(proof, pubVals)
			execErr := runSpend(lock, unlocking)

			if tc.name == "canonical_control_rejected_fail_closed" {
				// F-007: rewritten to expect rejection — the honest proof is refused because the body is fail-closed.
				if refErr != nil {
					t.Fatalf("reference verifier rejected the canonical fixture: %v", refErr)
				}
				if execErr == nil {
					t.Fatal("F-007: the compiled covenant ACCEPTED the canonical fixture; the v1 body must be fail-closed")
				}
				t.Logf("canonical fixture rejected on-chain (fail-closed): %v", execErr)
				return
			}

			if tc.wantAccept {
				if refErr != nil {
					t.Fatalf("reference verifier rejected the canonical fixture: %v", refErr)
				}
				if execErr != nil {
					t.Fatalf("compiled covenant REJECTED the canonical fixture: %v\n"+
						"Every on-chain negative below is vacuous until this passes.", execErr)
				}
				t.Logf("non-vacuity control OK: canonical fixture accepted on-chain "+
					"(|unlocking|=%d B, |locking|=%d B)", len(unlocking), len(*lock))
				return
			}

			if refErr == nil {
				t.Fatalf("reference verifier ACCEPTED corruption %s", tc.name)
			}

			if tc.knownGap != "" {
				// F-007: rewritten to expect rejection — these were ACCEPTED (known gap) and are now rejected,
				// but only by the fail-closed abort: the per-query chain is still not emitted.
				if execErr == nil {
					t.Fatalf("F-007: compiled covenant ACCEPTS corruption %s; the v1 body must be "+
						"fail-closed.\n  off-chain reference rejects it: %v\n  gap: %s",
						tc.name, refErr, tc.knownGap)
				}
				t.Logf("corruption %s rejected ONLY by the F-007 fail-closed abort (%v); "+
					"the underlying gap remains: %s", tc.name, execErr, tc.knownGap)
				return
			}

			if execErr == nil {
				t.Fatalf("compiled covenant ACCEPTED corruption %s — expected an OP_VERIFY "+
					"failure at %s.\n(off-chain reference rejected it with: %v)",
					tc.name, tc.docPoint, refErr)
			}
			t.Logf("on-chain rejection OK (documented point: %s)\n  script:    %v\n  reference: %v",
				tc.docPoint, execErr, refErr)
		})
	}
}

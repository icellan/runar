package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/icellan/runar/compilers/go/codegen"
	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// ---------------------------------------------------------------------------
// SP1 FRI verifier — verifying-key binding.
//
// The covenant's whole claim is "THIS program executed". That claim rests
// entirely on the verifying key reaching the Fiat-Shamir transcript: a
// verifier that ignores its VK hash accepts a proof produced for a DIFFERENT
// guest program, and then proves only "some SP1 program executed".
//
// Sp1FriVerifierPoc.runar.go:48-50 states the claim explicitly — "Bound at
// compile time; a malicious unlocking script cannot supply it". The tests
// below are the machine check on that sentence.
// ---------------------------------------------------------------------------

// sp1VkBindingParams returns the PoC parameter tuple with a real 32-byte SP1
// verifying-key hash, i.e. the tuple an SP1-wrapped guest program deploys at.
// Every named preset (minimal-guest / evm-guest / production-{100,64,16})
// leaves SP1VKeyHashByteSize at 0, so this is the only way to ask the compiler
// for a VK-bound verifier.
func sp1VkBindingParams() codegen.SP1FriVerifierParams {
	p := codegen.DefaultSP1FriParams()
	p.SP1VKeyHashByteSize = 32
	return p
}

// spliceVkHash rewrites the single `Sp1VKeyHash` constructor slot in a
// compiled locking script, mirroring the byte-offset-descending splice in
// packages/runar-go/sdk_contract.go. Returns the patched script hex.
func spliceVkHash(t *testing.T, scriptHex string, slots []ConstructorSlot, vk []byte) string {
	t.Helper()
	if len(slots) != 1 {
		t.Fatalf("expected exactly 1 constructor slot for Sp1VKeyHash, got %d", len(slots))
	}
	type sub struct {
		off int
		enc string
	}
	subs := make([]sub, 0, len(slots))
	for _, s := range slots {
		subs = append(subs, sub{off: s.ByteOffset, enc: encodePushDataHexVk(hex.EncodeToString(vk))})
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].off > subs[j].off })
	out := scriptHex
	for _, s := range subs {
		h := s.off * 2
		if h+2 > len(out) {
			t.Fatalf("constructor slot byteOffset=%d out of range (|script|=%d B)", s.off, len(out)/2)
		}
		out = out[:h] + s.enc + out[h+2:]
	}
	return out
}

func encodePushDataHexVk(dataHex string) string {
	n := len(dataHex) / 2
	switch {
	case n <= 75:
		return fmt.Sprintf("%02x", n) + dataHex
	case n <= 0xff:
		return "4c" + fmt.Sprintf("%02x", n) + dataHex
	case n <= 0xffff:
		return "4d" + fmt.Sprintf("%02x%02x", n&0xff, (n>>8)&0xff) + dataHex
	default:
		return "4e" + fmt.Sprintf("%02x%02x%02x%02x", n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff) + dataHex
	}
}

// candidateVk derives a deterministic 32-byte VK hash for index i. Different
// i means a different guest program.
func candidateVk(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("runar/sp1-fri/vk-binding/program-%d", i)))
	return h[:]
}

// TestSp1FriVerifier_VerifyingKeyBindsTheProgram is the adversarial test for
// R-057: a proof valid under program A's verifying key must NOT be accepted
// by the same covenant deployed under program B's verifying key.
//
// Construction — deliberately crafted, not random bytes:
//
//   - Compile the PoC covenant ONCE at a VK-bound tuple (SP1VKeyHashByteSize
//     = 32). One compilation, many splices: the only thing that differs
//     between the runs below is the 32 VK bytes baked into the locking
//     script.
//   - Encode ONE unlocking script from the canonical minimal-guest fixture.
//     Those bytes never change. The VK is a locking-script constant, so the
//     spender cannot adapt to it — which is exactly the property under test.
//   - Sweep candidate VK hashes. Because the VK is absorbed at the head of
//     the transcript, absorbing a different VK re-randomises every downstream
//     challenge, and the fixture's two grinding witnesses (CommitPoWBits=1,
//     QueryPoWBits=1) then hold with probability 1/4. So a sweep finds both:
//     an ACCEPTING VK (program A — the non-vacuity control, without which a
//     covenant that rejected everything would pass) and a REJECTING VK
//     (program B — the forgery the covenant must refuse).
//
// RED before the fix: every candidate VK is accepted, because
// lowerVerifySP1FRI drops the sp1VKeyHash argument (sp1_fri.go §1f
// "Discard for alt-stack balance") and emitTranscriptInit never absorbs it.
// The "no VK was rejected" branch fires.
func TestSp1FriVerifier_VerifyingKeyBindsTheProgram(t *testing.T) {
	root := sp1FixturesRoot(t)
	proofBytes, err := os.ReadFile(filepath.Join(root, "minimal-guest", "proof.postcard"))
	if err != nil {
		t.Fatalf("read canonical proof: %v", err)
	}
	pubBytes, pubVals := readPublicValuesBytes(t,
		filepath.Join(root, "minimal-guest", "public_values.hex"))

	proof, err := sp1fri.DecodeProof(proofBytes)
	if err != nil {
		t.Fatalf("decode canonical proof: %v", err)
	}
	if err := sp1fri.Verify(proof, pubVals); err != nil {
		t.Fatalf("off-chain reference rejected the canonical fixture: %v", err)
	}

	// One lowering at the VK-bound tuple. F-007: CompileFromSource refuses
	// verifySP1FRI, so the test-only helper produces the same script bytes.
	p := sp1VkBindingParams()
	if _, err := CompileFromSource(sp1PocContractPath(t), CompileOptions{SP1FriParams: &p}); err == nil {
		t.Fatal("F-007: CompileFromSource compiled verifySP1FRI at SP1VKeyHashByteSize=32; v1 must refuse")
	}
	artifact := lowerSP1FriPocBypassingRefusal(t, &p)
	if artifact.ScriptHex == "" {
		t.Fatal("lowering produced no locking script")
	}

	// One unlocking script, encoded at the SAME tuple the covenant was
	// compiled at. The VK is NOT pushed here: it is a readonly contract
	// property baked into the locking script, so the spender cannot supply
	// it. Passing the matching SP1VKeyHashByteSize proves the encoder and
	// the codegen agree about that.
	ups := sp1fri.MinimalGuestParams()
	ups.SP1VKeyHashByteSize = p.SP1VKeyHashByteSize
	unlocking, err := sp1fri.EncodeUnlockingScript(
		// R-059: nil ⇒ the encoder derives the canonical transcript-input
		// serialisation, which is what the Step 1 binding checks.
		proof, nil, pubBytes, candidateVk(0), ups)
	if err != nil {
		t.Fatalf("EncodeUnlockingScript: %v", err)
	}

	const sweep = 24
	var acceptedVk, rejectedVk []byte
	var rejectErr error
	accepts := 0
	for i := 0; i < sweep; i++ {
		vk := candidateVk(i)
		lockHex := spliceVkHash(t, artifact.ScriptHex, artifact.ConstructorSlots, vk)
		lock, err := script.NewFromHex(lockHex)
		if err != nil {
			t.Fatalf("parse spliced locking script: %v", err)
		}
		execErr := runSpend(lock, unlocking)
		if execErr == nil {
			accepts++
			if acceptedVk == nil {
				acceptedVk = vk
			}
		} else if rejectedVk == nil {
			rejectedVk = vk
			rejectErr = execErr
		}
	}

	// Was the non-vacuity control (some VK ACCEPTED).
	// F-007: rewritten to expect rejection — the v1 body is fail-closed, so NO verifying key may be accepted.
	if acceptedVk != nil {
		t.Fatalf("F-007: %d/%d candidate VKs were ACCEPTED (first vk=%x...); the v1 SP1 FRI body "+
			"must be fail-closed", accepts, sweep, acceptedVk[:8])
	}
	if rejectedVk == nil {
		t.Fatalf("R-057: all %d distinct verifying keys were ACCEPTED against the SAME proof. "+
			"The covenant's verifying key does not reach the Fiat-Shamir transcript, so it proves "+
			"\"some SP1 program executed\", not \"THIS program executed\". "+
			"Sp1FriVerifierPoc.runar.go:48-50 claims the opposite.", sweep)
	}

	t.Logf("fail-closed: 0/%d candidate verifying keys accepted the proof; first rejection vk=%x... (%v)",
		sweep, rejectedVk[:8], rejectErr)
}

// TestSp1FriVerifier_VkBindingIsReachableFromParams pins the narrower defect
// underneath R-057: the absorb path exists (sp1_fri.go emitTranscriptInit
// Step 2b) but was unreachable, because sp1FriPrePushedFieldNames never
// allocated the `_obs_sp1_vk_hash` slot that Step 2b looks up by name.
// Asking for SP1VKeyHashByteSize=32 therefore panicked the compiler rather
// than producing a VK-bound verifier — a remedy nobody could apply.
func TestSp1FriVerifier_VkBindingIsReachableFromParams(t *testing.T) {
	p := sp1VkBindingParams()
	// F-007: rewritten to expect refusal — CompileFromSource refuses verifySP1FRI in v1; the codegen reachability
	// below is checked on the test-only lowering instead.
	if _, err := CompileFromSource(sp1PocContractPath(t), CompileOptions{SP1FriParams: &p}); err == nil {
		t.Fatal("F-007: CompileFromSource compiled verifySP1FRI at SP1VKeyHashByteSize=32; v1 must refuse")
	}
	artifact := lowerSP1FriPocBypassingRefusal(t, &p)
	if artifact.ScriptHex == "" {
		t.Fatal("lowering produced no locking script")
	}

	// A VK-bound script must differ from the VK-blind one: the absorb adds
	// real opcodes.
	blind := lowerSP1FriPocBypassingRefusal(t, nil)
	if len(artifact.ScriptHex) <= len(blind.ScriptHex) {
		t.Fatalf("VK-bound script (%d B) is not larger than the VK-blind script (%d B) — "+
			"the sp1VKeyHash absorb emitted nothing",
			len(artifact.ScriptHex)/2, len(blind.ScriptHex)/2)
	}
}

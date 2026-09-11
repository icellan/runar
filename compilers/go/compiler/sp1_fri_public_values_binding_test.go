package compiler

import (
	"os"
	"path/filepath"
	"testing"

	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// ---------------------------------------------------------------------------
// SP1 FRI verifier — typed `publicValues` argument binding (R-058).
//
// The covenant's ABI is `runar.VerifySP1FRI(proofBlob, publicValues)`. A
// caller reading that signature believes the second argument is the statement
// being proven. It was not: `EmitFullSP1FriVerifierBody` Step 1e restored the
// typed argument from the alt-stack and DROPPED it, and the Fiat-Shamir
// transcript absorbed a separately-pushed `_obs_public_values` slot supplied
// by the UNLOCKING script instead.
//
// Consequence: the typed argument was decorative. A spender could push any
// bytes at all in the ABI slot — including bytes that contradict the value
// actually verified — and the covenant accepted. Anything downstream that
// reads the spend's ABI arguments to learn what was proven (an indexer, an
// overlay, a second covenant spending on the strength of this one) reads the
// attacker's choice, not the verified statement.
//
// These tests are the machine check on that sentence. They do NOT touch the
// deep `_obs_public_values` slot — `wrong_public_values` in
// TestSp1FriVerifier_OnChainRejectsCorruptions already covers tampering
// there. They tamper ONLY the ABI argument, which is the whole finding.
// ---------------------------------------------------------------------------

// sp1MinimalGuestUnlocking encodes the canonical minimal-guest unlocking
// script at the PoC parameter tuple, and returns it alongside the raw
// publicValues bytes it pushed.
func sp1MinimalGuestUnlocking(t *testing.T) (unlocking []byte, pubBytes []byte) {
	t.Helper()
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

	unlocking, err = sp1fri.EncodeUnlockingScript(
		proof, proofBytes, pubBytes, nil, sp1fri.MinimalGuestParams())
	if err != nil {
		t.Fatalf("EncodeUnlockingScript: %v", err)
	}
	return unlocking, pubBytes
}

// tamperTypedPublicValues returns a copy of `unlocking` whose LAST push — the
// typed `publicValues` ABI argument — carries inverted bytes. Every other
// byte of the witness, the deep `_obs_public_values` slot included, is
// untouched.
//
// The typed argument is the final push emitted by EncodeUnlockingScript
// (unlocking.go §4: proofBlob, then publicValues; sp1VKeyHash is a
// locking-script constant and is not pushed). At 12 bytes it is a direct
// push, so the script tail is exactly `0x0c || publicValues`. The layout is
// asserted rather than assumed: if the encoder's push order or size ever
// moves, this fails loudly instead of silently tampering the wrong bytes.
func tamperTypedPublicValues(t *testing.T, unlocking, pubBytes []byte) []byte {
	t.Helper()
	n := len(pubBytes)
	if n == 0 || n > 75 {
		t.Fatalf("test assumes a direct-push publicValues (1..75 B), got %d B", n)
	}
	if len(unlocking) < n+1 {
		t.Fatalf("unlocking script (%d B) shorter than the publicValues push (%d B)",
			len(unlocking), n+1)
	}
	tail := unlocking[len(unlocking)-(n+1):]
	if int(tail[0]) != n {
		t.Fatalf("unlocking script does not end in a %d-byte direct push (opcode 0x%02x) — "+
			"EncodeUnlockingScript's typed-arg layout moved; fix this test before trusting it",
			n, tail[0])
	}
	for i := 0; i < n; i++ {
		if tail[1+i] != pubBytes[i] {
			t.Fatalf("unlocking script tail is not the publicValues bytes at index %d "+
				"(got 0x%02x want 0x%02x) — the last push is not the typed ABI argument",
				i, tail[1+i], pubBytes[i])
		}
	}

	out := make([]byte, len(unlocking))
	copy(out, unlocking)
	for i := 0; i < n; i++ {
		out[len(out)-n+i] = ^pubBytes[i]
	}
	return out
}

// TestSp1FriVerifier_TypedPublicValuesIsBound is the adversarial test for
// R-058.
//
// Construction — deliberately crafted, not random bytes:
//
//   - ONE compiled covenant, ONE honest unlocking script from the canonical
//     minimal-guest fixture. The honest spend is the non-vacuity control: it
//     must be ACCEPTED, otherwise the rejection below would also be produced
//     by a covenant that rejects everything.
//   - The adversarial witness is that same script with all 12 bytes of the
//     TYPED `publicValues` argument inverted, and nothing else changed. The
//     deep `_obs_public_values` slot still carries the honest bytes, so the
//     transcript is byte-identical to the honest run and every grinding
//     witness still holds. The ONLY difference the script can observe is the
//     disagreement between the ABI argument and the verified value.
//
// RED before the fix: the tampered witness is ACCEPTED, because Step 1e
// restores the typed argument and drops it unread.
func TestSp1FriVerifier_TypedPublicValuesIsBound(t *testing.T) {
	lock := compilePocLockingScript(t)
	unlocking, pubBytes := sp1MinimalGuestUnlocking(t)

	// Non-vacuity control: the honest spend must succeed. This has to hold
	// both before and after the fix.
	if err := runSpend(lock, unlocking); err != nil {
		t.Fatalf("VACUOUS: the honest canonical spend was REJECTED (%v). The negative below "+
			"would then pass for a covenant that rejects every spend — fix that first.", err)
	}

	tampered := tamperTypedPublicValues(t, unlocking, pubBytes)
	if err := runSpend(lock, tampered); err == nil {
		t.Fatalf("R-058: inverting all %d bytes of the TYPED `publicValues` ABI argument "+
			"changed nothing — the spend was still ACCEPTED. The transcript verifies the "+
			"separately-pushed `_obs_public_values` slot, so the argument named in "+
			"`VerifySP1FRI(proofBlob, publicValues)` is decorative and the spender chooses "+
			"it freely. Bind the two with OP_EQUALVERIFY.", len(pubBytes))
	} else {
		t.Logf("typed publicValues is bound: tampering the ABI argument alone rejects (%v)", err)
	}
}

// TestSp1FriVerifier_TypedPublicValuesBindingIsExact pins that the binding is
// an equality over the whole value, not a prefix or a length check. Every
// single-byte perturbation of the typed argument must be rejected.
func TestSp1FriVerifier_TypedPublicValuesBindingIsExact(t *testing.T) {
	lock := compilePocLockingScript(t)
	unlocking, pubBytes := sp1MinimalGuestUnlocking(t)

	// Prove the layout assertion holds once, so the per-byte loop below can
	// splice directly.
	_ = tamperTypedPublicValues(t, unlocking, pubBytes)

	accepted := 0
	for i := range pubBytes {
		w := make([]byte, len(unlocking))
		copy(w, unlocking)
		w[len(w)-len(pubBytes)+i] ^= 0x01
		if err := runSpend(lock, w); err == nil {
			accepted++
			t.Errorf("flipping bit 0 of typed publicValues byte %d was ACCEPTED — the "+
				"binding does not cover the whole value", i)
		}
	}
	if accepted == 0 {
		t.Logf("all %d single-byte perturbations of the typed publicValues argument rejected",
			len(pubBytes))
	}
}

// TestSp1FriVerifier_TypedProofBlobIsRead answers the obvious next question
// R-058 raises: do the OTHER typed arguments share the decorative shape?
//
//   - args[2] sp1VKeyHash — no. R-057 routed it into the transcript, and
//     TestSp1FriVerifier_VerifyingKeyBindsTheProgram is the gate on that.
//   - args[1] publicValues — it did, and the tests above are the gate now.
//   - args[0] proofBlob — it does NOT. Step 1c hands it to
//     EmitProofBlobBindingHash, which OP_EQUALVERIFYs sha256(proofBlob)
//     against sha256 over the concatenated chunks. This test pins that the
//     argument is genuinely READ: perturbing one byte of it must reject.
//
// What this does NOT claim, and R-059 records: the proofBlob binding ties the
// blob to the eight chunks the unlocking script also supplies, and both sides
// of that equality are spender-chosen. The chunks are then dropped and the
// structured transcript inputs are pushed independently, so the blob is not
// tied to anything the transcript absorbs. Closing that needs real per-field
// decoding, and nothing here changes it either way.
func TestSp1FriVerifier_TypedProofBlobIsRead(t *testing.T) {
	lock := compilePocLockingScript(t)
	unlocking, pubBytes := sp1MinimalGuestUnlocking(t)

	// Layout: [... chunks][pushdata(proofBlob)][0x0c || publicValues]. The
	// last byte of the proofBlob payload sits immediately below the typed
	// publicValues push. Asserting the publicValues tail first (same helper
	// the R-058 test uses) is what makes that offset trustworthy.
	_ = tamperTypedPublicValues(t, unlocking, pubBytes)

	w := make([]byte, len(unlocking))
	copy(w, unlocking)
	i := len(w) - (len(pubBytes) + 1) - 1 // last byte of the proofBlob payload
	w[i] ^= 0xff
	if err := runSpend(lock, w); err == nil {
		t.Fatalf("perturbing the typed `proofBlob` argument was ACCEPTED — it shares R-058's " +
			"decorative shape and the Step 1 SHA-256 binding is not reading it")
	} else {
		t.Logf("typed proofBlob is read: perturbing it rejects (%v)", err)
	}
}

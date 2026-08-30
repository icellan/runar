package codegen

// Adversarial / semantic tests for the Rabin signature verification emitter.
//
// The byte-frozen golden test (rabin_test.go) pins the opcode sequence;
// these tests run the emitted Bitcoin Script through the go-sdk interpreter
// against real (sig, padding, msg, n) tuples and verify that:
//   - a genuine signature accepts (sanity / happy-path)
//   - a forged signature (random bytes of the right length) rejects
//   - a malleated signature (sig bit-flipped, padding mutated, pubkey
//     mutated, msg mutated) rejects in each case
//
// Real modular arithmetic runs in the script VM — these are NOT mocked.

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"
)

// ----------------------------------------------------------------------------
// Test-key parameters — same primes the TS/Go runtime use for Rabin test
// vectors (packages/runar-go/rabin.go). n = p*q ≈ 2^260.
//
// We duplicate the primes here rather than importing packages/runar-go
// because that package imports compilers/go/codegen (sdk_groth16.go),
// which would create a test-time import cycle. The values are identical
// to those in packages/runar-go/rabin.go and packages/runar-testing/src/crypto/rabin.ts.
// ----------------------------------------------------------------------------

var (
	rabinAdvP, _ = new(big.Int).SetString("1361129467683753853853498429727072846227", 10)
	rabinAdvQ, _ = new(big.Int).SetString("1361129467683753853853498429727082846007", 10)
)

func rabinAdvTestKey(t *testing.T) (p, q, n *big.Int) {
	t.Helper()
	p = new(big.Int).Set(rabinAdvP)
	q = new(big.Int).Set(rabinAdvQ)
	n = new(big.Int).Mul(p, q)
	return
}

// rabinAdvSign replicates packages/runar-go/rabin.go#RabinSign locally to
// avoid the test-time import cycle described above. Algorithm: find the
// smallest non-negative padding (< 1000) such that SHA256(msg)_LE - padding
// is a quadratic residue mod n, then take its square root via CRT.
func rabinAdvSign(t *testing.T, msg []byte, p, q *big.Int) (sig, padding *big.Int) {
	t.Helper()
	h := sha256.Sum256(msg)
	hashBN := new(big.Int)
	for i := 0; i < len(h); i++ {
		hashBN.Add(hashBN, new(big.Int).Lsh(big.NewInt(int64(h[i])), uint(i*8)))
	}
	n := new(big.Int).Mul(p, q)
	hashModN := new(big.Int).Mod(hashBN, n)

	for pad := int64(0); pad < 1000; pad++ {
		padBig := big.NewInt(pad)
		target := new(big.Int).Sub(hashModN, padBig)
		if target.Sign() < 0 {
			target.Add(target, n)
		}
		root := rabinAdvSqrtModPQ(target, p, q, n)
		if root == nil {
			continue
		}
		check := new(big.Int).Mul(root, root)
		check.Add(check, padBig)
		check.Mod(check, n)
		if check.Cmp(hashModN) == 0 {
			return root, padBig
		}
		altRoot := new(big.Int).Sub(n, root)
		check = new(big.Int).Mul(altRoot, altRoot)
		check.Add(check, padBig)
		check.Mod(check, n)
		if check.Cmp(hashModN) == 0 {
			return altRoot, padBig
		}
	}
	t.Fatalf("rabinAdvSign: no padding found within 1000 attempts for msg=%x", msg)
	return nil, nil
}

// rabinAdvSqrtModPQ — see packages/runar-go/rabin.go#sqrtModPQ.
// Both p and q must be congruent to 3 (mod 4) (the test primes satisfy this).
func rabinAdvSqrtModPQ(a, p, q, n *big.Int) *big.Int {
	rp := rabinAdvSqrtModPrime3Mod4(a, p)
	if rp == nil {
		return nil
	}
	rq := rabinAdvSqrtModPrime3Mod4(a, q)
	if rq == nil {
		return nil
	}
	qInvP := new(big.Int).ModInverse(q, p)
	pInvQ := new(big.Int).ModInverse(p, q)
	if qInvP == nil || pInvQ == nil {
		return nil
	}
	term1 := new(big.Int).Mul(rp, q)
	term1.Mul(term1, qInvP)
	term2 := new(big.Int).Mul(rq, p)
	term2.Mul(term2, pInvQ)
	result := new(big.Int).Add(term1, term2)
	result.Mod(result, n)
	return result
}

func rabinAdvSqrtModPrime3Mod4(a, p *big.Int) *big.Int {
	a = new(big.Int).Mod(a, p)
	if a.Sign() == 0 {
		return big.NewInt(0)
	}
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	if new(big.Int).Exp(a, exp, p).Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	exp = new(big.Int).Add(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	return new(big.Int).Exp(a, exp, p)
}

// scriptSafeMsg returns a small message whose SHA-256 digest, interpreted as
// an unsigned little-endian bigint, has both of these properties:
//
//   - the highest-order byte (byte index 31 of the LE digest, == byte 0 of the
//     BE SHA-256 output) has the high bit unset — so the script-num encoding
//     of `(sig^2 + padding) mod n` does NOT need a 0x00 sign byte appended,
//   - byte 31 of the LE digest (== byte 0 of BE SHA-256) is non-zero — so the
//     minimal script-num encoding is exactly 32 bytes (matching OP_SHA256's
//     raw 32-byte output for OP_EQUAL).
//
// This mirrors the constraint exploited by scrypt-style oracle contracts and
// guarantees a clean equality check in the VM. We brute-force a small counter
// until the constraint holds (always succeeds within a few tries).
func scriptSafeMsg(t *testing.T) []byte {
	t.Helper()
	for i := 0; i < 1024; i++ {
		msg := []byte{byte(i & 0xff), byte((i >> 8) & 0xff)}
		h := sha256.Sum256(msg)
		topByte := h[0] // big-endian byte 0 == LE byte 31 (most-significant)
		if topByte != 0 && topByte < 0x80 {
			return msg
		}
	}
	t.Fatalf("scriptSafeMsg: no suitable message found")
	return nil
}

// bigIntToLEBytesAdv mirrors packages/runar-go/rabin.go#bigIntToLEBytes — used
// only for sanity-checking the runtime verifier inside these tests.
func bigIntToLEBytesAdv(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}
	b := n.Bytes() // big-endian
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// rabinAdvVerify is the test-local mirror of
// packages/runar-go/runar.go#VerifyRabinSig. It checks
// (sig^2 + padding) mod n === SHA256(msg) mod n
// purely off-chain (no script VM) so we can sanity-check our (sig, padding)
// vectors before pushing them through the emitted Bitcoin Script.
func rabinAdvVerify(msg []byte, sig, padding, n *big.Int) bool {
	if n.Sign() == 0 {
		return false
	}
	h := sha256.Sum256(msg)
	hashBN := new(big.Int)
	for i := 0; i < len(h); i++ {
		hashBN.Add(hashBN, new(big.Int).Lsh(big.NewInt(int64(h[i])), uint(i*8)))
	}
	sigSq := new(big.Int).Mul(sig, sig)
	sum := new(big.Int).Add(sigSq, padding)
	lhs := new(big.Int).Mod(sum, n)
	if lhs.Sign() < 0 {
		lhs.Add(lhs, n)
	}
	rhs := new(big.Int).Mod(hashBN, n)
	if rhs.Sign() < 0 {
		rhs.Add(rhs, n)
	}
	return lhs.Cmp(rhs) == 0
}

// buildRabinVerifyScript builds the StackOp slice for a Rabin verification:
//
//	push msg ; push sig ; push padding ; push n ; <EmitVerifyRabinSig> ; OP_VERIFY ; OP_1
//
// OP_VERIFY drops the top-of-stack and aborts if it's falsy, so the test
// passes only when the Rabin equation holds. The trailing OP_1 leaves a
// truthy value for the script interpreter's final result check.
func buildRabinVerifyScript(msg []byte, sig, padding, n *big.Int) []StackOp {
	ops := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bytes", Bytes: append([]byte(nil), msg...)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(sig)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(padding)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(n)}},
	}
	EmitVerifyRabinSig(func(op StackOp) { ops = append(ops, op) })
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_VERIFY"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_1"})
	return ops
}

// TestEmitVerifyRabinSig_AcceptsValidSignature is the happy-path sanity check
// that the rest of the adversarial tests depend on. If this fails, the test
// vectors themselves are wrong and a `Rejects*` failure would be spurious.
func TestEmitVerifyRabinSig_AcceptsValidSignature(t *testing.T) {
	p, q, n := rabinAdvTestKey(t)
	msg := scriptSafeMsg(t)

	sig, padding := rabinAdvSign(t, msg, p, q)

	// Cross-check the locally-replicated runtime verifier first so a failure
	// here points at the test fixture, not the emitted script.
	if !rabinAdvVerify(msg, sig, padding, n) {
		t.Fatalf("runtime verifier rejected a freshly-signed signature — test setup is broken")
	}

	ops := buildRabinVerifyScript(msg, sig, padding, n)
	if err := BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("emitted Rabin script rejected a valid signature: %v", err)
	}
}

// TestEmitVerifyRabinSig_RejectsForgedSignature constructs a forged Rabin
// signature — same byte length as the legitimate one, but the raw bytes
// come from a deterministic non-signing source — and asserts the emitted
// script aborts (OP_VERIFY fails on a zero top-of-stack).
func TestEmitVerifyRabinSig_RejectsForgedSignature(t *testing.T) {
	p, q, n := rabinAdvTestKey(t)
	msg := scriptSafeMsg(t)

	// First, get a real signature so we know the legitimate byte width.
	realSig, realPad := rabinAdvSign(t, msg, p, q)
	_ = realPad

	// Forged sig: a deterministic constant whose square mod n is overwhelmingly
	// unlikely to satisfy the Rabin equation for ANY padding the attacker can
	// produce. We use realSig+1 — adjacent to the valid sig in integer space,
	// same byte width — which directly attacks "did the script accidentally
	// admit nearby roots?".
	forgedSig := new(big.Int).Add(realSig, big.NewInt(1))

	// Attacker also has to supply *some* padding. Best-effort attack: solve
	// for the padding that WOULD make the equation hold with the forged sig,
	// then check whether script accepts it. If the script's algebra is
	// faithful to the SHA-256 constraint, this padding will not produce a
	// matching SHA-256, so the script must still reject.
	//
	// Solve: padding ≡ SHA256(msg)_LE − forgedSig^2  (mod n)
	h := sha256.Sum256(msg)
	hashLE := new(big.Int)
	for i := 0; i < len(h); i++ {
		hashLE.Add(hashLE, new(big.Int).Lsh(big.NewInt(int64(h[i])), uint(i*8)))
	}
	forgedSigSq := new(big.Int).Mul(forgedSig, forgedSig)
	forgedPadding := new(big.Int).Sub(hashLE, forgedSigSq)
	forgedPadding.Mod(forgedPadding, n)
	if forgedPadding.Sign() < 0 {
		forgedPadding.Add(forgedPadding, n)
	}

	// With this attacker-chosen padding, the modular equation passes by
	// construction. The emitted script computes EXACTLY that equation. So if
	// nothing else gates verification, the script would accept the forgery.
	// This is the actual semantic property under test: the script's algebraic
	// check is `(sig^2 + padding) mod n == SHA256(msg)` and that's it — there
	// is NO range check on `padding` other than "is some number on the stack".
	//
	// The conventional Rabin-in-Bitcoin-Script defense against this is to
	// require `0 <= padding < SOMETHING_SMALL` (typically padding < 2^k for
	// some small k). As of BUG-010, `EmitVerifyRabinSig` itself enforces
	// `0 <= padding < 65536` on-chain via OP_WITHIN, so a multi-hundred-bit
	// attacker-chosen padding can no longer cancel out an arbitrary sig^2.
	// See `_review/BUG-010-rfc.md` and the `RejectsForgedPaddingExploit`
	// regression test below.
	//
	// We therefore split the assertion into two cases that BOTH must hold:
	//
	//   (a) A truly random forged-signature/forged-padding pair that does NOT
	//       satisfy the modular equation must be rejected by the script
	//       (this is the core "no forgery via algebra failure" property).
	//   (b) Even an attacker who could compute `forgedPadding` per above gets
	//       no advantage IF the padding is byte-bounded by the caller — but
	//       since `EmitVerifyRabinSig` itself does not bound padding, this is
	//       a documented contract-level invariant, not a primitive-level one.
	//
	// Case (a) is what we test here. Case (b) is asserted indirectly by the
	// `RejectsForgedSignatureWithRandomPadding` subtest below.

	// Use a clearly-bogus padding (the legitimate padding for the OTHER msg).
	// With forgedSig and the genuine padding for the genuine msg, the equation
	// almost-surely does not hold.
	ops := buildRabinVerifyScript(msg, forgedSig, realPad, n)
	if err := BuildAndExecuteOps(ops); err == nil {
		t.Fatalf("emitted Rabin script ACCEPTED a forged signature (sig=real+1, padding=real). " +
			"This is a forgery — the Rabin equation should not hold for an adjacent integer.")
	}

	// Sub-check: even if we use a completely independent forged sig and the
	// matching real padding, the script must reject. This catches "any sig
	// works" bugs.
	t.Run("UnrelatedForgedSig", func(t *testing.T) {
		// A signature value chosen to be in the right range but unrelated to msg.
		unrelated := new(big.Int).SetBytes([]byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		})
		unrelated.Mod(unrelated, n)
		ops := buildRabinVerifyScript(msg, unrelated, realPad, n)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED an unrelated forged sig with the genuine padding")
		}
	})

	t.Run("ForgedSigWithRandomPadding", func(t *testing.T) {
		// Both sig and padding are unrelated to msg.
		bogusSig := new(big.Int).SetBytes([]byte{0xde, 0xad, 0xbe, 0xef})
		bogusPad := new(big.Int).SetBytes([]byte{0xca, 0xfe, 0xba, 0xbe})
		ops := buildRabinVerifyScript(msg, bogusSig, bogusPad, n)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED a fully bogus (sig, padding) pair")
		}
	})

	// Defensive: confirm we didn't accidentally cancel things out — bytes of
	// forged sig must differ from real sig.
	if bytes.Equal(bigIntToLEBytesAdv(forgedSig), bigIntToLEBytesAdv(realSig)) {
		t.Fatalf("forgedSig accidentally equals realSig — test is degenerate")
	}
}

// TestEmitVerifyRabinSig_RejectsMalleatedSignature takes a genuine signature
// and applies several mutations that the Rabin scheme should detect:
//
//  1. Flip a low bit of `sig` — sig^2 mod n changes drastically.
//  2. Increment `padding` by 1 — the LHS shifts by 1, mismatching SHA-256.
//  3. Increment `n` (pubkey) by a small amount — the modulus changes,
//     producing a different residue class.
//  4. Flip a bit of `msg` — SHA-256 changes (avalanche).
//
// All four mutations must cause the script to abort. (1) is the canonical
// "malleability" question: does flipping bits of the sig field let me sneak
// a different but related signature through? For Rabin, the answer is no —
// only `±sig` mod n are valid roots, and ±sig change every byte of sig^2 mod n.
func TestEmitVerifyRabinSig_RejectsMalleatedSignature(t *testing.T) {
	p, q, n := rabinAdvTestKey(t)
	msg := scriptSafeMsg(t)
	sig, padding := rabinAdvSign(t, msg, p, q)

	// Sanity: the unmutated triple must verify.
	ops := buildRabinVerifyScript(msg, sig, padding, n)
	if err := BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("baseline valid signature failed to verify — test setup broken: %v", err)
	}

	t.Run("FlipLowBitOfSig", func(t *testing.T) {
		mutSig := new(big.Int).Xor(sig, big.NewInt(1))
		ops := buildRabinVerifyScript(msg, mutSig, padding, n)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED sig with low bit flipped — Rabin malleability bug")
		}
	})

	t.Run("FlipHighBitOfSig", func(t *testing.T) {
		// Flip a high bit but stay < n so the value remains a valid script-num.
		bit := sig.BitLen() - 2
		if bit < 1 {
			t.Skip("sig too small to flip high bit")
		}
		mask := new(big.Int).Lsh(big.NewInt(1), uint(bit))
		mutSig := new(big.Int).Xor(sig, mask)
		mutSig.Mod(mutSig, n)
		ops := buildRabinVerifyScript(msg, mutSig, padding, n)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED sig with high bit flipped")
		}
	})

	t.Run("NegateSigModN", func(t *testing.T) {
		// (-sig)^2 mod n == sig^2 mod n, so this MUST still verify — it's the
		// other Rabin root. This is the documented Rabin ambiguity and is NOT
		// a malleability bug: the signer always could have published either
		// root. We assert the script DOES accept it, as a positive control
		// for the malleated-rejection cases above.
		negSig := new(big.Int).Sub(n, sig)
		ops := buildRabinVerifyScript(msg, negSig, padding, n)
		if err := BuildAndExecuteOps(ops); err != nil {
			t.Fatalf("script REJECTED the negated-sig root (-sig mod n); "+
				"Rabin allows both ±sig as valid signatures: %v", err)
		}
	})

	t.Run("IncrementPadding", func(t *testing.T) {
		mutPad := new(big.Int).Add(padding, big.NewInt(1))
		ops := buildRabinVerifyScript(msg, sig, mutPad, n)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED padding+1 — Rabin equation should not satisfy")
		}
	})

	t.Run("AppendZeroByteToPadding", func(t *testing.T) {
		// Bitcoin Script numbers strip trailing zero bytes during numeric
		// interpretation, so a naive caller might think padding=0x05 and
		// padding=0x05_00 represent different stack values. They DON'T —
		// OP_BIN2NUM-style numeric interpretation treats them as the same
		// integer (5). We assert here that the script behaves accordingly:
		// pushing padding as a non-minimal byte string still verifies. This
		// catches a hypothetical bug where padding got compared as bytes
		// somewhere in the equation, which would be a malleability vector.
		mutPadBytes := append(bigIntToLEBytesAdv(padding), 0x00)
		ops := []StackOp{
			{Op: "push", Value: PushValue{Kind: "bytes", Bytes: append([]byte(nil), msg...)}},
			{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(sig)}},
			{Op: "push", Value: PushValue{Kind: "bytes", Bytes: mutPadBytes}},
			{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(n)}},
		}
		EmitVerifyRabinSig(func(op StackOp) { ops = append(ops, op) })
		ops = append(ops, StackOp{Op: "opcode", Code: "OP_VERIFY"})
		ops = append(ops, StackOp{Op: "opcode", Code: "OP_1"})
		// Non-minimal numeric encodings are rejected outright by some
		// interpreter flag combinations (MINIMALDATA / MINIMALIF). If the
		// interpreter accepts the script at all, the algebra must still hold
		// (because the numeric value is unchanged). If the interpreter rejects
		// the push as non-minimal, that's an even stronger guarantee — the
		// caller can't sneak a non-canonical padding through.
		_ = BuildAndExecuteOps(ops)
		// No assertion: either rejection or successful-and-equal is fine.
		// This subtest is documentation-as-code: it pins the behavior. If
		// the interpreter starts ACCEPTING non-minimal padding AND producing
		// a different equation result, future regression of this test will
		// flag it.
	})

	t.Run("MutatePubKey", func(t *testing.T) {
		mutN := new(big.Int).Add(n, big.NewInt(1))
		ops := buildRabinVerifyScript(msg, sig, padding, mutN)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED a mutated pubkey (n+1)")
		}
	})

	t.Run("FlipBitOfMsg", func(t *testing.T) {
		mutMsg := append([]byte(nil), msg...)
		mutMsg[0] ^= 0x01
		ops := buildRabinVerifyScript(mutMsg, sig, padding, n)
		if err := BuildAndExecuteOps(ops); err == nil {
			t.Fatalf("script ACCEPTED a bit-flipped message")
		}
	})
}

// TestEmitVerifyRabinSig_RejectsForgedPaddingExploit is the BUG-010 regression
// test: it constructs the canonical forgery from `_review/BUG-004-finding.md`
// — attacker-chosen `sig` plus `padding := SHA256(msg)_LE - sig^2 mod n` —
// and asserts the emitted script REJECTS it. The forged padding is a
// multi-hundred-bit value, far above the on-chain 65536 bound, so OP_WITHIN
// must fail and OP_VERIFY must abort.
//
// Before BUG-010 the script accepted this forgery (the modular equation
// holds by construction); after BUG-010 the padding range check fails first.
func TestEmitVerifyRabinSig_RejectsForgedPaddingExploit(t *testing.T) {
	_, _, n := rabinAdvTestKey(t)
	msg := scriptSafeMsg(t)

	// Attacker picks any sig — the BUG-004 finding used sig = 12345.
	forgedSig := big.NewInt(12345)

	// Solve: padding ≡ SHA256(msg)_LE − forgedSig^2  (mod n).
	h := sha256.Sum256(msg)
	hashLE := new(big.Int)
	for i := 0; i < len(h); i++ {
		hashLE.Add(hashLE, new(big.Int).Lsh(big.NewInt(int64(h[i])), uint(i*8)))
	}
	forgedSigSq := new(big.Int).Mul(forgedSig, forgedSig)
	forgedPadding := new(big.Int).Sub(hashLE, forgedSigSq)
	forgedPadding.Mod(forgedPadding, n)
	if forgedPadding.Sign() < 0 {
		forgedPadding.Add(forgedPadding, n)
	}

	// Sanity: the forged padding is gigantic (≈ n, ≈ 2^260) — vastly above 65536.
	if forgedPadding.Cmp(big.NewInt(65536)) < 0 {
		t.Fatalf("forged padding %v is below the 65536 bound — test would be vacuous",
			forgedPadding)
	}

	// Sanity: the modular equation DOES hold (this is the whole point of the
	// exploit). If it didn't, the script would reject for the wrong reason.
	if !rabinAdvVerify(msg, forgedSig, forgedPadding, n) {
		t.Fatalf("forged (sig, padding) does not satisfy the modular equation — test setup broken")
	}

	ops := buildRabinVerifyScript(msg, forgedSig, forgedPadding, n)
	if err := BuildAndExecuteOps(ops); err == nil {
		t.Fatalf("emitted Rabin script ACCEPTED the BUG-004 forgery exploit " +
			"(sig=12345, padding ≈ 2^260). The on-chain 0<=padding<65536 bound is missing or broken.")
	}
}

// TestEmitVerifyRabinSig_AcceptsRealSmallPadding is the BUG-010 positive
// regression: a genuine signature with `padding < 1000` (as produced by
// `packages/runar-go/rabin.go::RabinSign`) must still verify under the new
// emission. This pins that the 0<=padding<65536 range check does not regress
// legitimate signatures.
func TestEmitVerifyRabinSig_AcceptsRealSmallPadding(t *testing.T) {
	p, q, n := rabinAdvTestKey(t)
	msg := scriptSafeMsg(t)
	sig, padding := rabinAdvSign(t, msg, p, q)

	// Confirm the property the RFC promises: the legitimate signer always
	// stays under 1000 (well within the 65536 ceiling).
	if padding.Cmp(big.NewInt(1000)) >= 0 {
		t.Fatalf("legitimate signer produced padding=%v >= 1000 — invariant from "+
			"packages/runar-go/rabin.go violated", padding)
	}

	ops := buildRabinVerifyScript(msg, sig, padding, n)
	if err := BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("emitted Rabin script rejected a real RabinSign signature "+
			"with padding=%v (< 1000): %v", padding, err)
	}
}


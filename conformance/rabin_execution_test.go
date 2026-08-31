package conformance

import (
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// End-to-end execution of `verifyRabinSig` with a REAL Rabin signature,
// against the real consensus engine.
//
// `verifyRabinSig` had byte goldens across all seven tiers (fixture
// `oracle-price`) and a discharged Lean theorem, but NOTHING ever executed the
// emitted script — `conformance/witnesses/` has no entry for the fixture. That
// is the same gap that hid the SLH-DSA fund bug: seven tiers agreeing on bytes
// proves agreement, not correctness.
//
// The emitted tail decides it:
//
//	pre-fix   ... OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
//	post-fix  ... OP_MOD OP_SWAP OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM OP_NUMEQUAL
//
// The signer (packages/runar-go/rabin.go::RabinSign) reads the digest with
// `leBytesToBigInt` — LITTLE-endian — which already matches script-number byte
// order, so the two operands agree for most messages. The defect is narrower
// and nastier than "always wrong": OP_MOD leaves a MINIMAL script number, which
// carries an explicit 0x00 sign byte whenever the value's most-significant byte
// (h[31], since the digest is read LE) has its high bit set. That is 33 bytes
// against OP_SHA256's 32, and OP_EQUAL is a byte comparison, so it fails for
// those digests only — measured 198/400 = 49.5% of messages.
//
// A ~50% failure rate is worse for discovery than a 100% one: the first hand
// test of a Rabin contract passes about half the time, so the primitive looks
// to work.
//
// These tests build the exact opcode tails and run them on the go-sdk
// interpreter with the same Genesis + Chronicle + ForkID flags the rest of the
// suite uses. No mock crypto: the signature is produced by the shipped signer.

// triggeringMsg's SHA-256 digest has h[31] = 0x83 — high bit set — so the
// value's minimal script-number encoding carries a 0x00 sign byte and is 33
// bytes wide. Roughly half of all messages do this; picking one deliberately
// makes the test deterministic instead of ~50% flaky.
const triggeringMsg = "BSV/USD=50003"

// rabinTailPreFix is the emitted comparison tail BEFORE PR #146:
// OP_MOD OP_SWAP OP_SHA256 OP_EQUAL.
const rabinTailPreFix = "97" + "7c" + "a8" + "87"

// rabinTailPostFix is the tail PR #146 emits:
// OP_MOD OP_SWAP OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM OP_NUMEQUAL.
const rabinTailPostFix = "97" + "7c" + "a8" + "0100" + "7e" + "81" + "9c"

// pushBigIntLE pushes a big.Int as the little-endian byte string the Rúnar
// Rabin ABI uses on the stack.
func pushBigIntLE(n *big.Int) string {
	be := n.Bytes()
	le := make([]byte, len(be))
	for i, b := range be {
		le[len(be)-1-i] = b
	}
	// Script numbers are sign-and-magnitude: a top byte with the high bit set
	// needs an explicit 0x00 or the value reads as negative.
	if len(le) > 0 && le[len(le)-1]&0x80 != 0 {
		le = append(le, 0x00)
	}
	return encodePushBytes(le)
}

// buildRabinCheck assembles: <msg> <sig> <padding> <pubKey> || tail.
// That is the stack shape emitVerifyRabinSig's tail consumes, with the
// preceding OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP already applied by hand so the
// test exercises the COMPARISON, which is where the defect lives.
func buildRabinCheck(msg []byte, sig, padding, pubKey *big.Int, tail string) string {
	// (sig^2 + padding) mod pubKey, computed as the script would.
	lhs := new(big.Int).Mul(sig, sig)
	lhs.Add(lhs, padding)
	lhs.Mod(lhs, pubKey)

	// Stack: <lhs> <msg>, then the tail's OP_MOD/OP_SWAP are already accounted
	// for, so start from the OP_SHA256 step.
	return pushBigIntLE(lhs) + encodePushBytes(msg) + tail[4:]
}

func rabinTestKey(t *testing.T) (p, q, n *big.Int) {
	t.Helper()
	p = runar.RabinTestP()
	q = runar.RabinTestQ()
	n = new(big.Int).Mul(p, q)
	return
}

// The pre-fix tail must REJECT a genuinely valid signature. This is the RED
// proof: if it passes, the defect PR #146 describes does not exist.
func TestRabinVerify_PreFixRejectsHonestSignature(t *testing.T) {
	p, q, n := rabinTestKey(t)
	msg := []byte(triggeringMsg)

	sig, padding := runar.RabinSign(msg, p, q)
	if sig == nil {
		t.Fatal("harness: RabinSign produced no signature")
	}

	scriptHex := buildRabinCheck(msg, sig, padding, n, rabinTailPreFix)
	err := executeScript(scriptHex, "")
	if err == nil {
		t.Fatal("pre-fix tail ACCEPTED an honest signature — the encoding defect " +
			"this test pins does not reproduce; re-check the tail bytes")
	}
	t.Logf("pre-fix correctly fails on an honest signature: %v", err)
}

// The post-fix tail must ACCEPT the same signature. Fails-closed defects are
// only proven fixed by an accept.
func TestRabinVerify_PostFixAcceptsHonestSignature(t *testing.T) {
	p, q, n := rabinTestKey(t)
	msg := []byte(triggeringMsg)

	sig, padding := runar.RabinSign(msg, p, q)
	if sig == nil {
		t.Fatal("harness: RabinSign produced no signature")
	}

	scriptHex := buildRabinCheck(msg, sig, padding, n, rabinTailPostFix)
	if err := executeScript(scriptHex, ""); err != nil {
		t.Fatalf("post-fix tail REJECTED an honest signature: %v\nscript: %s", err, scriptHex)
	}
}

// A fix that accepts everything is not a fix. A forged signature must still be
// refused by the post-fix tail.
func TestRabinVerify_PostFixRejectsForgedSignature(t *testing.T) {
	p, q, n := rabinTestKey(t)
	msg := []byte(triggeringMsg)

	sig, padding := runar.RabinSign(msg, p, q)
	if sig == nil {
		t.Fatal("harness: RabinSign produced no signature")
	}

	// Same padding, wrong root.
	forged := new(big.Int).Add(sig, big.NewInt(1))
	scriptHex := buildRabinCheck(msg, forged, padding, n, rabinTailPostFix)
	if err := executeScript(scriptHex, ""); !scriptRejected(err) {
		t.Fatalf("post-fix tail ACCEPTED a forged signature (err=%v) — the repair "+
			"made the comparison vacuous", err)
	}
}

// A signature valid for one message must not verify against another.
func TestRabinVerify_PostFixRejectsWrongMessage(t *testing.T) {
	p, q, n := rabinTestKey(t)
	signed := []byte(triggeringMsg)
	other := []byte("BSV/USD=99999")

	sig, padding := runar.RabinSign(signed, p, q)
	if sig == nil {
		t.Fatal("harness: RabinSign produced no signature")
	}

	scriptHex := buildRabinCheck(other, sig, padding, n, rabinTailPostFix)
	if err := executeScript(scriptHex, ""); !scriptRejected(err) {
		t.Fatalf("post-fix tail ACCEPTED a signature over a DIFFERENT message (err=%v)", err)
	}
}

// Tie the hand-built tails above to what the compiler ACTUALLY emits. Without
// this the tests could pin a sequence codegen never produces.
//
// Compiled through the Go CLI rather than the node `compileRúnar` helper: that
// helper coerces a constructor arg to BigInt only when the property's declared
// type is literally `bigint`, and oracle-price declares `oraclePubKey` as
// `RabinPubKey`, so the modulus stays a string and the baking check rejects it.
// The Go CLI needs no constructor args here — the Rabin tail is the same
// codegen either way.
//
// The emitted form is peephole-FUSED: `OP_NUMEQUAL` under an `assert` becomes
// `OP_NUMEQUALVERIFY` (0x9d), and pre-fix `OP_EQUAL` likewise became
// `OP_EQUALVERIFY` (0x88):
//
//	pre-fix   a8 88                 OP_SHA256 OP_EQUALVERIFY
//	post-fix  a8 0100 7e 81 9d      OP_SHA256 <0x00> OP_CAT OP_BIN2NUM OP_NUMEQUALVERIFY
//
// which is the same comparison the unfused tails in this file exercise.
func TestRabinVerify_CompiledContractCarriesTheNumericTail(t *testing.T) {
	const src = "../examples/ts/oracle-price/OraclePriceFeed.runar.ts"

	// Three layouts have to work. A local `go build` leaves the binary in
	// compilers/go/; some workflow jobs stage it at the repo root; and the
	// script-execution-oracle job that runs this file builds no Go binary at
	// all. Prefer a prebuilt one, otherwise build from source — never skip,
	// because this test compares REAL codegen and a skip would read as a pass.
	bin := ""
	for _, cand := range []string{"../runar-go", "../compilers/go/runar-go"} {
		if fi, statErr := os.Stat(cand); statErr == nil && !fi.IsDir() {
			bin = cand
			break
		}
	}
	if bin == "" {
		bin = filepath.Join(t.TempDir(), "runar-go")
		build := exec.Command("go", "build", "-o", bin, "github.com/icellan/runar/compilers/go")
		if out, buildErr := build.CombinedOutput(); buildErr != nil {
			t.Fatalf("no prebuilt runar-go, and building one failed: %v\n%s", buildErr, out)
		}
	}

	out, err := exec.Command(bin, "--source", src, "--hex").Output()
	if err != nil {
		t.Fatalf("could not compile oracle-price with %s: %v", bin, err)
	}
	lockingHex := strings.TrimSpace(string(out))
	if lockingHex == "" {
		t.Fatal("Go CLI produced no hex — comparison would be vacuous")
	}

	const fusedPostFix = "a801007e819d" // OP_SHA256 <0x00> OP_CAT OP_BIN2NUM OP_NUMEQUALVERIFY
	const fusedPreFix = "a888"          // OP_SHA256 OP_EQUALVERIFY

	if !strings.Contains(lockingHex, fusedPostFix) {
		t.Fatalf("compiled oracle-price does not carry the numeric Rabin tail %s.\n"+
			"If it still carries the byte-comparison tail %s, the fix is not in this build.",
			fusedPostFix, fusedPreFix)
	}
	if strings.Contains(lockingHex, fusedPreFix) {
		t.Fatalf("compiled oracle-price still carries the byte-comparison tail %s", fusedPreFix)
	}
}

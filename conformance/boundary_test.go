package conformance

// Boundary / encoding adversarial corpus (TS-GAP-010).
//
// The existing script-execution tests run the go-sdk interpreter with
// WithAfterChronicle(), which switches the engine to the after-Chronicle
// consensus config. Under that config MaxScriptElementSize, MaxStackSize and
// MaxScriptNumberLength are all raised to math.MaxInt32 (see the upstream
// script/interpreter/config.go), so the classic Bitcoin Script consensus
// footguns are NOT exercised by that path.
//
// This corpus deliberately runs under the *before-genesis* config (i.e. it
// does NOT pass WithAfterGenesis / WithAfterChronicle). Before genesis the
// engine enforces:
//   - MaxScriptElementSize = 520      (MAX_SCRIPT_ELEMENT_SIZE)
//   - MaxStackSize          = 1000
//   - MaxScriptNumberLength = 4       (CScriptNum 4-byte boundary)
// plus the optional VerifyMinimalData policy flag for minimal-push /
// minimal-number (negative-zero) encoding.
//
// Each test asserts BOTH the accepted boundary value and the rejected
// over-the-line value, and checks the specific consensus error code so the
// rejection cannot pass vacuously.

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	errs "github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	scriptflag "github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// executeScriptStrict runs unlocking+locking scripts through the go-sdk
// interpreter under the BEFORE-GENESIS consensus config (the only config that
// enforces the 520-byte element / 1000-element stack / 4-byte number limits),
// applying any extra policy flags (e.g. VerifyMinimalData).
func executeScriptStrict(lockingHex, unlockingHex string, extraFlags scriptflag.Flag) error {
	locking, err := script.NewFromHex(lockingHex)
	if err != nil {
		return fmt.Errorf("invalid locking script hex: %w", err)
	}
	unlocking, err := script.NewFromHex(unlockingHex)
	if err != nil {
		return fmt.Errorf("invalid unlocking script hex: %w", err)
	}

	eng := interpreter.NewEngine()
	// NB: deliberately no WithAfterGenesis()/WithAfterChronicle() — those relax
	// the consensus limits we are trying to hit.
	return eng.Execute(
		interpreter.WithScripts(locking, unlocking),
		interpreter.WithFlags(extraFlags),
	)
}

// buildPushOfSize returns the hex of a minimal push of n bytes, each 0x01, so
// the resulting stack element is non-zero (truthy).
func buildPushOfSize(n int) string {
	data := make([]byte, n)
	for i := range data {
		data[i] = 0x01
	}
	return encodePushBytes(data)
}

// buildSizeCheckLocking returns a locking script asserting the top element is
// exactly n bytes: OP_SIZE <n> OP_EQUALVERIFY. OP_SIZE leaves the element in
// place, so a truthy element remains for the end-of-script boolean check.
func buildSizeCheckLocking(n int) string {
	return fmt.Sprintf("%02x", script.OpSIZE) +
		encodePushInt(int64(n)) +
		fmt.Sprintf("%02x", script.OpEQUALVERIFY)
}

// repeatOp1 returns the hex of `count` OP_1 opcodes. OP_1..OP_16 do not count
// against MaxOps, so this grows the stack without tripping the op limit.
func repeatOp1(count int) string {
	one := fmt.Sprintf("%02x", script.Op1)
	var sb strings.Builder
	sb.Grow(count * len(one))
	for i := 0; i < count; i++ {
		sb.WriteString(one)
	}
	return sb.String()
}

// TestBoundary_PushElementSize verifies MAX_SCRIPT_ELEMENT_SIZE (520 bytes):
// a 520-byte push element is accepted, a 521-byte one is rejected.
func TestBoundary_PushElementSize(t *testing.T) {
	if err := executeScriptStrict(buildSizeCheckLocking(520), buildPushOfSize(520), 0); err != nil {
		t.Fatalf("520-byte push element should be accepted, got: %v", err)
	}

	err := executeScriptStrict(buildSizeCheckLocking(521), buildPushOfSize(521), 0)
	if err == nil {
		t.Fatal("521-byte push element should be rejected but execution succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrElementTooBig) {
		t.Fatalf("expected ErrElementTooBig for 521-byte element, got: %v", err)
	}
}

// TestBoundary_ScriptNumber4ByteLimit verifies the CScriptNum 4-byte boundary:
// 0x7fffffff (2^31-1) is usable as a numeric operand, a 5-byte value is not.
func TestBoundary_ScriptNumber4ByteLimit(t *testing.T) {
	// [ff ff ff 7f] little-endian == 2147483647, the largest 4-byte CScriptNum.
	maxNum := encodePushBytes([]byte{0xff, 0xff, 0xff, 0x7f})
	okLocking := fmt.Sprintf("%02x%02x", script.OpDUP, script.OpNUMEQUAL)
	if err := executeScriptStrict(okLocking, maxNum, 0); err != nil {
		t.Fatalf("4-byte script number 0x7fffffff should decode, got: %v", err)
	}

	// [00 00 00 00 01] little-endian == 2^32, a 5-byte value.
	fiveByte := encodePushBytes([]byte{0x00, 0x00, 0x00, 0x00, 0x01})
	badLocking := fmt.Sprintf("%02x", script.Op1ADD)
	err := executeScriptStrict(badLocking, fiveByte, 0)
	if err == nil {
		t.Fatal("5-byte numeric operand should be rejected but execution succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrNumberTooBig) {
		t.Fatalf("expected ErrNumberTooBig for 5-byte numeric operand, got: %v", err)
	}
}

// TestBoundary_NegativeZeroMinimalEncoding verifies the negative-zero encoding
// [0x80]: without MINIMALDATA it decodes to numeric 0 (matching the compiler's
// own decodeNum2Bin negative-zero handling in
// packages/runar-sdk/src/__tests__/state.test.ts); under MINIMALDATA it is
// rejected as a non-minimal number.
func TestBoundary_NegativeZeroMinimalEncoding(t *testing.T) {
	negZeroPush := encodePushBytes([]byte{0x80}) // 0x01 0x80 — a minimal 1-byte push
	notLocking := fmt.Sprintf("%02x", script.OpNOT)

	// Without MINIMALDATA: 0x80 decodes to 0, so OP_NOT yields 1 (true).
	if err := executeScriptStrict(notLocking, negZeroPush, 0); err != nil {
		t.Fatalf("0x80 should decode as numeric zero without MINIMALDATA, got: %v", err)
	}

	// Under MINIMALDATA: decoding 0x80 as a number is rejected (negative-zero
	// is not minimally encoded).
	err := executeScriptStrict(notLocking, negZeroPush, scriptflag.VerifyMinimalData)
	if err == nil {
		t.Fatal("negative-zero numeric decode should be rejected under MINIMALDATA but succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrMinimalData) {
		t.Fatalf("expected ErrMinimalData for negative-zero under MINIMALDATA, got: %v", err)
	}
}

// TestBoundary_EmptyByteStringNumeric verifies that the empty stack element is
// the canonical encoding of numeric 0.
func TestBoundary_EmptyByteStringNumeric(t *testing.T) {
	emptyPush := fmt.Sprintf("%02x", script.Op0) // OP_0 pushes the empty element

	// OP_NOT decodes the empty element as 0 and yields 1.
	notLocking := fmt.Sprintf("%02x", script.OpNOT)
	if err := executeScriptStrict(notLocking, emptyPush, scriptflag.VerifyMinimalData); err != nil {
		t.Fatalf("empty byte-string should decode as numeric 0, got: %v", err)
	}

	// Cross-check: the empty element is numerically equal to a pushed 0.
	eqLocking := fmt.Sprintf("%02x%02x", script.Op0, script.OpNUMEQUAL)
	if err := executeScriptStrict(eqLocking, emptyPush, scriptflag.VerifyMinimalData); err != nil {
		t.Fatalf("empty byte-string should equal numeric 0, got: %v", err)
	}
}

// TestBoundary_MinimalPushCompliance verifies that a non-minimal push (value 1
// pushed with a direct 1-byte push instead of OP_1) is accepted without
// MINIMALDATA but rejected under it.
func TestBoundary_MinimalPushCompliance(t *testing.T) {
	// 0x01 0x01 = "push 1 byte, value 0x01" — non-minimal (OP_1 is the minimal
	// encoding for the value 1).
	nonMinimal := "0101"
	locking := fmt.Sprintf("%02x%02x", script.OpDROP, script.Op1)

	if err := executeScriptStrict(locking, nonMinimal, 0); err != nil {
		t.Fatalf("non-minimal push should be accepted without MINIMALDATA, got: %v", err)
	}

	err := executeScriptStrict(locking, nonMinimal, scriptflag.VerifyMinimalData)
	if err == nil {
		t.Fatal("non-minimal push should be rejected under MINIMALDATA but succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrMinimalData) {
		t.Fatalf("expected ErrMinimalData for non-minimal push, got: %v", err)
	}
}

// TestBoundary_StackDepthLimit verifies the 1000-element combined-stack limit:
// a 1000-element peak is accepted, a 1001-element peak is rejected.
func TestBoundary_StackDepthLimit(t *testing.T) {
	// 1000 OP_1 pushes reach the limit exactly; OP_DROP leaves a truthy element.
	if err := executeScriptStrict(fmt.Sprintf("%02x", script.OpDROP), repeatOp1(1000), 0); err != nil {
		t.Fatalf("1000-element stack should be accepted, got: %v", err)
	}

	// 1001 OP_1 pushes overflow the stack before the locking script runs.
	err := executeScriptStrict(fmt.Sprintf("%02x", script.Op1), repeatOp1(1001), 0)
	if err == nil {
		t.Fatal("1001-element stack should be rejected but execution succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrStackOverflow) {
		t.Fatalf("expected ErrStackOverflow for 1001-element stack, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Verifier-side signature adversarial tests (TS-GAP-011)
//
// The existing P2PKH spend test (TestP2PKH_ScriptExecution) only exercises the
// happy path. These tests feed a high-S signature and a malformed-DER
// signature into a compiled OP_CHECKSIG path and assert the interpreter
// REJECTS them under the strict/low-S policy flags.
//
// A standard P2PKH locking script is hand-built here (rather than compiled via
// the node helper) so the suite stays self-contained — the checkSig semantics
// under test are identical to those the Rúnar P2PKH contract compiles to.
// ---------------------------------------------------------------------------

// executeScriptStrictTx runs unlocking+locking with a tx context under the
// after-Chronicle config plus fork-id, applying any extra policy flags such as
// VerifyLowS / VerifyDERSignatures. WithForkID already implies
// VerifyStrictEncoding, so DER structure is enforced; low-S requires the extra
// VerifyLowS flag.
func executeScriptStrictTx(lockingHex, unlockingHex string, tx *transaction.Transaction, inputIdx int, prevOutput *transaction.TransactionOutput, extraFlags scriptflag.Flag) error {
	locking, err := script.NewFromHex(lockingHex)
	if err != nil {
		return fmt.Errorf("invalid locking script hex: %w", err)
	}
	unlocking, err := script.NewFromHex(unlockingHex)
	if err != nil {
		return fmt.Errorf("invalid unlocking script hex: %w", err)
	}

	eng := interpreter.NewEngine()
	return eng.Execute(
		interpreter.WithScripts(locking, unlocking),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
		interpreter.WithTx(tx, inputIdx, prevOutput),
		interpreter.WithFlags(extraFlags),
	)
}

// buildP2PKHLocking returns the hex of a standard P2PKH locking script:
// OP_DUP OP_HASH160 <20-byte pkh> OP_EQUALVERIFY OP_CHECKSIG.
func buildP2PKHLocking(pubKeyHash []byte) string {
	return fmt.Sprintf("%02x%02x", script.OpDUP, script.OpHASH160) +
		encodePushBytes(pubKeyHash) +
		fmt.Sprintf("%02x%02x", script.OpEQUALVERIFY, script.OpCHECKSIG)
}

// canonicalizeIntDER mirrors the go-sdk ec.canonicalizeInt helper: minimal
// big-endian bytes with a leading 0x00 when the high bit would otherwise make
// the value look negative.
func canonicalizeIntDER(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 {
		b = []byte{0x00}
	}
	if b[0]&0x80 != 0 {
		padded := make([]byte, len(b)+1)
		copy(padded[1:], b)
		b = padded
	}
	return b
}

// encodeDER hand-rolls the strict DER encoding go-sdk uses
// (0x30 <len> 0x02 <lenR> R 0x02 <lenS> S) for an arbitrary (R, S) pair —
// needed because ec.Signature.Serialize() force-normalises S to the low form,
// so it cannot emit a high-S signature.
func encodeDER(r, s *big.Int) []byte {
	rb := canonicalizeIntDER(r)
	sb := canonicalizeIntDER(s)
	length := 6 + len(rb) + len(sb)
	b := make([]byte, length)
	b[0] = 0x30
	b[1] = byte(length - 2)
	b[2] = 0x02
	b[3] = byte(len(rb))
	off := copy(b[4:], rb) + 4
	b[off] = 0x02
	b[off+1] = byte(len(sb))
	copy(b[off+2:], sb)
	return b
}

// TestP2PKH_ScriptExecution_HighS feeds a signature whose S value is the high
// (non-canonical) complement N-S into an OP_CHECKSIG path and asserts it is
// rejected under the low-S policy. A positive control confirms the canonical
// low-S form of the same signature verifies, so high-S is the sole rejection
// cause.
func TestP2PKH_ScriptExecution_HighS(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubKeyBytes := privKey.PubKey().Compressed()
	pubKeyHash := crypto.Hash160(pubKeyBytes)

	lockingHex := buildP2PKHLocking(pubKeyHash)

	const satoshis = uint64(10000)
	spendTx, prevOutput, err := buildSpendingTx(lockingHex, satoshis)
	if err != nil {
		t.Fatalf("build tx: %v", err)
	}

	sigHash, err := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	sig, err := privKey.Sign(sigHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Positive control: canonical low-S form verifies under the low-S policy.
	lowDER := sig.Serialize() // Serialize() normalises S to the low form.
	lowUnlock := encodePushBytes(append(append([]byte{}, lowDER...), byte(sighash.AllForkID))) +
		encodePushBytes(pubKeyBytes)
	if err := executeScriptStrictTx(lockingHex, lowUnlock, spendTx, 0, prevOutput, scriptflag.VerifyLowS); err != nil {
		t.Fatalf("canonical low-S signature should verify, got: %v", err)
	}

	// Force S to the high half: S' = N - S (both are valid ECDSA S values;
	// this is the classic ECDSA malleability). N-S > N/2 whenever S <= N/2.
	N := ec.S256().N
	halfN := new(big.Int).Rsh(N, 1)
	highS := sig.S
	if highS.Cmp(halfN) <= 0 {
		highS = new(big.Int).Sub(N, sig.S)
	}
	if highS.Cmp(halfN) <= 0 {
		t.Fatalf("failed to construct a high-S value (S=%x)", highS)
	}

	highDER := encodeDER(sig.R, highS)
	highUnlock := encodePushBytes(append(append([]byte{}, highDER...), byte(sighash.AllForkID))) +
		encodePushBytes(pubKeyBytes)

	err = executeScriptStrictTx(lockingHex, highUnlock, spendTx, 0, prevOutput, scriptflag.VerifyLowS)
	if err == nil {
		t.Fatal("high-S signature should be rejected under low-S policy but execution succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrSigHighS) {
		t.Fatalf("expected ErrSigHighS for high-S signature, got: %v", err)
	}
}

// TestP2PKH_ScriptExecution_MalformedDER corrupts the DER total-length prefix
// of an otherwise valid signature and asserts the OP_CHECKSIG path rejects it
// under strict DER encoding. A positive control confirms the intact signature
// verifies.
func TestP2PKH_ScriptExecution_MalformedDER(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubKeyBytes := privKey.PubKey().Compressed()
	pubKeyHash := crypto.Hash160(pubKeyBytes)

	lockingHex := buildP2PKHLocking(pubKeyHash)

	const satoshis = uint64(10000)
	spendTx, prevOutput, err := buildSpendingTx(lockingHex, satoshis)
	if err != nil {
		t.Fatalf("build tx: %v", err)
	}

	sigHash, err := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	sig, err := privKey.Sign(sigHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	derSig := sig.Serialize()

	// Positive control: the intact DER signature verifies.
	goodUnlock := encodePushBytes(append(append([]byte{}, derSig...), byte(sighash.AllForkID))) +
		encodePushBytes(pubKeyBytes)
	if err := executeScriptStrictTx(lockingHex, goodUnlock, spendTx, 0, prevOutput, scriptflag.VerifyDERSignatures); err != nil {
		t.Fatalf("intact DER signature should verify, got: %v", err)
	}

	// Corrupt the DER total-length prefix (byte index 1). The interpreter
	// expects sig[1] == len(sig)-2; setting it to len(sig) is unambiguously
	// wrong without changing the sequence tag or the overall length.
	bad := append([]byte{}, derSig...)
	bad[1] = byte(len(derSig))
	badUnlock := encodePushBytes(append(append([]byte{}, bad...), byte(sighash.AllForkID))) +
		encodePushBytes(pubKeyBytes)

	err = executeScriptStrictTx(lockingHex, badUnlock, spendTx, 0, prevOutput, scriptflag.VerifyDERSignatures)
	if err == nil {
		t.Fatal("malformed-DER signature should be rejected under strict DER but execution succeeded")
	}
	if !errs.IsErrorCode(err, errs.ErrSigInvalidDataLen) {
		t.Fatalf("expected ErrSigInvalidDataLen for corrupted DER length prefix, got: %v", err)
	}
}

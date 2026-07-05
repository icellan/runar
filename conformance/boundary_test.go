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
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	errs "github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	scriptflag "github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
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

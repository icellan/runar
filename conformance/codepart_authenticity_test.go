package conformance

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// ---------------------------------------------------------------------------
// R-010 / CL-BUG-091 — `_codePart` must be authenticated against the script
// that is actually executing.
//
// `_codePart` is an implicit method parameter: the SPENDER pushes it, and the
// compiler OP_CATs it verbatim as the script prefix of the reconstructed
// state-continuation output. The only constraint the emitted script places on
// those bytes is
//
//	hash256(serializedOutputs) == extractHashOutputs(preimage)
//
// which the attacker satisfies for free, because the attacker is the one
// building the transaction. Nothing binds `_codePart` to the locking script
// under execution, so a spender can substitute an arbitrary script — e.g. a
// P2PKH to a key they control — and walk away with the contract's satoshis
// while the script still verifies.
//
// The tests below drive the real go-sdk Script interpreter over a full
// BIP-143 spend of `stateful-counter` (the same harness as
// TestStateful_Increment):
//
//   - TestCodePartHijack_* : the attack. MUST be rejected.
//   - TestCodePartHonestSpend_Control : the honest spend. MUST be accepted,
//     both before and after the fix, so that a "fix" which simply breaks all
//     spending is caught.
// ---------------------------------------------------------------------------

// attackerPKH is a recognizable 20-byte hash160 standing in for a key the
// attacker controls.
var attackerPKH = []byte{
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
	0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
}

// codePartSpendResult is the outcome of running one stateful-counter spend
// through the interpreter with a caller-chosen `_codePart`.
type codePartSpendResult struct {
	err error
	// continuationScriptHex is the script the attacker actually pays to.
	continuationScriptHex string
}

// runCounterSpendWithCodePart builds and executes a complete increment spend of
// `stateful-counter`, but lets the caller choose the `_codePart` witness item
// AND the continuation output script independently of the real locking script.
//
// When witnessCodePart == the contract's true code part and the continuation
// output is rebuilt from it, this is exactly the honest spend performed by
// TestStateful_Increment. When the caller substitutes a foreign script it is
// the hijack.
//
// contSatoshis / changeSatoshis let the caller move value into the substituted
// output, which is what makes the attack a fund loss rather than a curiosity.
func runCounterSpendWithCodePart(
	t *testing.T,
	witnessCodePart []byte,
	contSatoshis uint64,
	changeSatoshis uint64,
) codePartSpendResult {
	t.Helper()

	// The genuine deployed contract: compile stateful-counter with count=0.
	trueCodePartHex, err := compileRúnar("stateful-counter", `{"count":"0"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Locking script actually funded on chain: trueCodePart + OP_RETURN + state.
	initialStateHex := serializeBigintState(0)
	fullLockingHex := trueCodePartHex + "6a" + initialStateHex

	// The continuation output is reconstructed by the SCRIPT from whatever
	// `_codePart` the spender pushes, so the transaction must carry an output
	// built from the witness value — not from the real code part.
	newStateHex := serializeBigintState(1)
	continuationScriptHex := hex.EncodeToString(witnessCodePart) + "6a" + newStateHex

	// increment() is public method 0; its OP_CODESEPARATOR is the first one.
	codeSepOffset := findCodeSeparatorOffset(trueCodePartHex, 0)
	if codeSepOffset < 0 {
		t.Fatal("OP_CODESEPARATOR not found in codePart")
	}

	prevSatoshis := uint64(10000)
	changePKH := make([]byte, 20)

	fullLockingScript, err := script.NewFromHex(fullLockingHex)
	if err != nil {
		t.Fatalf("parse full locking script: %v", err)
	}
	prevOutput := &transaction.TransactionOutput{
		Satoshis:      prevSatoshis,
		LockingScript: fullLockingScript,
	}

	spendTx := transaction.NewTransaction()
	spendTx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       makeFundingTxID(),
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, prevOutput)

	contScript, err := script.NewFromHex(continuationScriptHex)
	if err != nil {
		t.Fatalf("parse continuation script: %v", err)
	}
	spendTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      contSatoshis,
		LockingScript: contScript,
	})
	spendTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      changeSatoshis,
		LockingScript: buildP2PKHLockingScript(changePKH),
	})

	// BIP-143 preimage with scriptCode = everything after OP_CODESEPARATOR of
	// the REAL locking script (that is what the node computes).
	scriptCodeHex := fullLockingHex[(codeSepOffset+1)*2:]
	scriptCodeScript, err := script.NewFromHex(scriptCodeHex)
	if err != nil {
		t.Fatalf("parse scriptCode: %v", err)
	}
	spendTx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      prevSatoshis,
		LockingScript: scriptCodeScript,
	})
	preimage, err := spendTx.CalcInputPreimage(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("calc preimage: %v", err)
	}
	spendTx.Inputs[0].SetSourceTxOutput(prevOutput)

	// Unlocking stack (bottom → top):
	//   _codePart, _changePKH, _changeAmount, _newAmount, txPreimage, selector
	unlockingHex := encodePushBytes(witnessCodePart) +
		encodePushBytes(changePKH) +
		encodePushInt(int64(changeSatoshis)) +
		encodePushInt(int64(contSatoshis)) +
		encodePushBytes(preimage) +
		encodePushInt(0)

	unlockScript, err := script.NewFromHex(unlockingHex)
	if err != nil {
		t.Fatalf("parse unlocking script: %v", err)
	}
	spendTx.Inputs[0].UnlockingScript = unlockScript

	return codePartSpendResult{
		err:                   executeScriptWithTx(fullLockingHex, unlockingHex, spendTx, 0, prevOutput),
		continuationScriptHex: continuationScriptHex,
	}
}

// trueCounterCodePart returns the genuine compiled code part for
// stateful-counter with count=0.
func trueCounterCodePart(t *testing.T) []byte {
	t.Helper()
	h, err := compileRúnar("stateful-counter", `{"count":"0"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode code part: %v", err)
	}
	return b
}

// TestCodePartHonestSpend_Control is the control: the honest increment spend,
// with `_codePart` equal to the real code part, must verify. It must pass both
// before and after the R-010 fix — a fix that merely breaks all spending fails
// here.
func TestCodePartHonestSpend_Control(t *testing.T) {
	res := runCounterSpendWithCodePart(t, trueCounterCodePart(t), 9000, 500)
	if res.err != nil {
		t.Fatalf("honest spend must verify, got: %v", res.err)
	}
}

// TestCodePartHijack_P2PKH is the fund-loss attack: `_codePart` is replaced
// with a bare P2PKH to the attacker, and 9,900 of the 10,000 input satoshis are
// routed into that output. Nothing about the contract's state machine is
// preserved. The script MUST reject.
func TestCodePartHijack_P2PKH(t *testing.T) {
	hijacked, err := hex.DecodeString("76a914" + hex.EncodeToString(attackerPKH) + "88ac")
	if err != nil {
		t.Fatalf("decode hijack script: %v", err)
	}

	// 9,900 of the 10,000 input satoshis go to the attacker; 100 is left as
	// change so the fee/serialization arithmetic of the honest path is
	// untouched and the only thing under test is `_codePart`.
	res := runCounterSpendWithCodePart(t, hijacked, 9900, 100)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified while paying 9900/10000 sat to "+
				"an attacker-controlled output %s — `_codePart` is an unauthenticated "+
				"spender witness",
			res.continuationScriptHex,
		)
	}
}

// TestCodePartHijack_TruncatedTail truncates the genuine code part, dropping
// the post-OP_CODESEPARATOR logic that enforces the state machine. Because the
// truncated prefix still ends inside the method-dispatch table it is a subtler
// substitution than the P2PKH one, but it is equally unauthorized: the
// continuation output no longer carries the contract's rules.
func TestCodePartHijack_TruncatedTail(t *testing.T) {
	full := trueCounterCodePart(t)
	if len(full) < 8 {
		t.Fatalf("code part implausibly short: %d bytes", len(full))
	}
	// Keep everything up to (and including) the first OP_CODESEPARATOR, drop
	// the rest. The kept prefix is a real fragment of the contract, so this is
	// not merely "invalid bytes".
	sepOffset := findCodeSeparatorOffset(hex.EncodeToString(full), 0)
	if sepOffset < 0 {
		t.Fatal("OP_CODESEPARATOR not found in code part")
	}
	truncated := full[:sepOffset+1]

	res := runCounterSpendWithCodePart(t, truncated, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with a truncated code part "+
				"(%d of %d bytes), producing continuation output %s",
			len(truncated), len(full), res.continuationScriptHex,
		)
	}
}

// TestCodePartHijack_AppendedTail keeps the genuine code part intact but
// appends extra bytes. The appended tail lands between the contract logic and
// the OP_RETURN state separator in the continuation output, so the "same"
// contract is redeployed under different rules.
func TestCodePartHijack_AppendedTail(t *testing.T) {
	full := trueCounterCodePart(t)
	// OP_DROP OP_1 — harmless-looking, but it is not the deployed code.
	appended := append(append([]byte{}, full...), 0x75, 0x51)

	res := runCounterSpendWithCodePart(t, appended, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with %d bytes appended to the "+
				"code part, producing continuation output %s",
			len(appended)-len(full), res.continuationScriptHex,
		)
	}
}

// TestCodePartHijack_PrologueOnly is the degenerate truncation: the spender
// claims a code part consisting of nothing but the two prologue bytes
// (OP_NOP, OP_CODESEPARATOR). The continuation output would then be
// `OP_NOP OP_CODESEPARATOR OP_RETURN <state>` — post-Genesis a bare OP_RETURN,
// spendable by anyone. A prefix-only check would accept this (the empty tail
// trivially matches), so it is the sharpest test of the split-point pin.
func TestCodePartHijack_PrologueOnly(t *testing.T) {
	res := runCounterSpendWithCodePart(t, []byte{0x61, 0xab}, 9900, 100)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with a 2-byte prologue-only "+
				"code part, producing the anyone-can-spend output %s",
			res.continuationScriptHex,
		)
	}
}

// TestCodePartHijack_PrologueSwapped keeps the genuine code part but rewrites
// its first byte, so the redeployed contract no longer starts with the
// OP_NOP/OP_CODESEPARATOR prologue the authentication depends on. Substituting
// 0x6a (OP_RETURN) there is the sharpest form: the whole continuation output
// becomes a data carrier that anyone can spend.
func TestCodePartHijack_PrologueSwapped(t *testing.T) {
	full := trueCounterCodePart(t)
	swapped := append([]byte{}, full...)
	swapped[0] = 0x6a

	res := runCounterSpendWithCodePart(t, swapped, 9900, 100)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with the prologue byte "+
				"rewritten to OP_RETURN, producing output %s",
			res.continuationScriptHex[:64],
		)
	}
}

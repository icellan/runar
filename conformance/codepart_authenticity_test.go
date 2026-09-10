package conformance

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
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

// ---------------------------------------------------------------------------
// R-095 / CL-GAP-072 — additional forged-code-part cases.
//
// The five hijacks above all destroy the code part in a structurally obvious
// way: they swap in a non-contract script, lop off the whole post-separator
// body, bolt bytes onto the end, or rewrite the prologue. Each of those can be
// rejected by a check far weaker than the one R-010 actually emits — a length
// pin alone kills the truncation and the extension, and a two-byte prologue
// compare kills the swap.
//
// The cases below are the ones that survive those weaker checks, so they are
// what actually pins the authentication down:
//
//   - ForeignContract   : a DIFFERENT but perfectly valid compiled Rúnar
//                         contract. Right shape, right prologue, plausible
//                         length — this is the substitution R-010 exists for.
//   - ProloguePreserved : `0x61ab` intact, first byte AFTER it flipped. A test
//                         suite that only compared the prologue would pass this.
//   - DeepByteFlip      : one byte changed in the middle of the body. Same
//                         length, same prologue, same tail.
//   - ShortByOne/LongByOne : off-by-one length. The nearest possible miss.
// ---------------------------------------------------------------------------

// foreignCodePart compiles `stateful` — a real, valid StatefulSmartContract
// that is NOT the contract under execution — and returns its code part. Its
// state section is a single bigint, exactly like stateful-counter, so the
// substituted continuation output is a fully functional contract rather than
// obvious garbage: the ideal substitution payload.
func foreignCodePart(t *testing.T) []byte {
	t.Helper()
	h, err := compileRúnar("stateful", `{"count":"0","maxCount":"100"}`)
	if err != nil {
		t.Fatalf("compile foreign contract: %v", err)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode foreign code part: %v", err)
	}
	return b
}

// TestCodePartHijack_ForeignContract is the substitution attack in its purest
// form: the spender claims the code part of a DIFFERENT valid contract. The
// forgery starts with the same `0x61ab` prologue, is a well-formed compiled
// Rúnar script, carries the same single-bigint state layout, and is within a
// couple of bytes of the honest length — so it defeats every structural
// heuristic. Only a byte-for-byte bind to the executing script rejects it.
func TestCodePartHijack_ForeignContract(t *testing.T) {
	honest := trueCounterCodePart(t)
	foreign := foreignCodePart(t)

	if len(foreign) < 2 || foreign[0] != 0x61 || foreign[1] != 0xab {
		t.Fatalf("foreign contract does not carry the 61ab prologue: %x", foreign[:2])
	}
	if hex.EncodeToString(foreign) == hex.EncodeToString(honest) {
		t.Fatal("foreign contract compiled to the same bytes as the honest one — not a substitution")
	}

	res := runCounterSpendWithCodePart(t, foreign, 9900, 100)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with the code part of a "+
				"DIFFERENT valid contract (%d bytes vs the honest %d), redirecting "+
				"9900/10000 sat into %s… — `_codePart` is not bound to the executing script",
			len(foreign), len(honest), res.continuationScriptHex[:64],
		)
	}
}

// TestCodePartHijack_ProloguePreserved keeps `0x61ab` byte-for-byte and flips
// the very first byte after it. This is the case that proves the test cannot be
// satisfied by a compiler that only pins the two prologue bytes.
func TestCodePartHijack_ProloguePreserved(t *testing.T) {
	forged := append([]byte{}, trueCounterCodePart(t)...)
	if len(forged) < 4 {
		t.Fatalf("code part implausibly short: %d bytes", len(forged))
	}
	forged[2] ^= 0xff

	if forged[0] != 0x61 || forged[1] != 0xab {
		t.Fatal("prologue must stay intact for this case to mean anything")
	}

	res := runCounterSpendWithCodePart(t, forged, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with an intact 61ab prologue "+
				"but byte 2 flipped (0x%02x -> 0x%02x) — the authentication checks only the prologue",
			forged[2]^0xff, forged[2],
		)
	}
}

// TestCodePartHijack_DeepByteFlip changes exactly one byte in the middle of the
// contract body. Same length, same prologue, same final byte — every coarse
// property of the honest code part is preserved. On-chain this is how a real
// substitution would be built: patch one opcode (an OP_EQUALVERIFY into an
// OP_DROP, say) and leave everything else alone.
func TestCodePartHijack_DeepByteFlip(t *testing.T) {
	honest := trueCounterCodePart(t)
	forged := append([]byte{}, honest...)
	mid := len(forged) / 2
	forged[mid] ^= 0x01

	if len(forged) != len(honest) {
		t.Fatal("flip must not change the length")
	}

	res := runCounterSpendWithCodePart(t, forged, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with a single byte flipped at "+
				"offset %d of %d (0x%02x -> 0x%02x) — the authentication does not cover the body",
			mid, len(honest), honest[mid], forged[mid],
		)
	}
}

// TestCodePartHijack_ShortByOne drops the final byte. This is the nearest
// possible miss on the low side, and it is the case the split-point pin exists
// for: the forged value IS a genuine prefix of the executing script, so a
// prefix-equality check alone accepts it. Only pinning where the code part ENDS
// rejects it.
func TestCodePartHijack_ShortByOne(t *testing.T) {
	honest := trueCounterCodePart(t)
	forged := honest[:len(honest)-1]

	res := runCounterSpendWithCodePart(t, forged, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with a code part one byte SHORT "+
				"(%d vs %d) — a genuine prefix of the executing script passed, so the "+
				"split point is not pinned",
			len(forged), len(honest),
		)
	}
}

// TestCodePartHijack_LongByOne appends a single byte. The nearest possible miss
// on the high side. The honest code part is a genuine prefix of the forgery, so
// this is the mirror image of ShortByOne.
func TestCodePartHijack_LongByOne(t *testing.T) {
	honest := trueCounterCodePart(t)
	forged := append(append([]byte{}, honest...), 0x75) // OP_DROP

	res := runCounterSpendWithCodePart(t, forged, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the script verified with a code part one byte LONG "+
				"(%d vs %d)",
			len(forged), len(honest),
		)
	}
}

// ---------------------------------------------------------------------------
// R-095 — the VARIABLE-LENGTH state path.
//
// `emitCodePartAuthentication` pins the split point two ways:
//
//	(8a) SIZE(rest) == 1 + fixedStateLen   — only when the state section has a
//	                                         compile-time-constant length
//	(8b) rest[0] == 0x6a                   — always
//
// Every case above runs against `stateful-counter`, whose state is one bigint,
// so (8a) applies and SIZE(codePart) is pinned exactly. A contract with a
// ByteString state field has no compile-time state length, so (8a) is skipped
// and (8b) is the ONLY thing standing between the spender and a shorter
// claimed code part.
//
// That matters because the executing script contains 0x6a bytes of its own.
// The cases below run the same forgeries against `stateful-bytestring`
// (MessageBoard: `message: ByteString` mutable, `owner: PubKey` readonly) to
// establish, by execution, what the var-len path actually rejects.
// ---------------------------------------------------------------------------

const (
	// mbOwner is a well-formed compressed pubkey. `post` never checks a
	// signature, so the key only has to parse.
	mbOwner = "02" + "1111111111111111111111111111111111111111111111111111111111111111"
	// mbMessage / mbNewMessage are the before/after ByteString state values.
	mbMessage    = "48656c6c6f"   // "Hello"
	mbNewMessage = "576f726c6421" // "World!"
)

// encodeVarLenState frames a ByteString state field the way both the SDK
// serializer and the compiler's on-chain codec do: <len><data> for len <= 75.
func encodeVarLenState(dataHex string) string {
	n := len(dataHex) / 2
	if n > 75 {
		panic("encodeVarLenState: test values must stay in the single-byte push range")
	}
	return hex.EncodeToString([]byte{byte(n)}) + dataHex
}

// deployedCodePartHex returns the code part as it is actually DEPLOYED, which
// is not what `compile()` alone returns.
//
// A contract that reads variable-length state emits its `codeSeparatorIndex`
// as an OP_0 PLACEHOLDER (`emitCodeSepIndexPlaceholder` in
// packages/runar-compiler/src/passes/06-emit.ts); the SDK overwrites it at
// deploy time with the real index, adjusted for constructor-arg expansion.
// Executing the unpatched compiler output puts a 0 where the script needs a 1,
// the state-section offset lands one byte late, and the spend dies inside the
// push-data decoder with "n is larger than length of array" — a harness
// failure that looks exactly like a covenant rejection. Every var-len case
// here must therefore run against the SDK-built script.
//
// For contracts whose state is entirely fixed-size there are no slots and this
// returns the same bytes `compileRúnar` does.
func deployedCodePartHex(contractName, ctorArgsJSONArray string) (string, error) {
	srcRelPath, err := resolveTSSource(contractName)
	if err != nil {
		return "", err
	}
	fileName := filepath.Base(srcRelPath)

	code := fmt.Sprintf(`
(async () => {
const { compile } = await import('./packages/runar-compiler/dist/index.js');
const sdk = await import('./packages/runar-sdk/dist/index.js');
const fs = require('fs');
const src = fs.readFileSync('%s', 'utf-8');
const r = compile(src, { fileName: '%s' });
if (!r.success || !r.artifact) { process.exit(1); }
const c = new sdk.RunarContract(r.artifact, %s);
process.stdout.write(c.buildCodeScript());
})();
`, srcRelPath, fileName, ctorArgsJSONArray)

	cmd := exec.Command("node", "-e", code)
	cmd.Dir = ".." // project root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("SDK code-script build failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// mbCtorArgs is the message-board constructor arg vector in SDK (positional)
// form.
const mbCtorArgs = `["` + mbMessage + `","` + mbOwner + `"]`

// trueMessageBoardCodePart returns the genuine DEPLOYED code part for
// stateful-bytestring.
func trueMessageBoardCodePart(t *testing.T) []byte {
	t.Helper()
	h, err := deployedCodePartHex("stateful-bytestring", mbCtorArgs)
	if err != nil {
		t.Fatalf("build message board code script: %v", err)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode message board code part: %v", err)
	}
	return b
}

// runMessageBoardPostWithCodePart is runCounterSpendWithCodePart for the
// variable-length-state contract: a complete BIP-143 `post` spend of
// stateful-bytestring with a caller-chosen `_codePart`.
func runMessageBoardPostWithCodePart(
	t *testing.T,
	witnessCodePart []byte,
	contSatoshis uint64,
	changeSatoshis uint64,
) codePartSpendResult {
	t.Helper()

	trueCodePartHex, err := deployedCodePartHex("stateful-bytestring", mbCtorArgs)
	if err != nil {
		t.Fatalf("build code script: %v", err)
	}

	fullLockingHex := trueCodePartHex + "6a" + encodeVarLenState(mbMessage)
	continuationScriptHex := hex.EncodeToString(witnessCodePart) + "6a" + encodeVarLenState(mbNewMessage)

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

	newMessageBytes, err := hex.DecodeString(mbNewMessage)
	if err != nil {
		t.Fatalf("decode new message: %v", err)
	}

	// Unlocking stack (bottom → top):
	//   _codePart, newMessage, _changePKH, _changeAmount, _newAmount,
	//   txPreimage, selector
	unlockingHex := encodePushBytes(witnessCodePart) +
		encodePushBytes(newMessageBytes) +
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

// TestCodePartHonestSpend_VarLenState_Control is the control for the
// variable-length-state harness. Without it every rejection below could be the
// harness failing rather than the covenant rejecting.
func TestCodePartHonestSpend_VarLenState_Control(t *testing.T) {
	res := runMessageBoardPostWithCodePart(t, trueMessageBoardCodePart(t), 9000, 500)
	if res.err != nil {
		t.Fatalf("honest var-len-state spend must verify, got: %v", res.err)
	}
}

// TestCodePartHijack_VarLenState_SplitPointCollision is the sharpest forgery in
// this file, and the only one that is not a generic "wrong bytes" case: it is
// built to SATISFY the authentication rather than to violate it.
//
// For a fixed-size-state contract the emitted check pins the split point
// exactly (SIZE(rest) == 1 + fixedStateLen). A ByteString state field has no
// compile-time length, so that clause is not emitted and the only surviving
// constraint on where the code part ENDS is
//
//	rest[0] == 0x6a
//
// The forgery follows straight from that. For any offset k at which the
// executing script's own bytes happen to hold 0x6a, claiming
//
//	_codePart = trueCodePart[:k]
//
// makes n = k-2, so scriptCode[0:n] == trueCodePart[2:k] and the prologue
// concatenation reproduces the claim byte-for-byte — the OP_EQUALVERIFY at the
// end of emitCodePartAuthentication PASSES — while rest[0] is trueCodePart[k],
// which is 0x6a by construction. Both surviving clauses are satisfied by a
// code part that is not the executing script.
//
// This is not hypothetical: the message-board script carries 0x6a bytes of its
// own (they are the `01 6a` OP_RETURN-separator pushes the continuation builder
// uses), so the collision offsets exist in the real compiled contract. The test
// enumerates every one of them and drives a full BIP-143 spend at each.
//
// The truncated claims must still be REJECTED. If any is accepted the spender
// can redeploy the contract's satoshis under a script that stops partway
// through the contract logic.
func TestCodePartHijack_VarLenState_SplitPointCollision(t *testing.T) {
	honest := trueMessageBoardCodePart(t)

	// Every offset the split-point check cannot distinguish from the real one.
	// k starts at 3 because a claim must be longer than the 0x61ab prologue.
	var collisions []int
	for k := 3; k < len(honest); k++ {
		if honest[k] == 0x6a {
			collisions = append(collisions, k)
		}
	}
	if len(collisions) == 0 {
		t.Skip("this build of the message-board script carries no interior 0x6a byte — " +
			"nothing collides with the split-point check, so there is nothing to forge here")
	}
	t.Logf("script is %d bytes; %d interior 0x6a byte(s) collide with the split-point check: %v",
		len(honest), len(collisions), collisions)

	for _, k := range collisions {
		forged := honest[:k]

		// Restate the two surviving clauses so a future failure says WHY this
		// input was chosen rather than looking like an arbitrary truncation.
		if !(forged[0] == 0x61 && forged[1] == 0xab) {
			t.Fatalf("k=%d: forgery lost the prologue", k)
		}
		if honest[k] != 0x6a {
			t.Fatalf("k=%d: forgery does not satisfy rest[0] == 0x6a", k)
		}

		res := runMessageBoardPostWithCodePart(t, forged, 9900, 100)
		if res.err == nil {
			t.Errorf(
				"CODEPART HIJACK ACCEPTED at k=%d: a %d-byte claimed code part (the executing "+
					"script truncated at its own interior 0x6a) passed authentication and "+
					"redirected 9900/10000 sat into %s… — with variable-length state the split "+
					"point is not pinned",
				k, len(forged), res.continuationScriptHex[:64],
			)
		} else {
			t.Logf("k=%d (%d bytes): rejected — %v", k, len(forged), res.err)
		}
	}
}

// TestCodePartHijack_VarLenState_ForeignContract repeats the substitution
// attack on the variable-length-state path, so the weaker split-point pin is
// not the only thing this fixture exercises.
func TestCodePartHijack_VarLenState_ForeignContract(t *testing.T) {
	honest := trueMessageBoardCodePart(t)
	foreign := foreignCodePart(t)

	res := runMessageBoardPostWithCodePart(t, foreign, 9900, 100)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the var-len-state script verified with the code part "+
				"of a DIFFERENT valid contract (%d bytes vs the honest %d)",
			len(foreign), len(honest),
		)
	}
}

// TestCodePartHijack_VarLenState_DeepByteFlip is the same-length one-byte
// forgery on the variable-length path.
func TestCodePartHijack_VarLenState_DeepByteFlip(t *testing.T) {
	honest := trueMessageBoardCodePart(t)
	forged := append([]byte{}, honest...)
	mid := len(forged) / 2
	forged[mid] ^= 0x01

	res := runMessageBoardPostWithCodePart(t, forged, 9000, 500)
	if res.err == nil {
		t.Fatalf(
			"CODEPART HIJACK ACCEPTED: the var-len-state script verified with a single byte "+
				"flipped at offset %d of %d (0x%02x -> 0x%02x)",
			mid, len(honest), honest[mid], forged[mid],
		)
	}
}

// TestCodePartHijack_SplitPointCollision is the fixed-size-state twin of
// TestCodePartHijack_VarLenState_SplitPointCollision, and it is the case that
// isolates clause 8a — the exact length pin.
//
// stateful-counter's compiled script contains 0x6a bytes of its own. Claiming
// `_codePart = trueCodePart[:k]` at any such k satisfies BOTH of the clauses
// that survive on the variable-length path:
//
//	the prologue-prepended prefix compare (step 10), because the claim is a
//	genuine prefix of the executing script; and
//	rest[0] == 0x6a (clause 8b), by construction.
//
// What rejects it here — and only here — is clause 8a: the state section has a
// compile-time-constant length, so SIZE(rest) pins where the code part must
// end. Delete that one clause and these forgeries are accepted, which is
// precisely the state the variable-length path is in today.
//
// Keep this test adjacent to the var-len one: together they show that the
// difference between "rejected" and "accepted" for the same attack is nothing
// but whether the state section has a constant length.
func TestCodePartHijack_SplitPointCollision(t *testing.T) {
	honest := trueCounterCodePart(t)

	var collisions []int
	for k := 3; k < len(honest); k++ {
		if honest[k] == 0x6a {
			collisions = append(collisions, k)
		}
	}
	if len(collisions) == 0 {
		t.Skip("this build of stateful-counter carries no interior 0x6a byte")
	}
	t.Logf("script is %d bytes; %d interior 0x6a byte(s) collide with clause 8b: %v",
		len(honest), len(collisions), collisions)

	for _, k := range collisions {
		forged := honest[:k]
		res := runCounterSpendWithCodePart(t, forged, 9900, 100)
		if res.err == nil {
			t.Errorf(
				"CODEPART HIJACK ACCEPTED at k=%d: a %d-byte claimed code part (the executing "+
					"script truncated at its own interior 0x6a) passed authentication and "+
					"redirected 9900/10000 sat into %s… — the exact split-point pin is gone",
				k, len(forged), res.continuationScriptHex[:64],
			)
		} else {
			t.Logf("k=%d (%d bytes): rejected — %v", k, len(forged), res.err)
		}
	}
}

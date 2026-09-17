//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------------
// Audit finding #26 — missing consensus-finality negative coverage for the
// time-lock contract family.
//
// Every pre-existing Auction test (TestAuction_Close, TestAuction_WrongSigner_Rejected)
// deploys with deadline=0, which `extractLocktime(txPreimage) >= 0` always
// satisfies trivially — no test ever broadcasts a spend whose deadline is
// genuinely in the FUTURE relative to the live regtest chain tip and checks
// that the node's own consensus rules (not just the contract's script-level
// assert) actually reject it. The tests below close that gap.
//
// Background — Bitcoin only enforces nLockTime against a transaction when at
// least one input's nSequence is non-final (< 0xffffffff). A transaction
// whose inputs are ALL final (0xffffffff) is accepted by IsFinalTx
// immediately, REGARDLESS of its nLockTime value — a contract's own
// `assert(extractLocktime(txPreimage) >= deadline)` is consensus-enforced
// ONLY when the spending tx also carries a non-final input sequence. Issue
// #131 (fixed in the Go SDK; see resolveInputSequence in
// packages/runar-go/sdk_calling.go) makes the SDK's own Call()/PrepareCall
// default every input to 0xfffffffe whenever CallOptions.Locktime is set, so
// the SDK's own call path can't accidentally emit an unenforceable locktime.
//
//   - TestAuction_CloseBeforeDeadline_FinalSequence_Rejected pins the raw
//     Bitcoin mechanism directly. Until W7 this test asserted the opposite:
//     a premature close with an all-final sequence was ACCEPTED, because the
//     node takes nLockTime out of consensus scope for a final transaction and
//     the contract only checked nLockTime. The auctioneer could therefore
//     close at any height. Auction.close now also asserts
//     `extractSequence(txPreimage) !== 0xffffffffn`, so the SCRIPT refuses the
//     final-sequence spend before consensus ever gets a say.
//   - TestAuction_CloseBeforeDeadline_NonFinalSequence_Rejected is the
//     missing negative test itself: the SAME premature close, but with a
//     non-final input sequence, never gets mined — proving the auction
//     contract's own locktime logic is sound when consensus enforcement is
//     actually engaged.
//   - TestAuction_CloseBeforeDeadline_SDKDefault_Rejected is the end-to-end
//     regression guard for issue #131's fix: RunarContract.Call with
//     CallOptions.Locktime set (Sequence left nil) must default to a
//     non-final input sequence, so a premature close through the SDK's own
//     default call path — the path every real caller uses — can never be
//     mined either.
//
// Raw-crafted note: Auction extends StatefulSmartContract, which
// auto-injects checkPreimage + OP_CODESEPARATOR at method entry. The user's
// own checkSig(sig, this.auctioneer) executes AFTER that OP_CODESEPARATOR, so
// its BIP-143 scriptCode must be the deployed script SLICED at that byte
// offset, not the full script — signing over the full script produces an
// invalid signature (NULLFAIL) regardless of which key or lock/sequence
// values are used. codesepOffsetForClose recovers the real offset the
// compiler emitted for this specific deployment (offsets shift with
// constructor-arg encoding length) by matching a reference PrepareCall's
// known-correct preimage, reusing the exact technique
// bug100_covenant_bypass_test.go's recoverCodeSep already established for
// this codebase. checkPreimage itself (post-BUG-100 fix; see
// oppushtx-codegen.ts) derives its own OP_CHECKSIGVERIFY signature ON-CHAIN
// from the pushed preimage (fixed nonce k=2, privkey d=1) — the unlocking
// script must NOT also push a witness OP_PUSH_TX signature, or the script
// leaves an extra unconsumed stack item (CLEANSTACK rejection).
//
// Node-behavior note: SV Node accepts non-final transactions (future
// nLockTime + non-final nSequence) into the mempool for relay, but excludes
// them from block templates until they become final — sendrawtransaction /
// RunarContract.Call succeeding (err == nil, txid returned) is NOT evidence
// a spend is consensus-final. The only check that reflects real consensus
// enforcement is whether the spend can ever actually be MINED, so
// NonFinalSequence_Rejected and SDKDefault_Rejected mine several blocks after
// broadcasting and assert the contract's source UTXO remains unspent
// (helpers.AssertUtxoNeverSpent) rather than asserting on the broadcast RPC
// result.
// ---------------------------------------------------------------------------

// futureAuctionDeadline returns a deadline (block-height domain, far below
// the nLockTime UNIX-time threshold of 500_000_000) guaranteed to be ahead of
// the live regtest chain tip at the time this test runs.
func futureAuctionDeadline(t *testing.T) int64 {
	t.Helper()
	currentHeight, err := helpers.GetBlockCount()
	if err != nil {
		t.Fatalf("get block count: %v", err)
	}
	return int64(currentHeight) + 10_000
}

// codesepOffsetForClose recovers the OP_CODESEPARATOR byte offset the
// compiler emitted ahead of the close() method body for this specific
// deployed contract. Uses a reference PrepareCall (which computes the
// correct offset internally to build its preimage) and recoverCodeSep
// (defined in bug100_covenant_bypass_test.go) to reverse it out via known-
// exported SDK functions only — no reliance on RunarContract internals.
func codesepOffsetForClose(t *testing.T, contract *runar.RunarContract, provider runar.Provider, signer runar.Signer, auctioneer *helpers.Wallet, utxo *helpers.UTXO) int {
	t.Helper()
	refOpts := &runar.CallOptions{
		TerminalOutputs: []runar.TerminalOutput{
			{ScriptHex: auctioneer.P2PKHScript(), Satoshis: 4500},
		},
	}
	prepared, err := contract.PrepareCall("close", []interface{}{nil}, provider, signer, refOpts)
	if err != nil {
		t.Fatalf("reference PrepareCall for codesep recovery: %v", err)
	}
	return recoverCodeSep(t, prepared.TxHex, utxo.Script, utxo.Satoshis, prepared.Preimage)
}

// buildRawCloseTx builds a raw (non-SDK) close() spend of a deployed auction
// UTXO, with the given nLockTime and input nSequence set BEFORE signing — so
// both the checkSig signature and the OP_PUSH_TX preimage commit to them.
// Both signatures are computed over the scriptCode trimmed at the method's
// real OP_CODESEPARATOR offset (see codesepOffsetForClose). Returns the
// finished, signed transaction hex.
func buildRawCloseTx(t *testing.T, contract *runar.RunarContract, provider runar.Provider, signer runar.Signer, auctioneer *helpers.Wallet, utxo *helpers.UTXO, lockTime, sequence uint32) string {
	t.Helper()

	codesep := codesepOffsetForClose(t, contract, provider, signer, auctioneer, utxo)

	spendTx, err := helpers.BuildSpendTx(utxo, auctioneer.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}
	spendTx.LockTime = lockTime
	spendTx.Inputs[0].SequenceNumber = sequence

	sigHex, err := helpers.SignInputWithCodeSep(spendTx, 0, auctioneer.PrivKey, codesep)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	// checkPreimage (BUG-100 fix; see oppushtx-codegen.ts) derives its
	// OP_CHECKSIGVERIFY signature ON-CHAIN from the pushed preimage itself
	// (fixed nonce k=2, privkey d=1) — the unlocking script does NOT supply a
	// separate OP_PUSH_TX signature. Only the preimage is needed here; the
	// signature ComputeOpPushTx* also returns is for the (now unused) legacy
	// witness-signature path and must NOT be pushed, or the script leaves an
	// extra unconsumed item on the stack (CLEANSTACK rejection).
	_, preimageHex, err := helpers.SignOpPushTxWithCodeSep(spendTx, 0, codesep)
	if err != nil {
		t.Fatalf("op_push_tx preimage: %v", err)
	}
	preimageBytes, _ := hex.DecodeString(preimageHex)

	// Unlocking: <sig> <txPreimage> <methodIndex=1> (close)
	unlockHex := helpers.EncodePushBytes(sigBytes) +
		helpers.EncodePushBytes(preimageBytes) +
		helpers.EncodeMethodIndex(1)

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	return spendTx.Hex()
}

// TestAuction_CloseBeforeDeadline_FinalSequence_Rejected is the W7 regression
// guard. The spend it builds is the one that used to steal the auction: a
// close() whose nLockTime is a deadline genuinely far beyond the live regtest
// tip, but whose input nSequence is FINAL (0xffffffff). Consensus does not
// look at nLockTime on a final transaction, so the node would mine it at any
// height, and the contract's `extractLocktime(preimage) >= deadline` assert was
// satisfied by the number the spender himself wrote. This test previously
// asserted that acceptance.
//
// Auction.close now also asserts `extractSequence(txPreimage) !== 0xffffffffn`,
// so the spend dies in the script. Its sibling below — identical except for a
// non-final 0xfffffffe — is still rejected, by consensus, which is what keeps
// this pair from passing for one reason instead of two.
func TestAuction_CloseBeforeDeadline_FinalSequence_Rejected(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()

	deadline := futureAuctionDeadline(t)
	contract, _ := deployAuction(t, auctioneer, bidder, 1000, deadline)
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(auctioneer)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txHex := buildRawCloseTx(t, contract, provider, signer, auctioneer, utxo, uint32(deadline), transaction.DefaultSequenceNumber)

	helpers.AssertTxRejected(t, txHex)
	helpers.AssertUtxoNeverSpent(t, utxo.Txid, utxo.Vout, 5)
}

// TestAuction_CloseBeforeDeadline_NonFinalSequence_Rejected is the missing
// negative test from audit finding #26. Same premature close as above (a
// deadline genuinely in the future, nLockTime == deadline), but with a
// non-final input sequence (0xfffffffe) so nLockTime is actually
// consensus-enforced. SV Node may still relay it into the mempool (see the
// node-behavior note above), but it must NEVER get mined — the auction's
// time-lock holds when the transaction's sequence number actually engages
// Bitcoin's finality rule.
func TestAuction_CloseBeforeDeadline_NonFinalSequence_Rejected(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()

	deadline := futureAuctionDeadline(t)
	contract, _ := deployAuction(t, auctioneer, bidder, 1000, deadline)
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(auctioneer)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txHex := buildRawCloseTx(t, contract, provider, signer, auctioneer, utxo, uint32(deadline), 0xfffffffe)

	txid, err := helpers.SendRawTransaction(txHex)
	if err != nil {
		t.Logf("TX rejected immediately at broadcast (non-final): %v", err)
	} else {
		t.Logf("TX relayed into mempool (txid=%s) — verifying it never gets mined", txid)
	}

	helpers.AssertUtxoNeverSpent(t, utxo.Txid, utxo.Vout, 5)
}

// TestAuction_CloseBeforeDeadline_SDKDefault_Rejected is the end-to-end
// regression guard for issue #131's fix in the Go SDK. RunarContract.Call
// with CallOptions.Locktime set and Sequence left nil must default every
// input to a non-final sequence (see resolveInputSequence in
// packages/runar-go/sdk_calling.go), so a premature close (deadline still far
// in the future) submitted through the SDK's own default call path — the
// path every real caller uses, not just a hand-crafted raw tx — can NEVER be
// mined. SV Node may still relay it into the mempool (see the node-behavior
// note above; Call() returning err == nil here is expected and NOT itself a
// regression signal), so the guard checks whether the contract UTXO ever
// actually gets spent on-chain. If that ever happens, resolveInputSequence
// has silently reverted to emitting all-final sequences and #131 is open
// again.
func TestAuction_CloseBeforeDeadline_SDKDefault_Rejected(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()

	deadline := futureAuctionDeadline(t)
	contract, _ := deployAuction(t, auctioneer, bidder, 1000, deadline)
	utxo := contract.GetCurrentUtxo() // captured BEFORE Call() — Call() clears it on broadcast

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(auctioneer)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	lt := uint32(deadline)
	callOpts := &runar.CallOptions{
		Locktime: &lt,
		TerminalOutputs: []runar.TerminalOutput{
			{ScriptHex: auctioneer.P2PKHScript(), Satoshis: 4500},
		},
	}
	txid, _, err := contract.Call(
		"close",
		[]interface{}{nil}, // sig placeholder — auto-signed by SDK
		provider, signer, callOpts,
	)
	if err != nil {
		t.Logf("SDK Call rejected premature close immediately: %v", err)
	} else {
		t.Logf("SDK Call relayed premature close into mempool (txid=%s) — verifying it never gets mined", txid)
	}

	helpers.AssertUtxoNeverSpent(t, utxo.Txid, utxo.OutputIndex, 5)
}

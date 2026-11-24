package helpers

import (
	"errors"
	"fmt"
	"testing"
)

// AssertTxAccepted broadcasts a transaction and expects it to be accepted.
// Returns the txid.
func AssertTxAccepted(t *testing.T, txHex string) string {
	t.Helper()
	txid, err := SendRawTransaction(txHex)
	if err != nil {
		t.Fatalf("expected TX to be accepted but got error: %v", err)
	}
	t.Logf("TX accepted: %s", txid)
	return txid
}

// AssertTxRejected broadcasts a transaction and expects the NODE to refuse it
// because its script fails (ScriptVerifyFailed).
func AssertTxRejected(t *testing.T, txHex string) {
	t.Helper()
	AssertTxRejectedWith(t, txHex, ScriptVerifyFailed)
}

// AssertTxRejectedWith broadcasts a transaction and expects the node to refuse
// it at sendrawtransaction with a message containing reason. Any error used
// to pass, so an unreachable node or a refusal for an unrelated reason (a
// double-spend never runs the script) read as the rejection under test.
func AssertTxRejectedWith(t *testing.T, txHex string, reason string) {
	t.Helper()
	if why := checkTxRejected(txHex, reason); why != nil {
		t.Fatal(why)
	}
}

// checkTxRejected is the pure check behind AssertTxRejectedWith.
func checkTxRejected(txHex string, reason string) error {
	if reason == "" {
		return fmt.Errorf("AssertTxRejectedWith needs the rejection reason the test is about")
	}
	txid, err := SendRawTransaction(txHex)
	if err == nil {
		return fmt.Errorf("expected TX to be rejected but it was accepted: %s", txid)
	}
	var nodeErr *RPCNodeError
	if txid != "" || !errors.As(err, &nodeErr) || nodeErr.Method != "sendrawtransaction" {
		return fmt.Errorf("the node never refused the TX (it was accepted, or never ruled on): %v", err)
	}
	if !refusalMatches(nodeErr.Message, reason) {
		return fmt.Errorf("the node refused the TX for the wrong reason: expected %q, got %q", reason, nodeErr.Message)
	}
	return nil
}

// AssertTxInBlock mines a block and verifies the transaction has confirmations.
func AssertTxInBlock(t *testing.T, txid string) {
	t.Helper()
	if err := Mine(1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	tx, err := GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtransaction: %v", err)
	}
	confirmations, ok := tx["confirmations"].(float64)
	if !ok {
		// Teranode's getrawtransaction doesn't return confirmations.
		// If we can fetch the TX after mining, consider it confirmed.
		t.Logf("TX %s mined (confirmations not available)", txid)
		return
	}
	if confirmations < 1 {
		t.Fatalf("TX %s not in block (confirmations=%v)", txid, confirmations)
	}
	t.Logf("TX %s confirmed (confirmations=%v)", txid, confirmations)
}

// AssertUtxoNeverSpent mines blocksToMine blocks and then verifies (txid,
// vout) is STILL in the UTXO set (unspent). This is the correct way to prove
// a broadcast spend was never consensus-final: SV Node accepts non-final
// transactions (future nLockTime + non-final nSequence) into the mempool for
// relay, but excludes them from block templates until they become final —
// sendrawtransaction returning success (or even a txid) is NOT evidence the
// spend can ever be mined. Checking the source UTXO's on-chain spent status
// after mining is the only check that reflects actual consensus enforcement.
func AssertUtxoNeverSpent(t *testing.T, txid string, vout int, blocksToMine int) {
	t.Helper()
	if err := Mine(blocksToMine); err != nil {
		t.Fatalf("mine: %v", err)
	}
	out, err := GetTxOut(txid, vout)
	if err != nil {
		t.Fatalf("gettxout: %v", err)
	}
	if out == nil {
		t.Fatalf("UTXO %s:%d was spent — a premature/non-final spend was consensus-confirmed", txid, vout)
	}
	t.Logf("UTXO %s:%d still unspent after mining %d block(s) — spend never confirmed", txid, vout, blocksToMine)
}

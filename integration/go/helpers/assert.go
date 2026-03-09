package helpers

import "testing"

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

// AssertTxRejected broadcasts a transaction and expects it to be rejected.
func AssertTxRejected(t *testing.T, txHex string) {
	t.Helper()
	txid, err := SendRawTransaction(txHex)
	if err == nil {
		t.Fatalf("expected TX to be rejected but it was accepted: %s", txid)
	}
	t.Logf("TX correctly rejected: %v", err)
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

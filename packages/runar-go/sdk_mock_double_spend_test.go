package runar

import (
	"strings"
	"testing"
)

// MockProvider must refuse a double spend: a second, DIFFERENT transaction
// spending an outpoint an earlier accepted broadcast already spent. A node
// refuses it, so acking it lets a test "succeed" at a spend the network
// rejects.

func doubleSpendDeploy(t *testing.T, p *MockProvider) string {
	t.Helper()
	fund := strings.Repeat("ab", 32)
	p.AddUtxo("funder", UTXO{Txid: fund, OutputIndex: 0, Satoshis: 10_000, Script: mockValidationAnyoneCanSpendHex})
	deployTxid, err := p.Broadcast(buildOneInputTx(t, fund, 0, mockValidationAnyoneCanSpendHex, 10_000,
		"", 9_000, mockValidationAnyoneCanSpendHex))
	if err != nil {
		t.Fatalf("deploy broadcast: %v", err)
	}
	return deployTxid
}

func TestMockProvider_Broadcast_RefusesDoubleSpend(t *testing.T) {
	p := NewMockProvider("testnet")
	d := doubleSpendDeploy(t, p)
	first := buildOneInputTx(t, d, 0, mockValidationAnyoneCanSpendHex, 9_000, "", 8_000, mockValidationAnyoneCanSpendHex)
	if _, err := p.Broadcast(first); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	conflicting := buildOneInputTx(t, d, 0, mockValidationAnyoneCanSpendHex, 9_000, "", 7_000, mockValidationAnyoneCanSpendHex)
	if conflicting.TxID().String() == first.TxID().String() {
		t.Fatal("conflicting tx must differ from the first spend")
	}
	before := len(p.GetBroadcastedTxs())
	_, err := p.Broadcast(conflicting)
	if err == nil {
		t.Fatal("MockProvider accepted a double spend")
	}
	if !strings.Contains(err.Error(), "already spent") {
		t.Fatalf("error should name the double spend, got: %v", err)
	}
	if len(p.GetBroadcastedTxs()) != before {
		t.Fatal("a refused broadcast was recorded")
	}
}

func TestMockProvider_GetUtxos_OmitsSpentOutpoints(t *testing.T) {
	p := NewMockProvider("testnet")
	p.AddUtxo("funder", UTXO{Txid: strings.Repeat("ab", 32), OutputIndex: 1, Satoshis: 5_000, Script: mockValidationAnyoneCanSpendHex})
	doubleSpendDeploy(t, p)
	utxos, err := p.GetUtxos("funder")
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 || utxos[0].OutputIndex != 1 {
		t.Fatalf("GetUtxos must omit the spent outpoint, got %+v", utxos)
	}
}

func TestMockProvider_GetUtxos_ListsNewP2PKHOutput(t *testing.T) {
	p := NewMockProvider("testnet")
	pkh := "1111111111111111111111111111111111111111"
	p.AddUtxo(pkh, UTXO{Txid: strings.Repeat("cd", 32), OutputIndex: 0, Satoshis: 1, Script: mockValidationAnyoneCanSpendHex})
	fund := strings.Repeat("ab", 32)
	p.AddUtxo("funder", UTXO{Txid: fund, OutputIndex: 0, Satoshis: 10_000, Script: mockValidationAnyoneCanSpendHex})
	txid, err := p.Broadcast(buildOneInputTx(t, fund, 0, mockValidationAnyoneCanSpendHex, 10_000, "", 9_000, "76a914111111111111111111111111111111111111111188ac"))
	if err != nil {
		t.Fatal(err)
	}
	utxos, _ := p.GetUtxos(pkh)
	found := false
	for _, u := range utxos {
		if u.Txid == txid {
			found = u.OutputIndex == 0 && u.Satoshis == 9_000 && u.Script == "76a914111111111111111111111111111111111111111188ac"
		}
	}
	if !found {
		t.Fatalf("the new P2PKH output must be listed under %s, got %+v", pkh, utxos)
	}
}

func TestMockProvider_Broadcast_RefusesDuplicateInput(t *testing.T) {
	p := NewMockProvider("testnet")
	d := doubleSpendDeploy(t, p)
	tx := buildOneInputTx(t, d, 0, mockValidationAnyoneCanSpendHex, 9_000, "", 8_000, mockValidationAnyoneCanSpendHex)
	if err := tx.AddInputFrom(d, 0, mockValidationAnyoneCanSpendHex, 9_000, nil); err != nil {
		t.Fatal(err)
	}
	tx.Inputs[1].UnlockingScript = tx.Inputs[0].UnlockingScript
	if _, err := p.Broadcast(tx); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("a tx spending one outpoint twice must be refused, got: %v", err)
	}
}

func TestMockProvider_Broadcast_RefusedTxDoesNotSpend(t *testing.T) {
	p := NewMockProvider("testnet")
	d := doubleSpendDeploy(t, p)
	if _, err := p.Broadcast(buildOneInputTx(t, d, 0, mockValidationAnyoneCanSpendHex, 9_000, "", 50_000, mockValidationAnyoneCanSpendHex)); err == nil {
		t.Fatal("underfunded spend must be refused")
	}
	if _, err := p.Broadcast(buildOneInputTx(t, d, 0, mockValidationAnyoneCanSpendHex, 9_000, "", 8_000, mockValidationAnyoneCanSpendHex)); err != nil {
		t.Fatalf("outpoint must still be spendable after a refused broadcast: %v", err)
	}
}

func TestMockProvider_Broadcast_IdenticalRebroadcastIsNotDoubleSpend(t *testing.T) {
	p := NewMockProvider("testnet")
	d := doubleSpendDeploy(t, p)
	tx := buildOneInputTx(t, d, 0, mockValidationAnyoneCanSpendHex, 9_000, "", 8_000, mockValidationAnyoneCanSpendHex)
	first, err := p.Broadcast(tx)
	if err != nil {
		t.Fatal(err)
	}
	before := len(p.GetBroadcastedTxs())
	again, err := p.Broadcast(tx)
	if err != nil {
		t.Fatalf("re-broadcasting the identical tx must not be a double spend: %v", err)
	}
	if again != first || len(p.GetBroadcastedTxs()) != before {
		t.Fatalf("re-broadcast must be idempotent: txid %s vs %s, %d vs %d recorded", again, first, len(p.GetBroadcastedTxs()), before)
	}
}

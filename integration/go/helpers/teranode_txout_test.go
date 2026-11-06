package helpers

import "testing"

// Response shape captured from Teranode v0.13.2 GET /api/v1/utxos/:hash/json.
const teranodeUtxosJSON = `[
  {"txid":"5b85","vout":0,"lockingScript":"61ab","satoshis":5000,"utxoHash":"6066","status":"SPENT",
   "spendingData":{"txId":"6006","vin":0}},
  {"txid":"5b85","vout":1,"lockingScript":"76a9","satoshis":99994998,"utxoHash":"1afc","status":"OK"}
]`

func TestTeranodeTxOut_UnspentOutput(t *testing.T) {
	out, err := teranodeTxOutFromUtxosJSON([]byte(teranodeUtxosJSON), 1)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("status OK output reported as spent")
	}
	if out["value"] != int64(99994998) {
		t.Errorf("value: got %v", out["value"])
	}
	spk, _ := out["scriptPubKey"].(map[string]interface{})
	if spk["hex"] != "76a9" {
		t.Errorf("scriptPubKey.hex: got %v", spk["hex"])
	}
}

func TestTeranodeTxOut_SpentOutputIsNil(t *testing.T) {
	out, err := teranodeTxOutFromUtxosJSON([]byte(teranodeUtxosJSON), 0)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("SPENT output reported unspent: %v", out)
	}
}

func TestTeranodeTxOut_MissingVoutIsNil(t *testing.T) {
	out, err := teranodeTxOutFromUtxosJSON([]byte(teranodeUtxosJSON), 7)
	if err != nil || out != nil {
		t.Fatalf("want nil,nil for absent vout; got %v, %v", out, err)
	}
}

func TestTeranodeTxOut_GarbageIsError(t *testing.T) {
	if _, err := teranodeTxOutFromUtxosJSON([]byte(`{"message":"x"}`), 0); err == nil {
		t.Fatal("want error for non-array body")
	}
}

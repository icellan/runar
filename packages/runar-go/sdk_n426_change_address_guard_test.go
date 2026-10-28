package runar

// N-426: the stateful change-address guard. Replays the shared cross-SDK
// vector conformance/sdk-call/n426-change-address-guard.json (TS reference,
// Spend-validated in conformance/sdk-call/n426-change-address-guard.test.ts).
//
// Proves: on a stateful method that takes _changePKH, PrepareCall refuses
// ChangeAddress for another key (no ChangePubKey) with the shared message and
// broadcasts nothing; ChangeAddress + the matching ChangePubKey and
// ChangeAddress == the signer's own address are accepted.
// Does not prove: the terminal path, FinalizeCall, or a live node.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestN426_StatefulChangeAddressGuard(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-call")
	var g struct {
		Message        string `json:"message"`
		OtherPubKeyHex string `json:"otherPubKeyHex"`
		OtherAddress   string `json:"otherAddress"`
		OwnAddress     string `json:"ownAddress"`
	}
	var v n286Vector
	for name, dst := range map[string]interface{}{"n426-change-address-guard.json": &g, "stateful-merge-prepared.json": &v} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
	}
	var art RunarArtifact
	if err := json.Unmarshal(v.Artifact, &art); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}

	prepare := func(t *testing.T, opts *CallOptions) (*PreparedCall, *MockProvider, error) {
		t.Helper()
		signer, err := NewLocalSigner(v.PrivKeyHex)
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		addr, _ := signer.GetAddress()
		if addr != g.OwnAddress {
			t.Fatalf("signer address %s, vector says %s", addr, g.OwnAddress)
		}
		provider := NewMockProvider("testnet")
		provider.AddUtxo(addr, v.FundingUtxo)
		cu := v.ContractUtxo
		provider.AddContractUtxo(cu.Script, &cu)
		c, err := FromUtxo(&art, v.ContractUtxo)
		if err != nil {
			t.Fatalf("FromUtxo: %v", err)
		}
		prepared, err := c.PrepareCall(v.Method, []interface{}{nil}, provider, signer, opts)
		return prepared, provider, err
	}

	t.Run("refuses changeAddress for another key without changePubKey", func(t *testing.T) {
		_, provider, err := prepare(t, &CallOptions{ChangeAddress: g.OtherAddress})
		want := strings.Replace(g.Message, "{changeAddress}", g.OtherAddress, 1)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want it to contain %q", err, want)
		}
		if n := len(provider.GetBroadcastedTxs()); n != 0 {
			t.Fatalf("broadcast %d txs, want 0", n)
		}
	})
	t.Run("accepts changeAddress with the matching changePubKey", func(t *testing.T) {
		if _, _, err := prepare(t, &CallOptions{ChangeAddress: g.OtherAddress, ChangePubKey: g.OtherPubKeyHex}); err != nil {
			t.Fatalf("PrepareCall: %v", err)
		}
	})
	t.Run("accepts changeAddress equal to the signer's own address", func(t *testing.T) {
		if _, _, err := prepare(t, &CallOptions{ChangeAddress: g.OwnAddress}); err != nil {
			t.Fatalf("PrepareCall: %v", err)
		}
	})
}

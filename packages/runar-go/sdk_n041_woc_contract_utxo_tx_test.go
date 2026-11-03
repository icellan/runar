package runar

// N-041: WhatsOnChainProvider.GetContractUtxo returned Script "" (WoC's
// /script/{h}/unspent listing carries no locking script), and GetTransaction
// read GET /tx/hash/{txid}, whose JSON has no "hex" field, so Raw was always
// empty and satoshis came from float BTC values. ExternalSigner passed an
// empty subscript straight to its callback.
//
// Proves, with the shared vectors in
// conformance/sdk-woc/contract-utxo-tx-vectors.json and a stubbed HTTP server:
// GetContractUtxo returns the real locking script for both the legacy array
// and the {script,result} object listing, nil for an empty listing or a 404,
// and fails loudly on a txid mismatch, a missing output, a value mismatch, a
// script that does not hash to the requested scripthash, an empty script and
// an unavailable raw tx; GetTransaction returns the hash-verified served hex as
// Raw with inputs/outputs parsed from it and exact satoshis at 21e14 scale,
// and refuses a body that hashes to another txid; ExternalSigner refuses an
// empty subscript without calling its callback.
// Does NOT prove: that the live WoC API keeps these shapes (recorded
// 2026-09-29), nor which of several listed UTXOs is the right contract UTXO
// (the first entry is used, as before).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type wocN041Vectors struct {
	ContractUtxo struct {
		ScriptHash     string            `json:"scriptHash"`
		LegacyBody     string            `json:"legacyBody"`
		ObjectBody     string            `json:"objectBody"`
		RawTxHex       map[string]string `json:"rawTxHex"`
		ExpectedLegacy UTXO              `json:"expectedLegacy"`
		ExpectedObject UTXO              `json:"expectedObject"`
		NullVectors    []struct {
			Name string  `json:"name"`
			Body *string `json:"body"`
		} `json:"null_vectors"`
		RejectionVectors []struct {
			Name       string            `json:"name"`
			ScriptHash string            `json:"scriptHash"`
			Body       string            `json:"body"`
			RawTxHex   map[string]string `json:"rawTxHex"`
			Error      string            `json:"error"`
		} `json:"rejection_vectors"`
	} `json:"contractUtxo"`
	GetTransaction struct {
		Cases []struct {
			Name     string          `json:"name"`
			Txid     string          `json:"txid"`
			RawTxHex string          `json:"rawTxHex"`
			HashBody string          `json:"hashBody"`
			Expected TransactionData `json:"expected"`
		} `json:"cases"`
		RejectionVectors []struct {
			Name     string  `json:"name"`
			Txid     string  `json:"txid"`
			RawTxHex *string `json:"rawTxHex"`
			HashBody *string `json:"hashBody"`
			Error    string  `json:"error"`
		} `json:"rejection_vectors"`
	} `json:"getTransaction"`
}

func loadWocN041Vectors(t *testing.T) wocN041Vectors {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-woc", "contract-utxo-tx-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v wocN041Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(v.ContractUtxo.RejectionVectors) == 0 || len(v.GetTransaction.Cases) == 0 {
		t.Fatal("no N-041 vectors loaded")
	}
	return v
}

// wocN041Handler serves exact paths from routes; everything else is 404.
func wocN041Handler(routes map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if body, ok := routes[r.URL.Path]; ok {
			w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}
}

func wocN041Routes(listingPath string, listing *string, rawTxHex map[string]string) map[string]string {
	routes := map[string]string{}
	if listing != nil {
		routes[listingPath] = *listing
	}
	for txid, hex := range rawTxHex {
		routes["/tx/"+txid+"/hex"] = hex
	}
	return routes
}

func TestN041_WoCGetContractUtxo_ReturnsRealLockingScript(t *testing.T) {
	v := loadWocN041Vectors(t)
	cu := v.ContractUtxo
	path := "/script/" + cu.ScriptHash + "/unspent"
	for name, tc := range map[string]struct {
		body string
		want UTXO
	}{
		"legacy-array":  {cu.LegacyBody, cu.ExpectedLegacy},
		"object-result": {cu.ObjectBody, cu.ExpectedObject},
	} {
		t.Run(name, func(t *testing.T) {
			body := tc.body
			provider, server := newTestWoCProvider(wocN041Handler(wocN041Routes(path, &body, cu.RawTxHex)))
			defer server.Close()
			got, err := provider.GetContractUtxo(cu.ScriptHash)
			if err != nil {
				t.Fatalf("GetContractUtxo: %v", err)
			}
			if got == nil || *got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	for _, nv := range cu.NullVectors {
		t.Run("null/"+nv.Name, func(t *testing.T) {
			provider, server := newTestWoCProvider(wocN041Handler(wocN041Routes(path, nv.Body, nil)))
			defer server.Close()
			got, err := provider.GetContractUtxo(cu.ScriptHash)
			if err != nil || got != nil {
				t.Fatalf("want (nil, nil), got (%+v, %v)", got, err)
			}
		})
	}
}

func TestN041_WoCGetContractUtxo_Rejections(t *testing.T) {
	v := loadWocN041Vectors(t)
	for _, rv := range v.ContractUtxo.RejectionVectors {
		t.Run(rv.Name, func(t *testing.T) {
			body := rv.Body
			provider, server := newTestWoCProvider(wocN041Handler(
				wocN041Routes("/script/"+rv.ScriptHash+"/unspent", &body, rv.RawTxHex)))
			defer server.Close()
			got, err := provider.GetContractUtxo(rv.ScriptHash)
			if err == nil {
				t.Fatalf("expected an error containing %q, got %+v", rv.Error, got)
			}
			if !strings.Contains(err.Error(), rv.Error) {
				t.Fatalf("error %q does not contain %q", err.Error(), rv.Error)
			}
		})
	}
}

func TestN041_WoCGetTransaction_ParsesVerifiedRawTx(t *testing.T) {
	v := loadWocN041Vectors(t)
	for _, c := range v.GetTransaction.Cases {
		t.Run(c.Name, func(t *testing.T) {
			provider, server := newTestWoCProvider(wocN041Handler(map[string]string{
				"/tx/" + c.Txid + "/hex": c.RawTxHex,
				"/tx/hash/" + c.Txid:     c.HashBody,
			}))
			defer server.Close()
			got, err := provider.GetTransaction(c.Txid)
			if err != nil {
				t.Fatalf("GetTransaction: %v", err)
			}
			if !reflect.DeepEqual(*got, c.Expected) {
				t.Fatalf("got %+v\nwant %+v", *got, c.Expected)
			}
		})
	}
	for _, rv := range v.GetTransaction.RejectionVectors {
		t.Run(rv.Name, func(t *testing.T) {
			routes := map[string]string{}
			if rv.RawTxHex != nil {
				routes["/tx/"+rv.Txid+"/hex"] = *rv.RawTxHex
			}
			if rv.HashBody != nil {
				routes["/tx/hash/"+rv.Txid] = *rv.HashBody
			}
			provider, server := newTestWoCProvider(wocN041Handler(routes))
			defer server.Close()
			got, err := provider.GetTransaction(rv.Txid)
			if err == nil {
				t.Fatalf("expected an error containing %q, got %+v", rv.Error, got)
			}
			if !strings.Contains(err.Error(), rv.Error) {
				t.Fatalf("error %q does not contain %q", err.Error(), rv.Error)
			}
		})
	}
}

func TestN041_ExternalSigner_RefusesEmptySubscript(t *testing.T) {
	called := false
	signer := NewExternalSigner(strings.Repeat("02", 33), "addr",
		func(string, int, string, int64, *int) (string, error) {
			called = true
			return "deadbeef", nil
		})
	sig, err := signer.Sign(f040SpendTxHex, 0, "", 1000, nil)
	if err == nil || !strings.Contains(err.Error(), "empty subscript") {
		t.Fatalf("want an empty-subscript error, got sig %q err %v", sig, err)
	}
	if called {
		t.Fatal("callback was invoked with an empty subscript")
	}
	sig, err = signer.Sign(f040SpendTxHex, 0, "51", 1000, nil)
	if err != nil || sig != "deadbeef" || !called {
		t.Fatalf("non-empty subscript: got sig %q err %v called %v", sig, err, called)
	}
}

// N-041: ComputeOpPushTx built a preimage over an empty subscript. That can
// never match the script the node executes, so it is refused. Does not cover
// a non-empty subscript whose separator is its last byte (still accepted).
func TestN041_ComputeOpPushTx_RefusesEmptySubscript(t *testing.T) {
	if _, _, err := ComputeOpPushTx(f040SpendTxHex, 0, "", 1000); err == nil || !strings.Contains(err.Error(), "empty subscript") {
		t.Fatalf("empty subscript: want an empty-subscript error, got %v", err)
	}
	if _, pre, err := ComputeOpPushTxWithCodeSep(f040SpendTxHex, 0, "51ab51", 1000, 1); err != nil || len(pre) == 0 {
		t.Fatalf("non-empty scriptCode: got preimage len %d err %v", len(pre), err)
	}
}

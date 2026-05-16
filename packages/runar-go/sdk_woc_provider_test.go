package runar

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// newTestWoCProvider wires a WhatsOnChainProvider against a mock httptest.Server.
// The server's URL is substituted into the provider's baseURL so all subsequent
// HTTP calls hit the test handler.
func newTestWoCProvider(handler http.HandlerFunc) (*WhatsOnChainProvider, *httptest.Server) {
	server := httptest.NewServer(handler)
	p := NewWhatsOnChainProvider("mainnet")
	p.baseURL = server.URL
	return p, server
}

// ---------------------------------------------------------------------------
// Constructor / metadata
// ---------------------------------------------------------------------------

func TestWhatsOnChainProvider_NetworkURLs(t *testing.T) {
	mainnet := NewWhatsOnChainProvider("mainnet")
	if mainnet.baseURL != "https://api.whatsonchain.com/v1/bsv/main" {
		t.Errorf("mainnet URL: got %q", mainnet.baseURL)
	}
	if mainnet.GetNetwork() != "mainnet" {
		t.Errorf("mainnet network: got %q", mainnet.GetNetwork())
	}

	testnet := NewWhatsOnChainProvider("testnet")
	if testnet.baseURL != "https://api.whatsonchain.com/v1/bsv/test" {
		t.Errorf("testnet URL: got %q", testnet.baseURL)
	}

	defaultNet := NewWhatsOnChainProvider("")
	if defaultNet.GetNetwork() != "mainnet" {
		t.Errorf("default network: got %q", defaultNet.GetNetwork())
	}
}

func TestWhatsOnChainProvider_FeeRate(t *testing.T) {
	p := NewWhatsOnChainProvider("mainnet")
	rate, err := p.GetFeeRate()
	if err != nil {
		t.Fatalf("GetFeeRate error: %v", err)
	}
	if rate != 100 {
		t.Errorf("fee rate: got %d, want 100", rate)
	}
}

// ---------------------------------------------------------------------------
// GetTransaction
// ---------------------------------------------------------------------------

func TestWhatsOnChainProvider_GetTransaction(t *testing.T) {
	txid := strings.Repeat("ab", 32)

	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/tx/hash/" + txid
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		resp := map[string]interface{}{
			"txid":    txid,
			"version": 1,
			"vin": []map[string]interface{}{
				{
					"txid":      strings.Repeat("11", 32),
					"vout":      0,
					"scriptSig": map[string]interface{}{"hex": "47ab"},
					"sequence":  0xffffffff,
				},
			},
			"vout": []map[string]interface{}{
				{
					"value":        0.001,
					"n":            0,
					"scriptPubKey": map[string]interface{}{"hex": "76a91400000000000000000000000000000000000000008ac"},
				},
				{
					"value":        0.005,
					"n":            1,
					"scriptPubKey": map[string]interface{}{"hex": "a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb87"},
				},
			},
			"locktime": 0,
			"hex":      "0100000000",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	defer server.Close()

	data, err := provider.GetTransaction(txid)
	if err != nil {
		t.Fatalf("GetTransaction failed: %v", err)
	}
	if data.Txid != txid {
		t.Fatalf("expected txid %s, got %s", txid, data.Txid)
	}
	if len(data.Outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(data.Outputs))
	}
	// 0.001 BSV * 1e8 = 100000 sats
	if data.Outputs[0].Satoshis != 100000 {
		t.Fatalf("expected first output 100000 sats, got %d", data.Outputs[0].Satoshis)
	}
	// 0.005 BSV * 1e8 = 500000 sats
	if data.Outputs[1].Satoshis != 500000 {
		t.Fatalf("expected second output 500000 sats, got %d", data.Outputs[1].Satoshis)
	}
	if len(data.Inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(data.Inputs))
	}
	if data.Inputs[0].Sequence != 0xffffffff {
		t.Errorf("unexpected sequence: %d", data.Inputs[0].Sequence)
	}
}

func TestWhatsOnChainProvider_GetTransaction_HTTPError(t *testing.T) {
	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "not found")
	})
	defer server.Close()

	_, err := provider.GetTransaction("deadbeef")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUtxos
// ---------------------------------------------------------------------------

func TestWhatsOnChainProvider_GetUtxos(t *testing.T) {
	address := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/address/" + address + "/unspent"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		entries := []map[string]interface{}{
			{
				"tx_hash": strings.Repeat("aa", 32),
				"tx_pos":  0,
				"value":   1000000,
				"height":  700000,
			},
			{
				"tx_hash": strings.Repeat("bb", 32),
				"tx_pos":  1,
				"value":   5000000,
				"height":  700001,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})
	defer server.Close()

	utxos, err := provider.GetUtxos(address)
	if err != nil {
		t.Fatalf("GetUtxos failed: %v", err)
	}
	if len(utxos) != 2 {
		t.Fatalf("expected 2 UTXOs, got %d", len(utxos))
	}
	if utxos[0].Txid != strings.Repeat("aa", 32) || utxos[0].Satoshis != 1000000 || utxos[0].OutputIndex != 0 {
		t.Errorf("unexpected utxo[0]: %+v", utxos[0])
	}
	if utxos[1].Txid != strings.Repeat("bb", 32) || utxos[1].Satoshis != 5000000 || utxos[1].OutputIndex != 1 {
		t.Errorf("unexpected utxo[1]: %+v", utxos[1])
	}
}

// ---------------------------------------------------------------------------
// GetContractUtxo
// ---------------------------------------------------------------------------

func TestWhatsOnChainProvider_GetContractUtxo_Found(t *testing.T) {
	scriptHash := strings.Repeat("cd", 32)

	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/script/" + scriptHash + "/unspent"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		entries := []map[string]interface{}{
			{
				"tx_hash": strings.Repeat("ee", 32),
				"tx_pos":  3,
				"value":   42000,
				"height":  800000,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})
	defer server.Close()

	utxo, err := provider.GetContractUtxo(scriptHash)
	if err != nil {
		t.Fatalf("GetContractUtxo failed: %v", err)
	}
	if utxo == nil {
		t.Fatal("expected utxo, got nil")
	}
	if utxo.Txid != strings.Repeat("ee", 32) || utxo.Satoshis != 42000 || utxo.OutputIndex != 3 {
		t.Errorf("unexpected utxo: %+v", utxo)
	}
}

func TestWhatsOnChainProvider_GetContractUtxo_NotFound(t *testing.T) {
	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	utxo, err := provider.GetContractUtxo("nonexistent")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if utxo != nil {
		t.Fatalf("expected nil utxo on 404, got %+v", utxo)
	}
}

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

func TestWhatsOnChainProvider_Broadcast(t *testing.T) {
	expectedTxid := strings.Repeat("ff", 32)
	var gotPayload string
	var gotPath string

	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		gotPayload = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedTxid)
	})
	defer server.Close()

	tx := transaction.NewTransaction()
	txid, err := provider.Broadcast(tx)
	if err != nil {
		t.Fatalf("Broadcast failed: %v", err)
	}
	if txid != expectedTxid {
		t.Fatalf("expected txid %s, got %s", expectedTxid, txid)
	}
	if gotPath != "/tx/raw" {
		t.Errorf("expected path /tx/raw, got %s", gotPath)
	}
	if !strings.Contains(gotPayload, `"txhex"`) {
		t.Errorf("expected txhex field in payload, got %s", gotPayload)
	}
}

func TestWhatsOnChainProvider_Broadcast_HTTPError(t *testing.T) {
	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "bad tx")
	})
	defer server.Close()

	tx := transaction.NewTransaction()
	_, err := provider.Broadcast(tx)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetRawTransaction
// ---------------------------------------------------------------------------

func TestWhatsOnChainProvider_GetRawTransaction(t *testing.T) {
	txid := strings.Repeat("ef", 32)
	expectedHex := "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100000000000000000000000000"

	provider, server := newTestWoCProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/tx/" + txid + "/hex"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		io.WriteString(w, expectedHex)
	})
	defer server.Close()

	rawHex, err := provider.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("GetRawTransaction failed: %v", err)
	}
	if rawHex != expectedHex {
		t.Fatalf("expected hex %s, got %s", expectedHex, rawHex)
	}
}

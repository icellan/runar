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

// newTestGorillaPoolProvider wires a GorillaPoolProvider against a mock
// httptest.Server. The server's URL is substituted into the provider's
// baseURL so all subsequent HTTP calls hit the test handler.
func newTestGorillaPoolProvider(handler http.HandlerFunc) (*GorillaPoolProvider, *httptest.Server) {
	server := httptest.NewServer(handler)
	p := NewGorillaPoolProvider("mainnet")
	p.baseURL = server.URL
	return p, server
}

// ---------------------------------------------------------------------------
// GetTransaction
// ---------------------------------------------------------------------------

func TestGorillaPoolProvider_GetTransaction(t *testing.T) {
	txid := strings.Repeat("ab", 32)

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/tx/" + txid
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		// GorillaPool returns satoshi-valued `value` integers when >= 1000;
		// fractional BSV when < 1000. Test both branches.
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
				// satoshi-valued (>= 1000) → kept as-is
				{
					"value":        100000,
					"n":            0,
					"scriptPubKey": map[string]interface{}{"hex": "76a91400000000000000000000000000000000000000008ac"},
				},
				// fractional BSV (< 1000) → scaled by 1e8
				{
					"value":        0.005,
					"n":            1,
					"scriptPubKey": map[string]interface{}{"hex": "a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb87"},
				},
			},
			"locktime": 0,
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
	if data.Outputs[0].Satoshis != 100000 {
		t.Fatalf("expected first output 100000 sats (kept as-is), got %d", data.Outputs[0].Satoshis)
	}
	// 0.005 * 1e8 = 500000
	if data.Outputs[1].Satoshis != 500000 {
		t.Fatalf("expected second output 500000 sats (scaled), got %d", data.Outputs[1].Satoshis)
	}
	if len(data.Inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(data.Inputs))
	}
}

func TestGorillaPoolProvider_GetTransaction_HTTPError(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "boom")
	})
	defer server.Close()

	_, err := provider.GetTransaction("deadbeef")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUtxos
// ---------------------------------------------------------------------------

func TestGorillaPoolProvider_GetUtxos(t *testing.T) {
	address := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/address/" + address + "/utxos"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		entries := []map[string]interface{}{
			{
				"txid":     strings.Repeat("aa", 32),
				"vout":     0,
				"satoshis": 1000000,
				"script":   "76a914000000000000000000000000000000000000000088ac",
			},
			{
				"txid":     strings.Repeat("bb", 32),
				"vout":     1,
				"satoshis": 5000000,
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
	if utxos[0].Script != "76a914000000000000000000000000000000000000000088ac" {
		t.Errorf("expected script preserved, got %q", utxos[0].Script)
	}
	if utxos[1].Txid != strings.Repeat("bb", 32) || utxos[1].Satoshis != 5000000 || utxos[1].OutputIndex != 1 {
		t.Errorf("unexpected utxo[1]: %+v", utxos[1])
	}
}

func TestGorillaPoolProvider_GetUtxos_NotFound(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	utxos, err := provider.GetUtxos("nobody")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if len(utxos) != 0 {
		t.Fatalf("expected empty utxos on 404, got %+v", utxos)
	}
}

// ---------------------------------------------------------------------------
// GetContractUtxo
// ---------------------------------------------------------------------------

func TestGorillaPoolProvider_GetContractUtxo_Found(t *testing.T) {
	scriptHash := strings.Repeat("cd", 32)

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/script/" + scriptHash + "/utxos"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		entries := []map[string]interface{}{
			{
				"txid":     strings.Repeat("ee", 32),
				"vout":     3,
				"satoshis": 42000,
				"script":   "abcd",
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
	if utxo.Script != "abcd" {
		t.Errorf("expected script preserved, got %q", utxo.Script)
	}
}

func TestGorillaPoolProvider_GetContractUtxo_NotFound(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	utxo, err := provider.GetContractUtxo("nope")
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

func TestGorillaPoolProvider_Broadcast(t *testing.T) {
	expectedTxid := strings.Repeat("ff", 32)
	var gotPayload string
	var gotPath string

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
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
	if gotPath != "/tx" {
		t.Errorf("expected path /tx, got %s", gotPath)
	}
	if !strings.Contains(gotPayload, `"rawTx"`) {
		t.Errorf("expected rawTx field in payload, got %s", gotPayload)
	}
}

func TestGorillaPoolProvider_Broadcast_HTTPError(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
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

func TestGorillaPoolProvider_GetRawTransaction(t *testing.T) {
	txid := strings.Repeat("ef", 32)
	expectedHex := "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100000000000000000000000000"

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
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

// ---------------------------------------------------------------------------
// Ordinal-specific methods
// ---------------------------------------------------------------------------

func TestGorillaPoolProvider_GetInscriptionsByAddress(t *testing.T) {
	address := "1Ord1nal"

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/inscriptions/address/" + address
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		entries := []map[string]interface{}{
			{
				"txid":          strings.Repeat("aa", 32),
				"vout":          0,
				"origin":        "abcd_0",
				"contentType":   "text/plain",
				"contentLength": 11,
				"height":        700000,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})
	defer server.Close()

	insc, err := provider.GetInscriptionsByAddress(address)
	if err != nil {
		t.Fatalf("GetInscriptionsByAddress failed: %v", err)
	}
	if len(insc) != 1 {
		t.Fatalf("expected 1 inscription, got %d", len(insc))
	}
	if insc[0].ContentType != "text/plain" || insc[0].Origin != "abcd_0" {
		t.Errorf("unexpected inscription: %+v", insc[0])
	}
}

func TestGorillaPoolProvider_GetBSV20Balance(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/bsv20/balance/1Addr/PEPE"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		io.WriteString(w, `"12345"`)
	})
	defer server.Close()

	bal, err := provider.GetBSV20Balance("1Addr", "PEPE")
	if err != nil {
		t.Fatalf("GetBSV20Balance failed: %v", err)
	}
	if bal != "12345" {
		t.Errorf("expected 12345, got %q", bal)
	}
}

func TestGorillaPoolProvider_GetBSV20Balance_NotFound(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	bal, err := provider.GetBSV20Balance("1Addr", "PEPE")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if bal != "0" {
		t.Errorf("expected balance 0 on 404, got %q", bal)
	}
}

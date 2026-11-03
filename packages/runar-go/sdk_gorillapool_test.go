package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// newTestGorillaPoolProvider wires a GorillaPoolProvider against a mock
// httptest.Server. The server's URL is substituted into the provider's
// baseURL so all subsequent HTTP calls hit the test handler.
func newTestGorillaPoolProvider(handler http.HandlerFunc) (*GorillaPoolProvider, *httptest.Server) {
	server := httptest.NewServer(handler)
	p, err := NewGorillaPoolProvider("mainnet")
	if err != nil {
		panic(err)
	}
	p.baseURL = server.URL
	return p, server
}

// ---------------------------------------------------------------------------
// GetTransaction
// ---------------------------------------------------------------------------

// F-027: this test used to pin a `value < 1000 → BTC` heuristic on a JSON
// `vout[].value` field that GorillaPool never returns (GET /tx/{txid} is binary).
// It now replays the shared recorded vectors: GetTransaction fetches
// /tx/{txid}/raw and reads each output's 8-byte LE satoshis from the raw tx.
//
// Proves: the decoder reports 1 sat for a real 1-sat inscription output,
// 999/1000/1e12/2.1e15 exactly, and the full input/output shape; and that a
// body hashing to a different txid is rejected. Does NOT prove the live API
// still serves /tx/{txid}/raw (the vectors were recorded 2026-09-27).

type gpVectorFile struct {
	Vectors []struct {
		Name        string `json:"name"`
		Txid        string `json:"txid"`
		ResponseHex string `json:"responseHex"`
		Expected    struct {
			Version    int `json:"version"`
			Locktime   int `json:"locktime"`
			InputCount int `json:"inputCount"`
			FirstInput struct {
				Txid         string `json:"txid"`
				OutputIndex  int    `json:"outputIndex"`
				ScriptLen    int    `json:"scriptLen"`
				ScriptSha256 string `json:"scriptSha256"`
				Sequence     uint32 `json:"sequence"`
			} `json:"firstInput"`
			Outputs []struct {
				Satoshis     int64  `json:"satoshis"`
				ScriptLen    int    `json:"scriptLen"`
				ScriptSha256 string `json:"scriptSha256"`
			} `json:"outputs"`
		} `json:"expected"`
	} `json:"vectors"`
	RejectionVectors []struct {
		Name          string `json:"name"`
		RequestedTxid string `json:"requestedTxid"`
		ResponseOf    string `json:"responseOf"`
	} `json:"rejection_vectors"`
}

func loadGorillaPoolVectors(t *testing.T) gpVectorFile {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-gorillapool", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f gpVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no GorillaPool vectors loaded")
	}
	return f
}

func sha256HexOfHex(t *testing.T, h string) string {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// serveRawTx serves `body` (the recorded binary response) at /tx/{txid}/raw.
func serveRawTx(t *testing.T, txid string, body []byte) (*GorillaPoolProvider, *httptest.Server) {
	return newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tx/"+txid+"/raw" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write(body)
	})
}

func TestGorillaPoolProvider_GetTransaction(t *testing.T) {
	f := loadGorillaPoolVectors(t)
	for _, v := range f.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			body, err := hex.DecodeString(v.ResponseHex)
			if err != nil {
				t.Fatalf("bad responseHex: %v", err)
			}
			provider, server := serveRawTx(t, v.Txid, body)
			defer server.Close()

			data, err := provider.GetTransaction(v.Txid)
			if err != nil {
				t.Fatalf("GetTransaction failed: %v", err)
			}
			if data.Txid != v.Txid {
				t.Fatalf("txid: got %s, want %s", data.Txid, v.Txid)
			}
			if data.Version != v.Expected.Version || data.Locktime != v.Expected.Locktime {
				t.Fatalf("version/locktime: got %d/%d, want %d/%d", data.Version, data.Locktime, v.Expected.Version, v.Expected.Locktime)
			}
			if data.Raw != v.ResponseHex {
				t.Fatalf("Raw does not equal the recorded body hex")
			}
			if len(data.Inputs) != v.Expected.InputCount {
				t.Fatalf("inputs: got %d, want %d", len(data.Inputs), v.Expected.InputCount)
			}
			in0, want0 := data.Inputs[0], v.Expected.FirstInput
			if in0.Txid != want0.Txid || in0.OutputIndex != want0.OutputIndex || in0.Sequence != want0.Sequence ||
				len(in0.Script) != 2*want0.ScriptLen || sha256HexOfHex(t, in0.Script) != want0.ScriptSha256 {
				t.Fatalf("first input: got %+v, want %+v", in0, want0)
			}
			if len(data.Outputs) != len(v.Expected.Outputs) {
				t.Fatalf("outputs: got %d, want %d", len(data.Outputs), len(v.Expected.Outputs))
			}
			for i, want := range v.Expected.Outputs {
				got := data.Outputs[i]
				if got.Satoshis != want.Satoshis {
					t.Fatalf("output %d satoshis: got %d, want %d", i, got.Satoshis, want.Satoshis)
				}
				if len(got.Script) != 2*want.ScriptLen || sha256HexOfHex(t, got.Script) != want.ScriptSha256 {
					t.Fatalf("output %d script mismatch", i)
				}
			}
		})
	}
}

func TestGorillaPoolProvider_GetTransaction_RejectsTxidMismatch(t *testing.T) {
	f := loadGorillaPoolVectors(t)
	for _, rv := range f.RejectionVectors {
		var bodyHex string
		for _, v := range f.Vectors {
			if v.Name == rv.ResponseOf {
				bodyHex = v.ResponseHex
			}
		}
		body, _ := hex.DecodeString(bodyHex)
		provider, server := serveRawTx(t, rv.RequestedTxid, body)
		data, err := provider.GetTransaction(rv.RequestedTxid)
		server.Close()
		if err == nil {
			t.Fatalf("%s: expected an error, got tx with %d outputs", rv.Name, len(data.Outputs))
		}
		if !strings.Contains(err.Error(), "txid mismatch") {
			t.Fatalf("%s: expected a txid mismatch error, got: %v", rv.Name, err)
		}
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

// gpTestTx builds a 2-output transaction and returns it with its raw bytes and
// txid, so a handler can serve a /tx/{txid}/raw body that hash-verifies.
func gpTestTx(t *testing.T, sats0, sats1 uint64) (*transaction.Transaction, []byte, string) {
	t.Helper()
	tx := transaction.NewTransaction()
	for _, sats := range []uint64{sats0, sats1} {
		s, err := hex.DecodeString("76a914000000000000000000000000000000000000000088ac")
		if err != nil {
			t.Fatal(err)
		}
		ls := script.Script(s)
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: &ls})
	}
	return tx, tx.Bytes(), tx.TxID().String()
}

// N-025: this test used to pin GET /address/{a}/utxos (a route the live API
// 404s) and a `script` field it never returns. It now pins the documented
// /txos/address/{a}/unspent listing plus the hash-verified raw tx, from which
// each UTXO's script and value are taken.
func TestGorillaPoolProvider_GetUtxos(t *testing.T) {
	address := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	_, raw, txid := gpTestTx(t, 1000000, 5000000)

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/txos/address/" + address + "/unspent":
			entries := []map[string]interface{}{
				{"txid": txid, "vout": 0, "satoshis": 1000000},
				{"txid": txid, "vout": 1, "satoshis": 5000000},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(entries)
		case "/tx/" + txid + "/raw":
			w.Write(raw)
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	utxos, err := provider.GetUtxos(address)
	if err != nil {
		t.Fatalf("GetUtxos failed: %v", err)
	}
	if len(utxos) != 2 {
		t.Fatalf("expected 2 UTXOs, got %d", len(utxos))
	}
	if utxos[0].Txid != txid || utxos[0].Satoshis != 1000000 || utxos[0].OutputIndex != 0 {
		t.Errorf("unexpected utxo[0]: %+v", utxos[0])
	}
	if utxos[0].Script != "76a914000000000000000000000000000000000000000088ac" {
		t.Errorf("expected script from the raw tx, got %q", utxos[0].Script)
	}
	if utxos[1].Txid != txid || utxos[1].Satoshis != 5000000 || utxos[1].OutputIndex != 1 {
		t.Errorf("unexpected utxo[1]: %+v", utxos[1])
	}
}

// N-025: a 404 used to be mapped to an empty UTXO list; it now raises.
func TestGorillaPoolProvider_GetUtxos_NotFound(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	utxos, err := provider.GetUtxos("nobody")
	if err == nil {
		t.Fatalf("expected an error on 404, got utxos %+v", utxos)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetContractUtxo
// ---------------------------------------------------------------------------

// N-025: GetContractUtxo used to read GET /script/{hash}/utxos, which the live
// API does not serve. No documented route looks UTXOs up by script hash, so it
// now refuses without making a request (both former tests pin that).
func TestGorillaPoolProvider_GetContractUtxo_Found(t *testing.T) {
	scriptHash := strings.Repeat("cd", 32)
	requests := 0
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	utxo, err := provider.GetContractUtxo(scriptHash)
	if err == nil {
		t.Fatalf("expected an error, got utxo %+v", utxo)
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected a not-supported error, got: %v", err)
	}
	if utxo != nil {
		t.Fatalf("expected nil utxo, got %+v", utxo)
	}
	if requests != 0 {
		t.Fatalf("expected no HTTP request, got %d", requests)
	}
}

func TestGorillaPoolProvider_GetContractUtxo_NotFound(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	utxo, err := provider.GetContractUtxo("nope")
	if err == nil {
		t.Fatalf("expected an error, got utxo %+v", utxo)
	}
	if utxo != nil {
		t.Fatalf("expected nil utxo, got %+v", utxo)
	}
}

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

// N-025: the documented Broadcast body is {"rawtx": string}; this used to pin
// the undocumented "rawTx" spelling.
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
	var payload map[string]string
	if err := json.Unmarshal([]byte(gotPayload), &payload); err != nil {
		t.Fatalf("payload is not JSON: %s", gotPayload)
	}
	if payload["rawtx"] != tx.Hex() || len(payload) != 1 {
		t.Errorf("expected {\"rawtx\": %q}, got %s", tx.Hex(), gotPayload)
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

// N-025: this used to pin GET /tx/{txid}/hex, which the live API 404s. It now
// pins the documented binary /tx/{txid}/raw route, hex-encoded and
// hash-verified against the requested txid.
func TestGorillaPoolProvider_GetRawTransaction(t *testing.T) {
	_, raw, txid := gpTestTx(t, 1, 2)
	expectedHex := hex.EncodeToString(raw)

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/tx/" + txid + "/raw"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Write(raw)
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

// N-025: this used to pin GET /inscriptions/address/{a} (a 404 on the live
// API) returning flat InscriptionInfo rows. It now pins the documented
// /txos/address/{a}/unspent Txo listing, keeping only Txos with an origin.
func TestGorillaPoolProvider_GetInscriptionsByAddress(t *testing.T) {
	address := "1Ord1nal"

	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/txos/address/" + address + "/unspent"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		entries := []map[string]interface{}{
			{
				"txid":     strings.Repeat("aa", 32),
				"vout":     0,
				"satoshis": 1,
				"height":   700000,
				"origin": map[string]interface{}{
					"outpoint": "abcd_0",
					"data": map[string]interface{}{
						"insc": map[string]interface{}{
							"file": map[string]interface{}{"hash": "x", "size": 11, "type": "text/plain"},
						},
					},
				},
			},
			{"txid": strings.Repeat("bb", 32), "vout": 1, "satoshis": 1000, "origin": nil},
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
	if insc[0].ContentType != "text/plain" || insc[0].Origin != "abcd_0" ||
		insc[0].ContentLength != 11 || insc[0].Height != 700000 {
		t.Errorf("unexpected inscription: %+v", insc[0])
	}
}

// N-025: this used to pin GET /bsv20/balance/{a}/{tick} returning a bare
// string. It now pins the documented /bsv20/{a}/balance TokenBalanceResponse[]
// listing, from which the matching tick's all.confirmed is returned.
func TestGorillaPoolProvider_GetBSV20Balance(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/bsv20/1Addr/balance"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		io.WriteString(w, `[{"all":{"confirmed":"12345","pending":"7"},"listed":{"confirmed":"0","pending":"0"},"tick":"PEPE","dec":0},`+
			`{"all":{"confirmed":"99","pending":"0"},"listed":{"confirmed":"0","pending":"0"},"tick":"OTHER","dec":0}]`)
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

// N-025: a 404 used to be mapped to balance "0"; it now raises.
func TestGorillaPoolProvider_GetBSV20Balance_NotFound(t *testing.T) {
	provider, server := newTestGorillaPoolProvider(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	bal, err := provider.GetBSV20Balance("1Addr", "PEPE")
	if err == nil {
		t.Fatalf("expected an error on 404, got balance %q", bal)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 in error, got: %v", err)
	}
}

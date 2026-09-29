package runar

// F-040: WhatsOnChainProvider.GetUtxos returned Script "" for every UTXO,
// because WoC's GET /address/{a}/unspent listing carries no locking script.
// The empty string became the BIP-143 scriptCode in LocalSigner.Sign, so every
// funding signature was computed over a zero-length scriptCode, which no real
// P2PKH OP_CHECKSIG accepts.
//
// Proves: with the shared recorded responses (conformance/sdk-woc/vectors.json)
// GetUtxos fetches GET /tx/{txid}/hex per UTXO and returns the real locking
// script; it fails loudly on a body for another txid, a missing output, a value
// that disagrees with the tx, an unavailable tx and an empty output script; and
// LocalSigner / WalletSigner refuse an empty subscript.
// Does NOT prove: that the live WoC API still serves these shapes (vectors
// recorded 2026-09-29), or anything about GetContractUtxo. The on-chain harm
// (Spend.validate rejects the empty-scriptCode signature) is shown by the TS
// test packages/runar-sdk/src/__tests__/f040-woc-utxo-script.test.ts.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type wocF040Rejection struct {
	Name        string            `json:"name"`
	UnspentBody string            `json:"unspentBody"`
	RawTxHex    map[string]string `json:"rawTxHex"`
	Error       string            `json:"error"`
}

type wocF040Vectors struct {
	Address     string            `json:"address"`
	UnspentBody string            `json:"unspentBody"`
	RawTxHex    map[string]string `json:"rawTxHex"`
	Expected    []struct {
		Txid        string `json:"txid"`
		OutputIndex int    `json:"outputIndex"`
		Satoshis    int64  `json:"satoshis"`
		Script      string `json:"script"`
	} `json:"expected"`
	RejectionVectors []wocF040Rejection `json:"rejection_vectors"`
}

func loadWocF040Vectors(t *testing.T) wocF040Vectors {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-woc", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v wocF040Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(v.Expected) == 0 || len(v.RejectionVectors) == 0 {
		t.Fatal("no WoC vectors loaded")
	}
	return v
}

var wocF040TxHexPath = regexp.MustCompile(`^/tx/([0-9a-f]{64})/hex$`)

// wocF040Handler serves unspentBody at the address listing and each raw tx
// hex at /tx/{txid}/hex; everything else is 404.
func wocF040Handler(address, unspentBody string, rawTxHex map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/address/"+address+"/unspent" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(unspentBody))
			return
		}
		if m := wocF040TxHexPath.FindStringSubmatch(r.URL.Path); m != nil {
			if body, ok := rawTxHex[m[1]]; ok {
				w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
				w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}
}

func TestF040_WoCGetUtxos_ReturnsRealLockingScript(t *testing.T) {
	v := loadWocF040Vectors(t)
	provider, server := newTestWoCProvider(wocF040Handler(v.Address, v.UnspentBody, v.RawTxHex))
	defer server.Close()

	utxos, err := provider.GetUtxos(v.Address)
	if err != nil {
		t.Fatalf("GetUtxos: %v", err)
	}
	if len(utxos) != len(v.Expected) {
		t.Fatalf("got %d UTXOs, want %d", len(utxos), len(v.Expected))
	}
	for i, want := range v.Expected {
		got := utxos[i]
		if got.Txid != want.Txid || got.OutputIndex != want.OutputIndex ||
			got.Satoshis != want.Satoshis || got.Script != want.Script {
			t.Errorf("utxo[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestF040_WoCGetUtxos_Rejections(t *testing.T) {
	v := loadWocF040Vectors(t)
	for _, rv := range v.RejectionVectors {
		t.Run(rv.Name, func(t *testing.T) {
			provider, server := newTestWoCProvider(wocF040Handler(v.Address, rv.UnspentBody, rv.RawTxHex))
			defer server.Close()
			utxos, err := provider.GetUtxos(v.Address)
			if err == nil {
				t.Fatalf("expected an error containing %q, got UTXOs %+v", rv.Error, utxos)
			}
			if !strings.Contains(err.Error(), rv.Error) {
				t.Fatalf("error %q does not contain %q", err.Error(), rv.Error)
			}
		})
	}
}

// f040SpendTxHex is a 1-in/1-out tx spending 11..11:0.
const f040SpendTxHex = "01000000" + "01" +
	"1111111111111111111111111111111111111111111111111111111111111111" +
	"00000000" + "00" + "ffffffff" + "01" + "8403000000000000" + "01" + "51" + "00000000"

func TestF040_LocalSigner_RefusesEmptySubscript(t *testing.T) {
	signer, err := NewLocalSigner(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(f040SpendTxHex, 0, "" /* empty subscript from a WoC UTXO */, 1000, nil)
	if err == nil {
		t.Fatalf("LocalSigner.Sign with an empty subscript returned signature %s, want an error", sig)
	}
	if !strings.Contains(err.Error(), "empty subscript") {
		t.Fatalf("error %q does not mention the empty subscript", err.Error())
	}
}

func TestF040_WalletSigner_RefusesEmptySubscript(t *testing.T) {
	ws := NewWalletSigner(WalletSignerOptions{
		ProtocolID: [2]interface{}{2, "test"},
		KeyID:      "1",
		Wallet:     newMockWalletClient(""),
	})
	sig, err := ws.Sign(f040SpendTxHex, 0, "", 1000, nil)
	if err == nil {
		t.Fatalf("WalletSigner.Sign with an empty subscript returned signature %s, want an error", sig)
	}
	if !strings.Contains(err.Error(), "empty subscript") {
		t.Fatalf("error %q does not mention the empty subscript", err.Error())
	}
}

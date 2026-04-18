package contract

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// compileContract compiles BSV20Token.runar.go end-to-end and returns a
// runar.RunarArtifact suitable for driving the SDK. The compiler package's
// Artifact is JSON-equivalent to runar.RunarArtifact, so we round-trip via
// JSON to cross the package boundary.
func compileContract(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	a, err := compiler.CompileFromSource("BSV20Token.runar.go")
	if err != nil {
		t.Fatalf("BSV20Token compile failed: %v", err)
	}
	raw, err := compiler.ArtifactToJSON(a)
	if err != nil {
		t.Fatalf("artifact marshal failed: %v", err)
	}
	var out runar.RunarArtifact
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("artifact unmarshal failed: %v", err)
	}
	return &out
}

// hexToBytes decodes a hex string to bytes, failing the test on error.
func hexToBytes(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	return b
}

// parseInscriptionJSON decodes the UTF-8 JSON payload from an inscription's
// hex-encoded data field into a map.
func parseInscriptionJSON(t *testing.T, dataHex string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(hexToBytes(t, dataHex), &m); err != nil {
		t.Fatalf("parse inscription JSON: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// Business logic tests
// ---------------------------------------------------------------------------

func TestBSV20Token_Unlock(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &BSV20Token{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestBSV20Token_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.Alice.PubKey
	c := &BSV20Token{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Bob.PrivKey), runar.Bob.PubKey)
}

// ---------------------------------------------------------------------------
// Rúnar compile check
// ---------------------------------------------------------------------------

func TestBSV20Token_Compile(t *testing.T) {
	if err := runar.CompileCheck("BSV20Token.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestBSV20Token_CompilesToValidArtifact(t *testing.T) {
	a := compileContract(t)
	if a.ContractName != "BSV20Token" {
		t.Errorf("expected contractName BSV20Token, got %q", a.ContractName)
	}
}

// ---------------------------------------------------------------------------
// BSV-20 deploy inscription
// ---------------------------------------------------------------------------

func TestBSV20Token_DeployInscription(t *testing.T) {
	a := compileContract(t)
	lim := "1000"
	inscription := runar.BSV20Deploy("RUNAR", "21000000", &lim, nil)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	contract.WithInscription(inscription)

	lockingScript := contract.GetLockingScript()
	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	if parsed.ContentType != "application/bsv-20" {
		t.Errorf("contentType = %q, want application/bsv-20", parsed.ContentType)
	}
	m := parseInscriptionJSON(t, parsed.Data)
	if m["p"] != "bsv-20" || m["op"] != "deploy" || m["tick"] != "RUNAR" || m["max"] != "21000000" || m["lim"] != "1000" {
		t.Errorf("unexpected deploy payload: %+v", m)
	}
}

func TestBSV20Token_DeployInscription_WithDecimals(t *testing.T) {
	a := compileContract(t)
	dec := "8"
	inscription := runar.BSV20Deploy("USDT", "100000000", nil, &dec)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	contract.WithInscription(inscription)

	lockingScript := contract.GetLockingScript()
	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	m := parseInscriptionJSON(t, parsed.Data)
	if m["dec"] != "8" {
		t.Errorf("dec = %v, want 8", m["dec"])
	}
}

// ---------------------------------------------------------------------------
// BSV-20 mint inscription
// ---------------------------------------------------------------------------

func TestBSV20Token_MintInscription(t *testing.T) {
	a := compileContract(t)
	inscription := runar.BSV20Mint("RUNAR", "1000")
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	contract.WithInscription(inscription)

	lockingScript := contract.GetLockingScript()
	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	if parsed.ContentType != "application/bsv-20" {
		t.Errorf("contentType = %q, want application/bsv-20", parsed.ContentType)
	}
	m := parseInscriptionJSON(t, parsed.Data)
	if m["p"] != "bsv-20" || m["op"] != "mint" || m["tick"] != "RUNAR" || m["amt"] != "1000" {
		t.Errorf("unexpected mint payload: %+v", m)
	}
}

// ---------------------------------------------------------------------------
// BSV-20 transfer inscription
// ---------------------------------------------------------------------------

func TestBSV20Token_TransferInscription(t *testing.T) {
	a := compileContract(t)
	inscription := runar.BSV20Transfer("RUNAR", "50")
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	contract.WithInscription(inscription)

	lockingScript := contract.GetLockingScript()
	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	if parsed.ContentType != "application/bsv-20" {
		t.Errorf("contentType = %q, want application/bsv-20", parsed.ContentType)
	}
	m := parseInscriptionJSON(t, parsed.Data)
	if m["p"] != "bsv-20" || m["op"] != "transfer" || m["tick"] != "RUNAR" || m["amt"] != "50" {
		t.Errorf("unexpected transfer payload: %+v", m)
	}
}

// ---------------------------------------------------------------------------
// Round-trip: inscription survives FromUtxo
// ---------------------------------------------------------------------------

func TestBSV20Token_InscriptionFromUtxoRoundTrip(t *testing.T) {
	a := compileContract(t)
	inscription := runar.BSV20Deploy("TEST", "1000", nil, nil)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	contract.WithInscription(inscription)

	lockingScript := contract.GetLockingScript()
	reconnected := runar.FromUtxo(a, runar.UTXO{
		Txid:        "0000000000000000000000000000000000000000000000000000000000000000",
		OutputIndex: 0,
		Satoshis:    1,
		Script:      lockingScript,
	})
	if reconnected.GetInscription() == nil {
		t.Fatal("expected inscription after FromUtxo")
	}
	if reconnected.GetInscription().ContentType != "application/bsv-20" {
		t.Errorf("contentType = %q, want application/bsv-20", reconnected.GetInscription().ContentType)
	}
	m := parseInscriptionJSON(t, reconnected.GetInscription().Data)
	if m["p"] != "bsv-20" || m["op"] != "deploy" || m["tick"] != "TEST" || m["max"] != "1000" {
		t.Errorf("unexpected round-trip payload: %+v", m)
	}
}

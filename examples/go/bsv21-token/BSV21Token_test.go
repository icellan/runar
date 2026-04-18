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

func compileContract(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	a, err := compiler.CompileFromSource("BSV21Token.runar.go")
	if err != nil {
		t.Fatalf("BSV21Token compile failed: %v", err)
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

func hexToBytes(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	return b
}

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

func TestBSV21Token_Unlock(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &BSV21Token{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestBSV21Token_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.Alice.PubKey
	c := &BSV21Token{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Bob.PrivKey), runar.Bob.PubKey)
}

// ---------------------------------------------------------------------------
// Rúnar compile check
// ---------------------------------------------------------------------------

func TestBSV21Token_Compile(t *testing.T) {
	if err := runar.CompileCheck("BSV21Token.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestBSV21Token_CompilesToValidArtifact(t *testing.T) {
	a := compileContract(t)
	if a.ContractName != "BSV21Token" {
		t.Errorf("expected contractName BSV21Token, got %q", a.ContractName)
	}
}

// ---------------------------------------------------------------------------
// BSV-21 deploy+mint inscription
// ---------------------------------------------------------------------------

func TestBSV21Token_DeployMintInscription_AllFields(t *testing.T) {
	a := compileContract(t)
	dec := "18"
	sym := "RNR"
	icon := "b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0"
	inscription := runar.BSV21DeployMint("1000000", &dec, &sym, &icon)
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
	if m["p"] != "bsv-20" || m["op"] != "deploy+mint" || m["amt"] != "1000000" ||
		m["dec"] != "18" || m["sym"] != "RNR" || m["icon"] != icon {
		t.Errorf("unexpected deploy+mint payload: %+v", m)
	}
}

func TestBSV21Token_DeployMintInscription_MinimalFields(t *testing.T) {
	a := compileContract(t)
	inscription := runar.BSV21DeployMint("500", nil, nil, nil)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	contract.WithInscription(inscription)

	lockingScript := contract.GetLockingScript()
	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	m := parseInscriptionJSON(t, parsed.Data)
	if m["p"] != "bsv-20" || m["op"] != "deploy+mint" || m["amt"] != "500" {
		t.Errorf("unexpected minimal deploy+mint payload: %+v", m)
	}
	if _, ok := m["dec"]; ok {
		t.Error("dec should be omitted when nil")
	}
	if _, ok := m["sym"]; ok {
		t.Error("sym should be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// BSV-21 transfer inscription
// ---------------------------------------------------------------------------

func TestBSV21Token_TransferInscription(t *testing.T) {
	a := compileContract(t)
	tokenID := "3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1"
	inscription := runar.BSV21Transfer(tokenID, "100")
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
	if m["p"] != "bsv-20" || m["op"] != "transfer" || m["id"] != tokenID || m["amt"] != "100" {
		t.Errorf("unexpected transfer payload: %+v", m)
	}
}

// ---------------------------------------------------------------------------
// Round-trip: inscription survives FromUtxo
// ---------------------------------------------------------------------------

func TestBSV21Token_DeployMintFromUtxoRoundTrip(t *testing.T) {
	a := compileContract(t)
	sym := "RNR"
	inscription := runar.BSV21DeployMint("1000000", nil, &sym, nil)
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
	if m["p"] != "bsv-20" || m["op"] != "deploy+mint" || m["amt"] != "1000000" || m["sym"] != "RNR" {
		t.Errorf("unexpected round-trip payload: %+v", m)
	}
}

func TestBSV21Token_TransferFromUtxoRoundTrip(t *testing.T) {
	a := compileContract(t)
	tokenID := "abc123_0"
	inscription := runar.BSV21Transfer(tokenID, "50")
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
	m := parseInscriptionJSON(t, reconnected.GetInscription().Data)
	if m["op"] != "transfer" || m["id"] != tokenID || m["amt"] != "50" {
		t.Errorf("unexpected transfer round-trip payload: %+v", m)
	}
}

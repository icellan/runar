package contract

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func compileContract(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	a, err := compiler.CompileFromSource("OrdinalNFT.runar.go")
	if err != nil {
		t.Fatalf("OrdinalNFT compile failed: %v", err)
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

// ---------------------------------------------------------------------------
// Business logic tests
// ---------------------------------------------------------------------------

func TestOrdinalNFT_Unlock(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &OrdinalNFT{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestOrdinalNFT_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.Alice.PubKey
	c := &OrdinalNFT{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Bob.PrivKey), runar.Bob.PubKey)
}

// TestOrdinalNFT_IsStateless verifies the contract has no mutable state —
// readonly properties stay in place after Unlock.
func TestOrdinalNFT_IsStateless(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &OrdinalNFT{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
	if len(c.PubKeyHash) == 0 {
		t.Error("expected PubKeyHash to remain non-empty after unlock")
	}
}

// ---------------------------------------------------------------------------
// Rúnar compile check
// ---------------------------------------------------------------------------

func TestOrdinalNFT_Compile(t *testing.T) {
	if err := runar.CompileCheck("OrdinalNFT.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestOrdinalNFT_CompilesToValidArtifact(t *testing.T) {
	a := compileContract(t)
	if a.ContractName != "OrdinalNFT" {
		t.Errorf("expected contractName OrdinalNFT, got %q", a.ContractName)
	}
	if len(a.ABI.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(a.ABI.Methods))
	}
	if a.ABI.Methods[0].Name != "unlock" {
		t.Errorf("expected method 'unlock', got %q", a.ABI.Methods[0].Name)
	}
}

// ---------------------------------------------------------------------------
// SDK inscription flow — image/png
// ---------------------------------------------------------------------------

func TestOrdinalNFT_AttachesImageInscription(t *testing.T) {
	a := compileContract(t)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})

	// Small PNG header as inscription data
	pngData := "89504e470d0a1a0a"
	contract.WithInscription(&runar.Inscription{ContentType: "image/png", Data: pngData})

	lockingScript := contract.GetLockingScript()

	expectedEnvelope := runar.BuildInscriptionEnvelope("image/png", pngData)
	if !strings.Contains(lockingScript, expectedEnvelope) {
		t.Errorf("locking script does not contain expected envelope\n  script: %s\n  envelope: %s",
			lockingScript, expectedEnvelope)
	}

	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	if parsed.ContentType != "image/png" {
		t.Errorf("contentType = %q, want image/png", parsed.ContentType)
	}
	if parsed.Data != pngData {
		t.Errorf("data = %q, want %q", parsed.Data, pngData)
	}
}

// ---------------------------------------------------------------------------
// SDK inscription flow — text/plain
// ---------------------------------------------------------------------------

func TestOrdinalNFT_AttachesTextInscription(t *testing.T) {
	a := compileContract(t)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})

	textData := hex.EncodeToString([]byte("Hello, Ordinals!"))
	contract.WithInscription(&runar.Inscription{ContentType: "text/plain", Data: textData})

	lockingScript := contract.GetLockingScript()

	parsed := runar.ParseInscriptionEnvelope(lockingScript)
	if parsed == nil {
		t.Fatal("expected inscription envelope, got nil")
	}
	if parsed.ContentType != "text/plain" {
		t.Errorf("contentType = %q, want text/plain", parsed.ContentType)
	}
	decoded, err := hex.DecodeString(parsed.Data)
	if err != nil {
		t.Fatalf("decode text data: %v", err)
	}
	if string(decoded) != "Hello, Ordinals!" {
		t.Errorf("decoded text = %q, want %q", string(decoded), "Hello, Ordinals!")
	}
}

// ---------------------------------------------------------------------------
// Round-trip through FromUtxo
// ---------------------------------------------------------------------------

func TestOrdinalNFT_InscriptionRoundTripFromUtxo(t *testing.T) {
	a := compileContract(t)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})

	pngData := "89504e470d0a1a0a"
	contract.WithInscription(&runar.Inscription{ContentType: "image/png", Data: pngData})

	lockingScript := contract.GetLockingScript()

	reconnected := runar.FromUtxo(a, runar.UTXO{
		Txid:        "0000000000000000000000000000000000000000000000000000000000000000",
		OutputIndex: 0,
		Satoshis:    1,
		Script:      lockingScript,
	})
	insc := reconnected.GetInscription()
	if insc == nil {
		t.Fatal("expected inscription after FromUtxo")
	}
	if insc.ContentType != "image/png" {
		t.Errorf("contentType = %q, want image/png", insc.ContentType)
	}
	if insc.Data != pngData {
		t.Errorf("data = %q, want %q", insc.Data, pngData)
	}
}

// ---------------------------------------------------------------------------
// Locking script without inscription has no envelope
// ---------------------------------------------------------------------------

func TestOrdinalNFT_LockingScriptWithoutInscription(t *testing.T) {
	a := compileContract(t)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})

	lockingScript := contract.GetLockingScript()
	if parsed := runar.ParseInscriptionEnvelope(lockingScript); parsed != nil {
		t.Errorf("expected no inscription envelope, got %+v", parsed)
	}
}

// ---------------------------------------------------------------------------
// WithInscription returns receiver for chaining
// ---------------------------------------------------------------------------

func TestOrdinalNFT_WithInscriptionChaining(t *testing.T) {
	a := compileContract(t)
	contract := runar.NewRunarContract(a, []interface{}{runar.Alice.PubKeyHash})
	result := contract.WithInscription(&runar.Inscription{ContentType: "text/plain", Data: ""})
	if result != contract {
		t.Error("WithInscription should return the same contract for chaining")
	}
}

//go:build integration

package integration

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Ordinal NFT integration tests — port of integration/ts/ordinal-nft.test.ts.
//
// Deploys a P2PKH-style stateless contract with a 1sat ordinals inscription
// envelope attached, asserts the envelope round-trips through the chain
// (deploy → fetch raw tx → parse), reconnects via FromTxId and confirms the
// reconstructed locking script matches, then exercises a transfer (unlock).

var ordinalNFTArtifact *runar.RunarArtifact
var ordinalNFTOnce sync.Once

func getOrdinalNFTArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	ordinalNFTOnce.Do(func() {
		var err error
		ordinalNFTArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/ordinal-nft/OrdinalNFT.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile OrdinalNFT: %v", err)
		}
	})
	return ordinalNFTArtifact
}

// utf8ToHex converts a Go string to its hex encoding (for inscription payloads).
func utf8ToHex(s string) string {
	return hex.EncodeToString([]byte(s))
}

func TestOrdinalNFT_DeployTextInscriptionAt1Sat(t *testing.T) {
	artifact := getOrdinalNFTArtifact(t)
	t.Logf("OrdinalNFT script: %d bytes", len(artifact.Script)/2)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	textHex := utf8ToHex("Hello, 1sat ordinals!")

	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(&runar.Inscription{ContentType: "text/plain", Data: textHex})

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		t.Fatalf("get tx: %v", err)
	}
	script := tx.Outputs[0].Script
	// OP_FALSE OP_IF PUSH3 "ord" OP_1 — fixed prefix for inscription envelopes.
	if !strings.Contains(script, "0063036f726451") {
		t.Fatalf("script missing inscription envelope prefix; got %s", script)
	}
	if !strings.Contains(script, textHex) {
		t.Fatalf("script missing inscription payload (%s)", textHex)
	}
	t.Logf("deploy TX with text inscription: %s", txid)
}

func TestOrdinalNFT_RoundTripViaFromTxId(t *testing.T) {
	artifact := getOrdinalNFTArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	imageData := strings.Repeat("ff", 64)
	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(&runar.Inscription{ContentType: "image/png", Data: imageData})

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	reconnected, err := runar.FromTxId(artifact, txid, 0, provider)
	if err != nil {
		t.Fatalf("fromTxId: %v", err)
	}
	insc := reconnected.GetInscription()
	if insc == nil {
		t.Fatalf("reconnected contract has no inscription")
	}
	if insc.ContentType != "image/png" {
		t.Fatalf("contentType: got %q, want %q", insc.ContentType, "image/png")
	}
	if insc.Data != imageData {
		t.Fatalf("inscription data round-trip mismatch")
	}
	if reconnected.GetLockingScript() != contract.GetLockingScript() {
		t.Fatalf("locking script mismatch after reconnection")
	}
}

func TestOrdinalNFT_TransferSpend(t *testing.T) {
	artifact := getOrdinalNFTArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	textHex := utf8ToHex("Transferable NFT")
	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(&runar.Inscription{ContentType: "text/plain", Data: textHex})

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// unlock(sig, pubKey) — both auto-computed from the signer when nil.
	spendTxid, _, err := contract.Call("unlock", []interface{}{nil, nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if len(spendTxid) != 64 {
		t.Fatalf("expected 64-char spend txid, got %d", len(spendTxid))
	}
	t.Logf("transfer spend TX: %s", spendTxid)
}

func TestOrdinalNFT_LargeInscriptionPushdata2(t *testing.T) {
	artifact := getOrdinalNFTArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// 500 bytes — large enough to force OP_PUSHDATA2 encoding.
	largeData := strings.Repeat("ab", 500)
	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(&runar.Inscription{ContentType: "image/jpeg", Data: largeData})

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	reconnected, err := runar.FromTxId(artifact, txid, 0, provider)
	if err != nil {
		t.Fatalf("fromTxId: %v", err)
	}
	insc := reconnected.GetInscription()
	if insc == nil {
		t.Fatalf("reconnected contract has no inscription")
	}
	if insc.ContentType != "image/jpeg" {
		t.Fatalf("contentType: got %q, want image/jpeg", insc.ContentType)
	}
	if insc.Data != largeData {
		t.Fatalf("large inscription data did not round-trip")
	}
}

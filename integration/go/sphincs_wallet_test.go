//go:build integration

package integration

// SPHINCSWallet integration test -- Hybrid ECDSA + SLH-DSA-SHA2-128s contract.
// Uses the same artifact cache as slhdsa_test.go (getSLHDSAArtifact).

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Deterministic SLH-DSA test public key (32 bytes hex: PK.seed[16] || PK.root[16]).
// Generated from seed [0, 1, 2, ..., 47] with SLH-DSA-SHA2-128s (n=16).
const sphincsTestPK = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf"

func sphincsTestPKHash() string {
	pkBytes, _ := hex.DecodeString(sphincsTestPK)
	return hex.EncodeToString(crypto.Hash160(pkBytes))
}

func TestSPHINCSWallet_Compile(t *testing.T) {
	artifact := getSLHDSAArtifact(t)
	if artifact.ContractName != "SPHINCSWallet" {
		t.Fatalf("expected contract name SPHINCSWallet, got %s", artifact.ContractName)
	}
	if len(artifact.Script) == 0 {
		t.Fatalf("expected non-empty script")
	}
	t.Logf("SPHINCSWallet compiled: %d bytes", len(artifact.Script)/2)
}

func TestSPHINCSWallet_ScriptSize(t *testing.T) {
	artifact := getSLHDSAArtifact(t)
	scriptBytes := len(artifact.Script) / 2
	// SLH-DSA scripts should be approximately 188 KB
	if scriptBytes < 100000 || scriptBytes > 500000 {
		t.Fatalf("expected script size 100-500 KB, got %d bytes", scriptBytes)
	}
	t.Logf("SPHINCSWallet script size: %d bytes", scriptBytes)
}

func TestSPHINCSWallet_Deploy(t *testing.T) {
	artifact := getSLHDSAArtifact(t)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()

	pkHash := sphincsTestPKHash()

	// Constructor: (ecdsaPubKeyHash, slhdsaPubKeyHash)
	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		pkHash,
	})

	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err := helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if txid == "" {
		t.Fatalf("expected non-empty txid")
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d chars", len(txid))
	}
	t.Logf("deployed SPHINCSWallet: txid=%s", txid)
}

func TestSPHINCSWallet_DeployDifferentKey(t *testing.T) {
	artifact := getSLHDSAArtifact(t)

	ecdsaWallet := helpers.NewWallet()

	otherPK := "aabbccdd00000000000000000000000011223344556677889900aabbccddeeff"
	otherPKBytes, _ := hex.DecodeString(otherPK)
	otherPKHash := hex.EncodeToString(crypto.Hash160(otherPKBytes))

	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		otherPKHash,
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err := helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if txid == "" {
		t.Fatalf("expected non-empty txid")
	}
	t.Logf("deployed SPHINCSWallet with different key: txid=%s", txid)
}

func TestSPHINCSWallet_DeployAndVerifyUTXO(t *testing.T) {
	artifact := getSLHDSAArtifact(t)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()

	pkHash := sphincsTestPKHash()

	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		pkHash,
	})

	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err := helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d chars", len(txid))
	}

	// Contract is deployed with correct hash commitments
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("expected UTXO after deploy")
	}
	t.Logf("SPHINCSWallet deployed and UTXO verified: txid=%s", txid)
}

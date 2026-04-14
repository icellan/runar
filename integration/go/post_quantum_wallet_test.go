//go:build integration

package integration

// PostQuantumWallet integration test -- Hybrid ECDSA + WOTS+ contract.
//
// Security Model: Two-Layer Authentication
// =========================================
//
// This contract creates a quantum-resistant spending path by combining
// classical ECDSA with WOTS+ (Winternitz One-Time Signature):
//
// 1. ECDSA proves the signature commits to this specific transaction
//    (via OP_CHECKSIG over the sighash preimage).
// 2. WOTS+ proves the ECDSA signature was authorized by the WOTS key
//    holder -- the ECDSA signature bytes ARE the message that WOTS signs.
//
// A quantum attacker who can break ECDSA could forge a valid ECDSA
// signature, but they cannot produce a valid WOTS+ signature over their
// forged sig without knowing the WOTS secret key.
//
// Constructor
//   - ecdsaPubKeyHash: Addr -- 20-byte HASH160 of compressed ECDSA public key
//   - wotsPubKeyHash: ByteString -- 20-byte HASH160 of 64-byte WOTS+ public key
//
// Method: spend(wotsSig, wotsPubKey, sig, pubKey)
//   - wotsSig: 2,144-byte WOTS+ signature (67 chains x 32 bytes)
//   - wotsPubKey: 64-byte WOTS+ public key (pubSeed[32] || pkRoot[32])
//   - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
//   - pubKey: 33-byte compressed ECDSA public key
//
// Script Size
//   ~10 KB -- dominated by the inline WOTS+ verification logic.
//
// Test Approach
//   Deployment tests use hash commitments of test keys. Full spending tests
//   (including two-pass ECDSA + WOTS signing) are in wots_test.go
//   (TestWOTS_ValidSpend) which uses raw transaction construction.

import (
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

var pqwArtifact *runar.RunarArtifact
var pqwOnce sync.Once

func getPQWArtifact(t *testing.T) *runar.RunarArtifact {
	pqwOnce.Do(func() {
		var err error
		pqwArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile PostQuantumWallet: %v", err)
		}
	})
	return pqwArtifact
}

func TestPostQuantumWallet_Compile(t *testing.T) {
	artifact := getPQWArtifact(t)
	if artifact.ContractName != "PostQuantumWallet" {
		t.Fatalf("expected contract name PostQuantumWallet, got %s", artifact.ContractName)
	}
	if len(artifact.Script) == 0 {
		t.Fatalf("expected non-empty script")
	}
	t.Logf("PostQuantumWallet compiled: %d bytes", len(artifact.Script)/2)
}

func TestPostQuantumWallet_ScriptSize(t *testing.T) {
	artifact := getPQWArtifact(t)
	scriptBytes := len(artifact.Script) / 2
	// Hybrid ECDSA+WOTS+ scripts should be approximately 10 KB
	if scriptBytes < 5000 || scriptBytes > 50000 {
		t.Fatalf("expected script size 5-50 KB, got %d bytes", scriptBytes)
	}
	t.Logf("PostQuantumWallet script size: %d bytes", scriptBytes)
}

func TestPostQuantumWallet_Deploy(t *testing.T) {
	artifact := getPQWArtifact(t)

	// Generate WOTS+ keypair from a deterministic seed
	seed := make([]byte, 32)
	seed[0] = 0x42
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x01
	kp := helpers.WOTSKeygen(seed, pubSeed)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()

	// Constructor: (ecdsaPubKeyHash, wotsPubKeyHash)
	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		helpers.WOTSPubKeyHashHex(kp),
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

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if txid == "" {
		t.Fatalf("expected non-empty txid")
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d chars", len(txid))
	}
	t.Logf("deployed PostQuantumWallet: txid=%s", txid)
}

func TestPostQuantumWallet_DeployDifferentSeed(t *testing.T) {
	artifact := getPQWArtifact(t)

	ecdsaWallet := helpers.NewWallet()

	// Keypair with different seed
	seed := make([]byte, 32)
	seed[0] = 0x99
	seed[1] = 0xAB
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x02
	kp := helpers.WOTSKeygen(seed, pubSeed)

	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		helpers.WOTSPubKeyHashHex(kp),
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

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if txid == "" {
		t.Fatalf("expected non-empty txid")
	}
	t.Logf("deployed PostQuantumWallet with different seed: txid=%s", txid)
}

// TestPostQuantumWallet_DeployAndVerifyUTXO deploys and verifies UTXO exists.
//
// The hybrid spend pattern requires:
//  1. Build unsigned spending transaction
//  2. ECDSA-sign the transaction input
//  3. WOTS-sign the ECDSA signature bytes
//  4. Construct unlocking script: <wotsSig> <wotsPK> <ecdsaSig> <ecdsaPubKey>
//
// This two-pass signing pattern is fully tested in wots_test.go
// (TestWOTS_ValidSpend) which uses raw transaction construction.
func TestPostQuantumWallet_DeployAndVerifyUTXO(t *testing.T) {
	artifact := getPQWArtifact(t)

	seed := make([]byte, 32)
	seed[0] = 0x42
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x01
	kp := helpers.WOTSKeygen(seed, pubSeed)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()

	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		helpers.WOTSPubKeyHashHex(kp),
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

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
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
	t.Logf("PostQuantumWallet deployed and UTXO verified: txid=%s", txid)
}

//go:build integration

package integration

// SPHINCSWallet integration test -- Hybrid ECDSA + SLH-DSA-SHA2-128s contract.
//
// Security Model: Two-Layer Authentication
// =========================================
//
// This contract creates a quantum-resistant spending path by combining
// classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):
//
// 1. ECDSA proves the signature commits to this specific transaction
//    (via OP_CHECKSIG over the sighash preimage).
// 2. SLH-DSA proves the ECDSA signature was authorized by the SLH-DSA
//    key holder -- the ECDSA signature bytes ARE the message that SLH-DSA signs.
//
// A quantum attacker who can break ECDSA could forge a valid ECDSA
// signature, but they cannot produce a valid SLH-DSA signature over their
// forged sig without knowing the SLH-DSA secret key. SLH-DSA security
// relies only on SHA-256 collision resistance, not on any number-theoretic
// assumption vulnerable to Shor's algorithm.
//
// Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
// can sign many messages -- it's NIST FIPS 205 standardized.
//
// Constructor
//   - ecdsaPubKeyHash: Addr -- 20-byte HASH160 of compressed ECDSA public key
//   - slhdsaPubKeyHash: ByteString -- 20-byte HASH160 of 32-byte SLH-DSA public key
//
// Method: spend(slhdsaSig, slhdsaPubKey, sig, pubKey)
//   - slhdsaSig: 7,856-byte SLH-DSA-SHA2-128s signature
//   - slhdsaPubKey: 32-byte SLH-DSA public key (PK.seed[16] || PK.root[16])
//   - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
//   - pubKey: 33-byte compressed ECDSA public key
//
// Script Size
//   ~188 KB -- SLH-DSA verification requires computing multiple WOTS+
//   verifications and Merkle tree path checks within the Bitcoin Script VM.
//
// Test Approach
//   Deployment tests use hash commitments of test keys. Full spending tests
//   (including two-pass ECDSA + SLH-DSA signing) are in slhdsa_test.go
//   (TestSLHDSA_ValidSpend) which uses raw transaction construction.

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
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "SPHINCSWallet" {
		t.Fatalf("expected contract name SPHINCSWallet, got %s", artifact.ContractName)
	}
	if len(artifact.Script) == 0 {
		t.Fatalf("expected non-empty script")
	}
	t.Logf("SPHINCSWallet compiled: %d bytes", len(artifact.Script)/2)
}

func TestSPHINCSWallet_ScriptSize(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	scriptBytes := len(artifact.Script) / 2
	// SLH-DSA scripts should be approximately 188 KB
	if scriptBytes < 100000 || scriptBytes > 500000 {
		t.Fatalf("expected script size 100-500 KB, got %d bytes", scriptBytes)
	}
	t.Logf("SPHINCSWallet script size: %d bytes", scriptBytes)
}

func TestSPHINCSWallet_Deploy(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()

	pkHash := sphincsTestPKHash()

	// Constructor: (ecdsaPubKeyHash, slhdsaPubKeyHash)
	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		pkHash,
	})

	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
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
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

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
	_, err = helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
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

// TestSPHINCSWallet_DeployAndVerifyUTXO deploys and verifies UTXO exists.
//
// The hybrid spend pattern requires:
//  1. Build unsigned spending transaction
//  2. ECDSA-sign the transaction input
//  3. SLH-DSA-sign the ECDSA signature bytes
//  4. Construct unlocking script: <slhdsaSig> <slhdsaPK> <ecdsaSig> <ecdsaPubKey>
//
// This two-pass signing pattern is fully tested in slhdsa_test.go
// (TestSLHDSA_ValidSpend) which uses raw transaction construction.
func TestSPHINCSWallet_DeployAndVerifyUTXO(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()

	pkHash := sphincsTestPKHash()

	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		pkHash,
	})

	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
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

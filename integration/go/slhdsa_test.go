//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Deterministic SLH-DSA keypair for reproducible tests.
// SLH-DSA-SHA2-128s: n=16, so seed must be 3*16 = 48 bytes.
var slhdsaTestSeed = func() []byte {
	s := make([]byte, 3*16)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}()

var slhdsaTestKP = runar.SLHKeygen(runar.SLH_SHA2_128s, slhdsaTestSeed)

// deployHybridSLHDSA deploys the hybrid ECDSA+SLH-DSA contract with two hash commitments:
// ecdsaPubKeyHash (from the ECDSA wallet) and slhdsaPubKeyHash (hash160 of the SLH-DSA public key).
func deployHybridSLHDSA(t *testing.T, ecdsaWallet *helpers.Wallet, slhdsaPK []byte, funder *helpers.Wallet) *runar.RunarContract {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Hybrid ECDSA+SLH-DSA script: %d bytes", len(artifact.Script)/2)

	// Constructor args: (ecdsaPubKeyHash, slhdsaPubKeyHash)
	slhdsaPKHashHex := hex.EncodeToString(crypto.Hash160(slhdsaPK))
	contract := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		slhdsaPKHashHex,
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

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract
}

func TestSLHDSA_Compile(t *testing.T) {
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
	t.Logf("Hybrid ECDSA+SLH-DSA compiled: %d bytes", len(artifact.Script)/2)
}

func TestSLHDSA_ScriptSize(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	scriptBytes := len(artifact.Script) / 2
	if scriptBytes < 100000 || scriptBytes > 500000 {
		t.Fatalf("expected script size 100-500 KB, got %d bytes", scriptBytes)
	}
	t.Logf("Hybrid ECDSA+SLH-DSA script size: %d bytes", scriptBytes)
}

func TestSLHDSA_Deploy(t *testing.T) {
	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridSLHDSA(t, ecdsaWallet, slhdsaTestKP.PK, funder)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed hybrid ECDSA+SLH-DSA contract")
}

func TestSLHDSA_DeployDifferentKey(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ecdsaWallet := helpers.NewWallet()

	// Keypair 1 (from package-level testKP)
	pk1HashHex := hex.EncodeToString(crypto.Hash160(slhdsaTestKP.PK))

	// Keypair 2 (different seed)
	seed2 := make([]byte, 3*16)
	seed2[0] = 0xAA
	seed2[1] = 0xBB
	kp2 := runar.SLHKeygen(runar.SLH_SHA2_128s, seed2)
	pk2HashHex := hex.EncodeToString(crypto.Hash160(kp2.PK))

	if pk1HashHex == pk2HashHex {
		t.Fatalf("expected different pubkey hashes from different seeds")
	}

	// Deploy with kp1
	contract1 := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		pk1HashHex,
	})
	funder1 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder1.Address, "", false)
	_, err = helpers.FundWallet(funder1, 1.0)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	provider1 := helpers.NewRPCProvider()
	signer1, _ := helpers.SDKSignerFromWallet(funder1)
	txid1, _, err := contract1.Deploy(provider1, signer1, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("deploy1: %v", err)
	}

	// Deploy with kp2
	contract2 := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		pk2HashHex,
	})
	funder2 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder2.Address, "", false)
	_, err = helpers.FundWallet(funder2, 1.0)
	if err != nil {
		t.Fatalf("fund2: %v", err)
	}
	provider2 := helpers.NewRPCProvider()
	signer2, _ := helpers.SDKSignerFromWallet(funder2)
	txid2, _, err := contract2.Deploy(provider2, signer2, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("deploy2: %v", err)
	}

	if txid1 == txid2 {
		t.Fatalf("expected different txids, got same: %s", txid1)
	}
	t.Logf("seed1 txid: %s, seed2 txid: %s", txid1, txid2)
}

func TestSLHDSA_ValidSpend(t *testing.T) {
	if testing.Short() {
		t.Skip("SLH-DSA is very slow (~248 KB script), skipping in short mode")
	}

	// The ECDSA wallet signs the transaction; the SLH-DSA key signs the ECDSA signature
	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridSLHDSA(t, ecdsaWallet, slhdsaTestKP.PK, funder)

	// Step 1: Build the spending transaction (unsigned)
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := funder.P2PKHScript()
	tx, err := helpers.BuildSpendTx(utxo, receiverScript, 49000)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	// Step 2: ECDSA-sign the transaction input
	ecdsaSigHex, err := helpers.SignInput(tx, 0, ecdsaWallet.PrivKey)
	if err != nil {
		t.Fatalf("sign input: %v", err)
	}
	ecdsaSigBytes, _ := hex.DecodeString(ecdsaSigHex)

	// Step 3: SLH-DSA-sign the ECDSA signature bytes
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, ecdsaSigBytes, slhdsaTestKP.SK)

	// Step 4: Construct unlocking script: <slhdsaSig> <slhdsaPK> <ecdsaSig> <ecdsaPubKey>
	unlockHex := helpers.EncodePushBytes(slhdsaSig) +
		helpers.EncodePushBytes(slhdsaTestKP.PK) +
		helpers.EncodePushBytes(ecdsaSigBytes) +
		helpers.EncodePushBytes(ecdsaWallet.PubKeyBytes)

	// Apply unlocking script and broadcast
	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 49000)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	txid := helpers.AssertTxAccepted(t, spendHex)
	helpers.AssertTxInBlock(t, txid)
}

func TestSLHDSA_TamperedSig_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("SLH-DSA is very slow, skipping in short mode")
	}

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridSLHDSA(t, ecdsaWallet, slhdsaTestKP.PK, funder)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := funder.P2PKHScript()
	tx, err := helpers.BuildSpendTx(utxo, receiverScript, 49000)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	ecdsaSigHex, err := helpers.SignInput(tx, 0, ecdsaWallet.PrivKey)
	if err != nil {
		t.Fatalf("sign input: %v", err)
	}
	ecdsaSigBytes, _ := hex.DecodeString(ecdsaSigHex)

	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, ecdsaSigBytes, slhdsaTestKP.SK)

	// Tamper with SLH-DSA signature
	tampered := make([]byte, len(slhdsaSig))
	copy(tampered, slhdsaSig)
	tampered[500] ^= 0xff

	unlockHex := helpers.EncodePushBytes(tampered) +
		helpers.EncodePushBytes(slhdsaTestKP.PK) +
		helpers.EncodePushBytes(ecdsaSigBytes) +
		helpers.EncodePushBytes(ecdsaWallet.PubKeyBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 49000)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

func TestSLHDSA_WrongECDSASig_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("SLH-DSA is very slow, skipping in short mode")
	}

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridSLHDSA(t, ecdsaWallet, slhdsaTestKP.PK, funder)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := funder.P2PKHScript()
	tx, err := helpers.BuildSpendTx(utxo, receiverScript, 49000)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	ecdsaSigHex, err := helpers.SignInput(tx, 0, ecdsaWallet.PrivKey)
	if err != nil {
		t.Fatalf("sign input: %v", err)
	}
	ecdsaSigBytes, _ := hex.DecodeString(ecdsaSigHex)

	// SLH-DSA signs different bytes than the actual ECDSA signature
	wrongMsg := make([]byte, len(ecdsaSigBytes))
	copy(wrongMsg, ecdsaSigBytes)
	wrongMsg[0] ^= 0xff
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, wrongMsg, slhdsaTestKP.SK)

	unlockHex := helpers.EncodePushBytes(slhdsaSig) +
		helpers.EncodePushBytes(slhdsaTestKP.PK) +
		helpers.EncodePushBytes(ecdsaSigBytes) +
		helpers.EncodePushBytes(ecdsaWallet.PubKeyBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 49000)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

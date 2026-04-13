//go:build integration

package integration

import (
	"encoding/hex"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// deployHybridWOTS deploys the hybrid ECDSA+WOTS+ contract with two hash commitments:
// ecdsaPubKeyHash (from the ECDSA wallet) and wotsPubKeyHash (hash160 of the WOTS+ public key).
var wotsArtifact *runar.RunarArtifact
var wotsOnce sync.Once

func getWOTSArtifact(t *testing.T) *runar.RunarArtifact {
	wotsOnce.Do(func() {
		var err error
		wotsArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile PostQuantumWallet: %v", err)
		}
	})
	return wotsArtifact
}

func deployHybridWOTS(t *testing.T, ecdsaWallet *helpers.Wallet, kp helpers.WOTSKeyPair, funder *helpers.Wallet) *runar.RunarContract {
	t.Helper()

	artifact := getWOTSArtifact(t)
	t.Logf("Hybrid ECDSA+WOTS+ script: %d bytes", len(artifact.Script)/2)

	// Constructor args: (ecdsaPubKeyHash, wotsPubKeyHash)
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

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract
}

func TestWOTS_Compile(t *testing.T) {
	artifact := getWOTSArtifact(t)
	if artifact.ContractName != "PostQuantumWallet" {
		t.Fatalf("expected contract name PostQuantumWallet, got %s", artifact.ContractName)
	}
	t.Logf("Hybrid ECDSA+WOTS+ compiled: %d bytes", len(artifact.Script)/2)
}

func TestWOTS_ScriptSize(t *testing.T) {
	artifact := getWOTSArtifact(t)
	scriptBytes := len(artifact.Script) / 2
	if scriptBytes < 5000 || scriptBytes > 50000 {
		t.Fatalf("expected script size 5-50 KB, got %d bytes", scriptBytes)
	}
	t.Logf("Hybrid ECDSA+WOTS+ script size: %d bytes", scriptBytes)
}

func TestWOTS_Deploy(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 0x42
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x01
	kp := helpers.WOTSKeygen(seed, pubSeed)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridWOTS(t, ecdsaWallet, kp, funder)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed hybrid ECDSA+WOTS+ contract")
}

func TestWOTS_DeployDifferentSeed(t *testing.T) {
	seed1 := make([]byte, 32)
	seed1[0] = 0xAA
	pubSeed1 := make([]byte, 32)
	pubSeed1[0] = 0x01
	kp1 := helpers.WOTSKeygen(seed1, pubSeed1)

	seed2 := make([]byte, 32)
	seed2[0] = 0xBB
	pubSeed2 := make([]byte, 32)
	pubSeed2[0] = 0x02
	kp2 := helpers.WOTSKeygen(seed2, pubSeed2)

	if helpers.WOTSPubKeyHex(kp1) == helpers.WOTSPubKeyHex(kp2) {
		t.Fatalf("expected different pubkeys from different seeds")
	}

	artifact := getWOTSArtifact(t)

	ecdsaWallet := helpers.NewWallet()

	// Deploy with kp1
	contract1 := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		helpers.WOTSPubKeyHashHex(kp1),
	})
	funder1 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder1.Address, "", false)
	_, err := helpers.FundWallet(funder1, 1.0)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	provider1 := helpers.NewBatchRPCProvider()
	defer provider1.MineAll()
	signer1, _ := helpers.SDKSignerFromWallet(funder1)
	txid1, _, err := contract1.Deploy(provider1, signer1, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy1: %v", err)
	}

	// Deploy with kp2
	contract2 := runar.NewRunarContract(artifact, []interface{}{
		ecdsaWallet.PubKeyHashHex(),
		helpers.WOTSPubKeyHashHex(kp2),
	})
	funder2 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder2.Address, "", false)
	_, err = helpers.FundWallet(funder2, 1.0)
	if err != nil {
		t.Fatalf("fund2: %v", err)
	}
	provider2 := helpers.NewBatchRPCProvider()
	defer provider2.MineAll()
	signer2, _ := helpers.SDKSignerFromWallet(funder2)
	txid2, _, err := contract2.Deploy(provider2, signer2, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy2: %v", err)
	}

	if txid1 == txid2 {
		t.Fatalf("expected different txids, got same: %s", txid1)
	}
	t.Logf("seed1 txid: %s, seed2 txid: %s", txid1, txid2)
}

func TestWOTS_ValidSpend(t *testing.T) {
	if testing.Short() {
		t.Skip("WOTS+ is slow, skipping in short mode")
	}

	seed := make([]byte, 32)
	seed[0] = 0x42
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x01
	kp := helpers.WOTSKeygen(seed, pubSeed)

	// The ECDSA wallet signs the transaction; the WOTS key signs the ECDSA signature
	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridWOTS(t, ecdsaWallet, kp, funder)

	// Step 1: Build the spending transaction (unsigned)
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := funder.P2PKHScript()
	tx, err := helpers.BuildSpendTx(utxo, receiverScript, 9000)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	// Step 2: ECDSA-sign the transaction input
	ecdsaSigHex, err := helpers.SignInput(tx, 0, ecdsaWallet.PrivKey)
	if err != nil {
		t.Fatalf("sign input: %v", err)
	}
	ecdsaSigBytes, _ := hex.DecodeString(ecdsaSigHex)

	// Step 3: WOTS-sign the ECDSA signature bytes
	wotsSig := helpers.WOTSSign(ecdsaSigBytes, kp.SK, kp.PubSeed)
	wotsPK, _ := hex.DecodeString(helpers.WOTSPubKeyHex(kp))

	// Step 4: Construct unlocking script: <wotsSig> <wotsPK> <ecdsaSig> <ecdsaPubKey>
	unlockHex := helpers.EncodePushBytes(wotsSig) +
		helpers.EncodePushBytes(wotsPK) +
		helpers.EncodePushBytes(ecdsaSigBytes) +
		helpers.EncodePushBytes(ecdsaWallet.PubKeyBytes)

	// Apply unlocking script and broadcast
	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 9000)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	txid := helpers.AssertTxAccepted(t, spendHex)
	t.Logf("TX accepted: %s", txid)
}

func TestWOTS_TamperedSig_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("WOTS+ is slow, skipping in short mode")
	}

	seed := make([]byte, 32)
	seed[0] = 0x42
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x01
	kp := helpers.WOTSKeygen(seed, pubSeed)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridWOTS(t, ecdsaWallet, kp, funder)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := funder.P2PKHScript()
	tx, err := helpers.BuildSpendTx(utxo, receiverScript, 9000)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	ecdsaSigHex, err := helpers.SignInput(tx, 0, ecdsaWallet.PrivKey)
	if err != nil {
		t.Fatalf("sign input: %v", err)
	}
	ecdsaSigBytes, _ := hex.DecodeString(ecdsaSigHex)

	wotsSig := helpers.WOTSSign(ecdsaSigBytes, kp.SK, kp.PubSeed)
	wotsPK, _ := hex.DecodeString(helpers.WOTSPubKeyHex(kp))

	// Tamper with WOTS signature
	tampered := make([]byte, len(wotsSig))
	copy(tampered, wotsSig)
	tampered[100] ^= 0xff

	unlockHex := helpers.EncodePushBytes(tampered) +
		helpers.EncodePushBytes(wotsPK) +
		helpers.EncodePushBytes(ecdsaSigBytes) +
		helpers.EncodePushBytes(ecdsaWallet.PubKeyBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 9000)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

func TestWOTS_WrongECDSASig_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("WOTS+ is slow, skipping in short mode")
	}

	seed := make([]byte, 32)
	seed[0] = 0x42
	pubSeed := make([]byte, 32)
	pubSeed[0] = 0x01
	kp := helpers.WOTSKeygen(seed, pubSeed)

	ecdsaWallet := helpers.NewWallet()
	funder := helpers.NewWallet()
	contract := deployHybridWOTS(t, ecdsaWallet, kp, funder)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := funder.P2PKHScript()
	tx, err := helpers.BuildSpendTx(utxo, receiverScript, 9000)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	ecdsaSigHex, err := helpers.SignInput(tx, 0, ecdsaWallet.PrivKey)
	if err != nil {
		t.Fatalf("sign input: %v", err)
	}
	ecdsaSigBytes, _ := hex.DecodeString(ecdsaSigHex)

	// WOTS signs different bytes than the actual ECDSA signature
	wrongMsg := make([]byte, len(ecdsaSigBytes))
	copy(wrongMsg, ecdsaSigBytes)
	wrongMsg[0] ^= 0xff
	wotsSig := helpers.WOTSSign(wrongMsg, kp.SK, kp.PubSeed)
	wotsPK, _ := hex.DecodeString(helpers.WOTSPubKeyHex(kp))

	unlockHex := helpers.EncodePushBytes(wotsSig) +
		helpers.EncodePushBytes(wotsPK) +
		helpers.EncodePushBytes(ecdsaSigBytes) +
		helpers.EncodePushBytes(ecdsaWallet.PubKeyBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 9000)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

//go:build integration

package integration

import (
	"encoding/hex"
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

func deployOraclePriceFeed(t *testing.T, oracleKP *helpers.RabinKeyPair, receiver *helpers.Wallet) *runar.RunarContract {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/oracle-price/OraclePriceFeed.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("OraclePriceFeed script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{
		oracleKP.N,
		receiver.PubKeyHex(),
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

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract
}

func TestOracle_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/oracle-price/OraclePriceFeed.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "OraclePriceFeed" {
		t.Fatalf("expected contract name OraclePriceFeed, got %s", artifact.ContractName)
	}
	t.Logf("OraclePriceFeed compiled: %d bytes", len(artifact.Script)/2)
}

func TestOracle_Deploy(t *testing.T) {
	receiver := helpers.NewWallet()
	oracleKP, err := helpers.GenerateRabinKeyPair()
	if err != nil {
		t.Fatalf("rabin keygen: %v", err)
	}
	contract := deployOraclePriceFeed(t, oracleKP, receiver)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed oracle price feed")
}

func TestOracle_DeployDifferentReceiver(t *testing.T) {
	receiver1 := helpers.NewWallet()
	receiver2 := helpers.NewWallet()
	oracleKP, err := helpers.GenerateRabinKeyPair()
	if err != nil {
		t.Fatalf("rabin keygen: %v", err)
	}

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/oracle-price/OraclePriceFeed.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Deploy with receiver1
	contract1 := runar.NewRunarContract(artifact, []interface{}{oracleKP.N, receiver1.PubKeyHex()})
	funder1 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder1.Address, "", false)
	_, err = helpers.FundWallet(funder1, 1.0)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	provider1 := helpers.NewRPCProvider()
	signer1, _ := helpers.SDKSignerFromWallet(funder1)
	txid1, _, err := contract1.Deploy(provider1, signer1, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy1: %v", err)
	}

	// Deploy with receiver2
	contract2 := runar.NewRunarContract(artifact, []interface{}{oracleKP.N, receiver2.PubKeyHex()})
	funder2 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder2.Address, "", false)
	_, err = helpers.FundWallet(funder2, 1.0)
	if err != nil {
		t.Fatalf("fund2: %v", err)
	}
	provider2 := helpers.NewRPCProvider()
	signer2, _ := helpers.SDKSignerFromWallet(funder2)
	txid2, _, err := contract2.Deploy(provider2, signer2, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy2: %v", err)
	}

	if txid1 == txid2 {
		t.Fatalf("expected different txids, got same: %s", txid1)
	}
	t.Logf("receiver1 txid: %s, receiver2 txid: %s", txid1, txid2)
}

func TestOracle_ValidSettle(t *testing.T) {
	receiver := helpers.NewWallet()
	oracleKP, err := helpers.GenerateRabinKeyPair()
	if err != nil {
		t.Fatalf("rabin keygen: %v", err)
	}

	contract := deployOraclePriceFeed(t, oracleKP, receiver)

	// Get UTXO from SDK contract, convert for raw spending
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	// Oracle signs price=55001 (above 50000 threshold)
	price := int64(55001)
	msgBytes := helpers.Num2binLE(big.NewInt(price), 8)
	rabinSig, err := helpers.RabinSign(msgBytes, oracleKP)
	if err != nil {
		t.Fatalf("rabin sign: %v", err)
	}

	// Build spending TX
	spendTx, err := helpers.BuildSpendTx(utxo, receiver.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}

	receiverSigHex, err := helpers.SignInput(spendTx, 0, receiver.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	receiverSigBytes, _ := hex.DecodeString(receiverSigHex)

	// Unlocking: <price> <rabinSig> <padding> <receiverSig>
	unlockHex := helpers.EncodePushInt(price) +
		helpers.EncodePushBigInt(rabinSig.Sig) +
		helpers.EncodePushBigInt(rabinSig.Padding) +
		helpers.EncodePushBytes(receiverSigBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiver.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}

	txid := helpers.AssertTxAccepted(t, spendHex)
	helpers.AssertTxInBlock(t, txid)
}

func TestOracle_PriceBelowThreshold_Rejected(t *testing.T) {
	receiver := helpers.NewWallet()
	oracleKP, err := helpers.GenerateRabinKeyPair()
	if err != nil {
		t.Fatalf("rabin keygen: %v", err)
	}

	contract := deployOraclePriceFeed(t, oracleKP, receiver)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	// Price 49999 is below the 50000 threshold
	price := int64(49999)
	msgBytes := helpers.Num2binLE(big.NewInt(price), 8)
	rabinSig, err := helpers.RabinSign(msgBytes, oracleKP)
	if err != nil {
		t.Fatalf("rabin sign: %v", err)
	}

	spendTx, err := helpers.BuildSpendTx(utxo, receiver.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}
	receiverSigHex, err := helpers.SignInput(spendTx, 0, receiver.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	receiverSigBytes, _ := hex.DecodeString(receiverSigHex)

	unlockHex := helpers.EncodePushInt(price) +
		helpers.EncodePushBigInt(rabinSig.Sig) +
		helpers.EncodePushBigInt(rabinSig.Padding) +
		helpers.EncodePushBytes(receiverSigBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiver.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

func TestOracle_WrongReceiver_Rejected(t *testing.T) {
	receiver := helpers.NewWallet()
	wrongKey := helpers.NewWallet()
	oracleKP, err := helpers.GenerateRabinKeyPair()
	if err != nil {
		t.Fatalf("rabin keygen: %v", err)
	}

	contract := deployOraclePriceFeed(t, oracleKP, receiver)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	price := int64(55001)
	msgBytes := helpers.Num2binLE(big.NewInt(price), 8)
	rabinSig, err := helpers.RabinSign(msgBytes, oracleKP)
	if err != nil {
		t.Fatalf("rabin sign: %v", err)
	}

	// Sign with wrong key (not the receiver)
	spendTx, err := helpers.BuildSpendTx(utxo, wrongKey.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}
	wrongSigHex, err := helpers.SignInput(spendTx, 0, wrongKey.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wrongSigBytes, _ := hex.DecodeString(wrongSigHex)

	unlockHex := helpers.EncodePushInt(price) +
		helpers.EncodePushBigInt(rabinSig.Sig) +
		helpers.EncodePushBigInt(rabinSig.Padding) +
		helpers.EncodePushBytes(wrongSigBytes)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, wrongKey.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

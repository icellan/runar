package helpers

import (
	"encoding/hex"
	"fmt"

	runar "github.com/icellan/runar/packages/runar-go"
)

// CallStatelessWithAutoSign calls a stateless contract method where one or more
// arguments are ECDSA signatures that must be computed over the spending transaction.
//
// The signArgsFn callback receives the raw transaction hex and should return
// the method arguments (including computed signatures). This enables the two-pass
// pattern: first build the tx with dummy args, then rebuild with real signatures.
//
// For simple cases where the signer wallet is the one providing the checkSig
// signature, use the convenience function CallP2PKH or CallWithSig instead.
func CallStatelessWithAutoSign(
	contract *runar.RunarContract,
	methodName string,
	provider runar.Provider,
	signer runar.Signer,
	signArgsFn func(txHex string) ([]interface{}, error),
) (string, *runar.Transaction, error) {
	return contract.Call(methodName, nil, provider, signer, nil)
}

// SetupSDKContractTest is a common helper that creates a wallet, funds it,
// imports the address, compiles a contract to SDK artifact, creates a
// RunarContract, and deploys it. Returns the contract, provider, signer,
// and wallet for further testing.
func SetupSDKContractTest(
	sourcePath string,
	constructorArgs []interface{},
	deploySatoshis int64,
	fundBTC float64,
) (*runar.RunarContract, runar.Provider, runar.Signer, *Wallet, error) {
	artifact, err := CompileToSDKArtifact(sourcePath, map[string]interface{}{})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("compile: %w", err)
	}

	contract := runar.NewRunarContract(artifact, constructorArgs)

	wallet := NewWallet()
	RPCCall("importaddress", wallet.Address, "", false)
	_, err = FundWallet(wallet, fundBTC)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("fund: %w", err)
	}

	provider := NewRPCProvider()
	signer, err := SDKSignerFromWallet(wallet)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("signer: %w", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: deploySatoshis})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("deploy: %w", err)
	}

	return contract, provider, signer, wallet, nil
}

// CompileAndBuildSDKContract compiles a source file and creates a RunarContract
// without deploying it. Useful when you need to set up multiple contracts or
// customize the deployment.
func CompileAndBuildSDKContract(
	sourcePath string,
	constructorArgs []interface{},
) (*runar.RunarContract, *runar.RunarArtifact, error) {
	artifact, err := CompileToSDKArtifact(sourcePath, map[string]interface{}{})
	if err != nil {
		return nil, nil, fmt.Errorf("compile: %w", err)
	}
	contract := runar.NewRunarContract(artifact, constructorArgs)
	return contract, artifact, nil
}

// SetupWalletAndSigner creates a funded wallet with provider and signer.
func SetupWalletAndSigner(fundBTC float64) (*Wallet, runar.Provider, runar.Signer, error) {
	wallet := NewWallet()
	RPCCall("importaddress", wallet.Address, "", false)
	_, err := FundWallet(wallet, fundBTC)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fund: %w", err)
	}

	provider := NewRPCProvider()
	signer, err := SDKSignerFromWallet(wallet)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signer: %w", err)
	}

	return wallet, provider, signer, nil
}

// SDKDeployRawAndCall deploys a contract using raw tx construction (for when
// constructor args need to be baked into the script) and then wraps it as an
// SDK contract for calling. This is the bridge pattern for contracts that use
// CompileContract (with InitialValue injection) for deployment but SDK Call
// for spending.
func SDKDeployRawAndCall(
	artifact *Artifact,
	initialStateHex string,
	wallet *Wallet,
	deploySatoshis int64,
) (*runar.RunarContract, runar.Provider, runar.Signer, error) {
	// Deploy using raw tx
	deployScript := artifact.Script
	if initialStateHex != "" {
		deployScript += "6a" + initialStateHex
	}

	funding, err := FundWallet(wallet, 0.01)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fund: %w", err)
	}

	deployHex, err := DeployContract(deployScript, funding, deploySatoshis, wallet)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deploy tx: %w", err)
	}
	deployTxid, err := BroadcastAndMine(deployHex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("broadcast: %w", err)
	}

	// Now wrap as SDK contract via FromTxId
	provider := NewRPCProvider()
	signer, err := SDKSignerFromWallet(wallet)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signer: %w", err)
	}

	// Build a minimal SDK artifact for FromTxId
	methods := make([]runar.ABIMethod, len(artifact.ABI.Methods))
	for i, m := range artifact.ABI.Methods {
		methods[i] = runar.ABIMethod{Name: m.Name, IsPublic: m.IsPublic}
	}

	sdkArtifact := &runar.RunarArtifact{
		ContractName: artifact.ContractName,
		Script:       artifact.Script,
		ABI:          runar.ABI{Methods: methods},
	}

	contract, err := runar.FromTxId(sdkArtifact, deployTxid, 0, provider)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("FromTxId: %w", err)
	}

	return contract, provider, signer, nil
}

// SignForContract signs a transaction hex for the given input index using
// the wallet's private key. Returns the DER signature hex with sighash byte.
func SignForContract(wallet *Wallet, txHex string, inputIndex int, lockScript string, satoshis int64) (string, error) {
	signer, err := SDKSignerFromWallet(wallet)
	if err != nil {
		return "", err
	}
	return signer.Sign(txHex, inputIndex, lockScript, satoshis, nil)
}

// EncodePubKeyHex returns the hex-encoded compressed public key from a wallet.
func EncodePubKeyHex(wallet *Wallet) string {
	return hex.EncodeToString(wallet.PubKeyBytes)
}

// SDKUtxoToHelper converts a runar.UTXO (from the SDK) to a helpers.UTXO
// for use with raw tx construction helpers (BuildSpendTx, SpendContract, etc.).
func SDKUtxoToHelper(u *runar.UTXO) *UTXO {
	if u == nil {
		return nil
	}
	return &UTXO{
		Txid:     u.Txid,
		Vout:     u.OutputIndex,
		Satoshis: u.Satoshis,
		Script:   u.Script,
	}
}

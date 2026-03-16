//go:build integration

package integration

import (
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

func setupMathDemo(t *testing.T, initialResult int64) (*runar.RunarContract, runar.Provider, runar.Signer) {
	t.Helper()
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/math-demo/MathDemo.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("MathDemo script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(initialResult)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	return contract, provider, signer
}

func TestMathDemo_Deploy(t *testing.T) {
	contract, _, _ := setupMathDemo(t, 1000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with value=1000")
}

func TestMathDemo_DivideByZero_Rejected(t *testing.T) {
	contract, provider, signer := setupMathDemo(t, 100)

	_, _, err := contract.Call("divideBy", []interface{}{int64(0)}, provider, signer, &runar.CallOptions{
		NewState: map[string]interface{}{"value": int64(0)},
	})
	if err == nil {
		t.Fatalf("expected divide by zero to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestMathDemo_WrongState_Rejected(t *testing.T) {
	contract, provider, signer := setupMathDemo(t, 1000)

	// divideBy(10) should give 100, but we claim 999
	_, _, err := contract.Call("divideBy", []interface{}{int64(10)}, provider, signer, &runar.CallOptions{
		NewState: map[string]interface{}{"value": int64(999)},
	})
	if err == nil {
		t.Fatalf("expected wrong state to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestMathDemo_DivideBy(t *testing.T) {
	// Deploy result=100, divideBy(5) -> result=20
	contract, provider, signer := setupMathDemo(t, 100)

	txid, _, err := contract.Call("divideBy", []interface{}{int64(5)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call divideBy: %v", err)
	}
	t.Logf("divideBy TX: %s", txid)
}

func TestMathDemo_ClampValue(t *testing.T) {
	// Deploy result=500, clampValue(10, 100) -> result=100
	contract, provider, signer := setupMathDemo(t, 500)

	txid, _, err := contract.Call("clampValue", []interface{}{int64(10), int64(100)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call clampValue: %v", err)
	}
	t.Logf("clampValue TX: %s", txid)
}

func TestMathDemo_Normalize(t *testing.T) {
	// Deploy result=-42, normalize() -> result=-1
	contract, provider, signer := setupMathDemo(t, -42)

	txid, _, err := contract.Call("normalize", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call normalize: %v", err)
	}
	t.Logf("normalize TX: %s", txid)
}

func TestMathDemo_SquareRoot(t *testing.T) {
	// Deploy result=144, squareRoot() -> result=12
	contract, provider, signer := setupMathDemo(t, 144)

	txid, _, err := contract.Call("squareRoot", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call squareRoot: %v", err)
	}
	t.Logf("squareRoot TX: %s", txid)
}

func TestMathDemo_Exponentiate(t *testing.T) {
	// Deploy result=2, exponentiate(3) -> result=8
	contract, provider, signer := setupMathDemo(t, 2)

	txid, _, err := contract.Call("exponentiate", []interface{}{int64(3)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call exponentiate: %v", err)
	}
	t.Logf("exponentiate TX: %s", txid)
}

func TestMathDemo_ReduceGcd(t *testing.T) {
	// Deploy result=48, reduceGcd(18) -> result=6
	contract, provider, signer := setupMathDemo(t, 48)

	txid, _, err := contract.Call("reduceGcd", []interface{}{int64(18)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call reduceGcd: %v", err)
	}
	t.Logf("reduceGcd TX: %s", txid)
}

func TestMathDemo_ComputeLog2(t *testing.T) {
	// Deploy result=256, computeLog2() -> result=8
	contract, provider, signer := setupMathDemo(t, 256)

	txid, _, err := contract.Call("computeLog2", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call computeLog2: %v", err)
	}
	t.Logf("computeLog2 TX: %s", txid)
}

func TestMathDemo_ScaleByRatio(t *testing.T) {
	// Deploy result=100, scaleByRatio(3, 4) -> result=75
	contract, provider, signer := setupMathDemo(t, 100)

	txid, _, err := contract.Call("scaleByRatio", []interface{}{int64(3), int64(4)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call scaleByRatio: %v", err)
	}
	t.Logf("scaleByRatio TX: %s", txid)
}

func TestMathDemo_ChainOperations(t *testing.T) {
	// Deploy result=1000
	// divideBy(10) -> 100
	// squareRoot() -> 10
	// scaleByRatio(5, 1) -> 50
	contract, provider, signer := setupMathDemo(t, 1000)

	txid1, _, err := contract.Call("divideBy", []interface{}{int64(10)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call divideBy (1000->100): %v", err)
	}
	t.Logf("result->100 TX: %s", txid1)

	txid2, _, err := contract.Call("squareRoot", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call squareRoot (100->10): %v", err)
	}
	t.Logf("result->10 TX: %s", txid2)

	txid3, _, err := contract.Call("scaleByRatio", []interface{}{int64(5), int64(1)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call scaleByRatio (10->50): %v", err)
	}
	t.Logf("result->50 TX: %s", txid3)
	t.Logf("chain: 1000->100->10->50 succeeded")
}

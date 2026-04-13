//go:build integration

package integration

import (
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Helper: deploy contract then call with args — expect the call to be REJECTED.
// The contract's assert(result === expected) must fail on-chain.
// ---------------------------------------------------------------------------

func expectRejected(t *testing.T, source, fileName string, ctorVals []interface{}, methodName string, methodArgs []interface{}) {
	t.Helper()
	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, ctorVals)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	_, _, err = contract.Call(methodName, methodArgs, provider, signer, nil)
	if err == nil {
		t.Fatal("SECURITY: wrong value was accepted on-chain — expected rejection")
	}
}

// ===========================================================================
// BabyBear negative tests
// ===========================================================================

func TestNeg_BB_FieldSub_WrongResult(t *testing.T) {
	// 10 - 3 = 7, not 8
	expectRejected(t, bbSubContractSource, "BBSubVec.runar.ts",
		[]interface{}{big.NewInt(8)}, "verify", []interface{}{big.NewInt(10), big.NewInt(3)})
}

func TestNeg_BB_FieldMul_WrongResult(t *testing.T) {
	// 3 * 7 = 21, not 22
	expectRejected(t, bbMulContractSource, "BBMulVec.runar.ts",
		[]interface{}{big.NewInt(22)}, "verify", []interface{}{big.NewInt(3), big.NewInt(7)})
}

func TestNeg_BB_FieldInv_WrongResult(t *testing.T) {
	// inv(2) != 0
	expectRejected(t, bbInvContractSource, "BBInvVec.runar.ts",
		[]interface{}{big.NewInt(0)}, "verify", []interface{}{big.NewInt(2)})
}

func TestNeg_BB_FieldAdd_WrapAround_Wrong(t *testing.T) {
	// (p-1) + 1 = 0, not 1
	pMinus1 := new(big.Int).Sub(bbP, big.NewInt(1))
	expectRejected(t, bbAddContractSource, "BBAddVec.runar.ts",
		[]interface{}{big.NewInt(1)}, "verify", []interface{}{pMinus1, big.NewInt(1)})
}

// ===========================================================================
// KoalaBear negative tests
// ===========================================================================

var kbP = big.NewInt(2130706433)

func TestNeg_KB_FieldAdd_WrongResult(t *testing.T) {
	// 5 + 9 = 14, not 15
	expectRejected(t, kbAddContractSource, "KBAddVec.runar.ts",
		[]interface{}{big.NewInt(15)}, "verify", []interface{}{big.NewInt(5), big.NewInt(9)})
}

func TestNeg_KB_FieldSub_WrongResult(t *testing.T) {
	// 10 - 3 = 7, not 8
	expectRejected(t, kbSubContractSource, "KBSubVec.runar.ts",
		[]interface{}{big.NewInt(8)}, "verify", []interface{}{big.NewInt(10), big.NewInt(3)})
}

func TestNeg_KB_FieldMul_WrongResult(t *testing.T) {
	// 4 * 5 = 20, not 21
	expectRejected(t, kbMulContractSource, "KBMulVec.runar.ts",
		[]interface{}{big.NewInt(21)}, "verify", []interface{}{big.NewInt(4), big.NewInt(5)})
}

func TestNeg_KB_FieldInv_WrongResult(t *testing.T) {
	// inv(3) != 0
	expectRejected(t, kbInvContractSource, "KBInvVec.runar.ts",
		[]interface{}{big.NewInt(0)}, "verify", []interface{}{big.NewInt(3)})
}

func TestNeg_KB_FieldAdd_WrapAround_Wrong(t *testing.T) {
	// (p-1) + 1 = 0, not p (which equals 0 mod p, but the value 'p' is not in the field)
	// Actually (p-1) + 1 = 0, not 1
	pMinus1 := new(big.Int).Sub(kbP, big.NewInt(1))
	expectRejected(t, kbAddContractSource, "KBAddVec.runar.ts",
		[]interface{}{big.NewInt(1)}, "verify", []interface{}{pMinus1, big.NewInt(1)})
}

func TestNeg_KB_FieldSub_Underflow_Wrong(t *testing.T) {
	// 0 - 1 = p-1 (not 0)
	expectRejected(t, kbSubContractSource, "KBSubVec.runar.ts",
		[]interface{}{big.NewInt(0)}, "verify", []interface{}{big.NewInt(0), big.NewInt(1)})
}

func TestNeg_KB_Ext4Mul_WrongComponent(t *testing.T) {
	// (1,0,0,0) * (1,0,0,0) = (1,0,0,0), not (2,0,0,0)
	expectRejected(t, kbExt4MulContractSource, "KBExt4MulVec.runar.ts",
		[]interface{}{big.NewInt(2), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		"verify", []interface{}{
			big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		})
}

func TestNeg_KB_Ext4Inv_WrongComponent(t *testing.T) {
	// inv(1,0,0,0) = (1,0,0,0), not (0,0,0,0)
	expectRejected(t, kbExt4InvContractSource, "KBExt4InvVec.runar.ts",
		[]interface{}{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		"verify", []interface{}{
			big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		})
}

// ===========================================================================
// BN254 negative tests
// ===========================================================================

func TestNeg_BN254_FieldAdd_WrongResult(t *testing.T) {
	a, _ := new(big.Int).SetString("7", 10)
	b, _ := new(big.Int).SetString("11", 10)
	wrong, _ := new(big.Int).SetString("19", 10) // 7+11=18, not 19
	expectRejected(t, bn254AddContractSource, "BN254AddVec.runar.ts",
		[]interface{}{wrong}, "verify", []interface{}{a, b})
}

func TestNeg_BN254_FieldMul_WrongResult(t *testing.T) {
	a, _ := new(big.Int).SetString("6", 10)
	b, _ := new(big.Int).SetString("7", 10)
	wrong, _ := new(big.Int).SetString("43", 10) // 6*7=42, not 43
	expectRejected(t, bn254MulContractSource, "BN254MulVec.runar.ts",
		[]interface{}{wrong}, "verify", []interface{}{a, b})
}

func TestNeg_BN254_FieldSub_WrongResult(t *testing.T) {
	a, _ := new(big.Int).SetString("100", 10)
	b, _ := new(big.Int).SetString("30", 10)
	wrong, _ := new(big.Int).SetString("71", 10) // 100-30=70, not 71
	expectRejected(t, bn254SubContractSource, "BN254SubVec.runar.ts",
		[]interface{}{wrong}, "verify", []interface{}{a, b})
}

func TestNeg_BN254_FieldInv_WrongResult(t *testing.T) {
	a, _ := new(big.Int).SetString("2", 10)
	wrong, _ := new(big.Int).SetString("0", 10) // inv(2) != 0
	expectRejected(t, bn254InvContractSource, "BN254InvVec.runar.ts",
		[]interface{}{wrong}, "verify", []interface{}{a})
}

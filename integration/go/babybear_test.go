//go:build integration

package integration

import (
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Baby Bear prime: p = 2013265921
var bbP = big.NewInt(2013265921)

// ---------------------------------------------------------------------------
// Test: bbFieldAdd — (3 + 7) mod p = 10
// ---------------------------------------------------------------------------

const bbFieldAddSource = `
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddTest extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
`

func TestBB_FieldAdd(t *testing.T) {
	compileDeployAndSpendSDK(t, bbFieldAddSource, "BBAddTest.runar.ts",
		[]interface{}{big.NewInt(10)}, "verify", []interface{}{big.NewInt(3), big.NewInt(7)})
}

// ---------------------------------------------------------------------------
// Test: bbFieldAdd — wrap-around (p-1) + 1 = 0
// ---------------------------------------------------------------------------

func TestBB_FieldAdd_WrapAround(t *testing.T) {
	pMinus1 := new(big.Int).Sub(bbP, big.NewInt(1))
	compileDeployAndSpendSDK(t, bbFieldAddSource, "BBAddTest.runar.ts",
		[]interface{}{big.NewInt(0)}, "verify", []interface{}{pMinus1, big.NewInt(1)})
}

// ---------------------------------------------------------------------------
// Test: bbFieldInv — a * inv(a) = 1 (algebraic identity)
// ---------------------------------------------------------------------------

const bbFieldInvIdentitySource = `
import { SmartContract, assert, bbFieldInv, bbFieldMul } from 'runar-lang';

class BBInvIdentity extends SmartContract {
  constructor() { super(); }
  public verify(a: bigint) {
    const inv = bbFieldInv(a);
    assert(bbFieldMul(a, inv) === 1n);
  }
}
`

func TestBB_FieldInv_Identity(t *testing.T) {
	artifact, err := helpers.CompileSourceStringToSDKArtifact(bbFieldInvIdentitySource, "BBInvIdentity.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{})

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

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	txid, _, err := contract.Call("verify", []interface{}{big.NewInt(42)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call verify: %v", err)
	}
	t.Logf("bbFieldInv identity TX confirmed: %s", txid)
}

// ---------------------------------------------------------------------------
// Test: bbFieldAdd — wrong expected value rejected on-chain
// ---------------------------------------------------------------------------

func TestBB_FieldAdd_WrongResult_Rejected(t *testing.T) {
	artifact, err := helpers.CompileSourceStringToSDKArtifact(bbFieldAddSource, "BBAddTest.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Wrong expected: 3+7=10, not 11
	contract := runar.NewRunarContract(artifact, []interface{}{big.NewInt(11)})

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

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	_, _, err = contract.Call("verify", []interface{}{big.NewInt(3), big.NewInt(7)}, provider, signer, nil)
	if err == nil {
		t.Fatalf("expected call with wrong expected to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

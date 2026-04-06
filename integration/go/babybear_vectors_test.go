//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// JSON vector types
// ---------------------------------------------------------------------------

type vectorFile struct {
	Field   string       `json:"field"`
	Prime   uint64       `json:"prime"`
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	Op          string  `json:"op"`
	A           uint64  `json:"a"`
	B           *uint64 `json:"b,omitempty"` // nil for unary ops like inv
	Expected    uint64  `json:"expected"`
	Description string  `json:"description"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func vectorsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "vectors")
}

func loadVectors(t *testing.T, filename string) vectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir(), filename))
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

// ---------------------------------------------------------------------------
// Contract sources — one per operation, compiled once, deployed per vector.
// Each contract takes `expected` as a constructor arg and the operands as
// method params. The contract asserts the result matches expected.
// ---------------------------------------------------------------------------

const bbAddContractSource = `
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
`

const bbSubContractSource = `
import { SmartContract, assert, bbFieldSub } from 'runar-lang';

class BBSubVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldSub(a, b) === this.expected);
  }
}
`

const bbMulContractSource = `
import { SmartContract, assert, bbFieldMul } from 'runar-lang';

class BBMulVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldMul(a, b) === this.expected);
  }
}
`

const bbInvContractSource = `
import { SmartContract, assert, bbFieldInv } from 'runar-lang';

class BBInvVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint) {
    assert(bbFieldInv(a) === this.expected);
  }
}
`

// runBinaryOpVectors compiles a contract once, then for each vector deploys
// with the expected value and calls verify(a, b) on regtest.
func runBinaryOpVectors(t *testing.T, source, fileName string, vf vectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	t.Logf("compiled %s: %d bytes script", fileName, len(artifact.Script)/2)

	for i, vec := range vf.Vectors {
		vec := vec // capture
		t.Run(fmt.Sprintf("%d_%s", i, vec.Description), func(t *testing.T) {
			contract := runar.NewRunarContract(artifact, []interface{}{big.NewInt(int64(vec.Expected))})

			wallet := helpers.NewWallet()
			helpers.RPCCall("importaddress", wallet.Address, "", false)
			_, err := helpers.FundWallet(wallet, 0.5)
			if err != nil {
				t.Fatalf("fund: %v", err)
			}

			provider := helpers.NewRPCProvider()
			signer, errS := helpers.SDKSignerFromWallet(wallet)
			if errS != nil {
				t.Fatalf("signer: %v", errS)
			}

			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			b := big.NewInt(int64(*vec.B))
			txid, _, err := contract.Call("verify", []interface{}{big.NewInt(int64(vec.A)), b}, provider, signer, nil)
			if err != nil {
				t.Fatalf("FAIL: %s — %v", vec.Description, err)
			}
			t.Logf("PASS: %s → tx %s", vec.Description, txid)
		})
	}
}

// runUnaryOpVectors compiles a contract once, then for each vector deploys
// with the expected value and calls verify(a) on regtest.
func runUnaryOpVectors(t *testing.T, source, fileName string, vf vectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	t.Logf("compiled %s: %d bytes script", fileName, len(artifact.Script)/2)

	for i, vec := range vf.Vectors {
		vec := vec // capture
		t.Run(fmt.Sprintf("%d_%s", i, vec.Description), func(t *testing.T) {
			contract := runar.NewRunarContract(artifact, []interface{}{big.NewInt(int64(vec.Expected))})

			wallet := helpers.NewWallet()
			helpers.RPCCall("importaddress", wallet.Address, "", false)
			_, err := helpers.FundWallet(wallet, 0.5)
			if err != nil {
				t.Fatalf("fund: %v", err)
			}

			provider := helpers.NewRPCProvider()
			signer, errS := helpers.SDKSignerFromWallet(wallet)
			if errS != nil {
				t.Fatalf("signer: %v", errS)
			}

			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			txid, _, err := contract.Call("verify", []interface{}{big.NewInt(int64(vec.A))}, provider, signer, nil)
			if err != nil {
				t.Fatalf("FAIL: %s — %v", vec.Description, err)
			}
			t.Logf("PASS: %s → tx %s", vec.Description, txid)
		})
	}
}

// ---------------------------------------------------------------------------
// Test entry points
// ---------------------------------------------------------------------------

func TestBB_Vectors_Add(t *testing.T) {
	vf := loadVectors(t, "babybear_add.json")
	t.Logf("loaded %d addition vectors", len(vf.Vectors))
	runBinaryOpVectors(t, bbAddContractSource, "BBAddVec.runar.ts", vf)
}

func TestBB_Vectors_Sub(t *testing.T) {
	vf := loadVectors(t, "babybear_sub.json")
	t.Logf("loaded %d subtraction vectors", len(vf.Vectors))
	runBinaryOpVectors(t, bbSubContractSource, "BBSubVec.runar.ts", vf)
}

func TestBB_Vectors_Mul(t *testing.T) {
	vf := loadVectors(t, "babybear_mul.json")
	t.Logf("loaded %d multiplication vectors", len(vf.Vectors))
	runBinaryOpVectors(t, bbMulContractSource, "BBMulVec.runar.ts", vf)
}

func TestBB_Vectors_Inv(t *testing.T) {
	vf := loadVectors(t, "babybear_inv.json")
	t.Logf("loaded %d inverse vectors", len(vf.Vectors))
	runUnaryOpVectors(t, bbInvContractSource, "BBInvVec.runar.ts", vf)
}

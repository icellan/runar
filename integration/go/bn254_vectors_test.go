//go:build integration

package integration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// JSON vector types for BN254 field arithmetic
// ---------------------------------------------------------------------------

type bn254FpVectorFile struct {
	Field   string       `json:"field"`
	Prime   string       `json:"prime"`
	Vectors []bn254FpVec `json:"vectors"`
}

type bn254FpVec struct {
	Op       string  `json:"op"`
	A        string  `json:"a"`
	B        *string `json:"b,omitempty"`
	Expected string  `json:"expected"`
	Desc     string  `json:"description"`
}

func loadBN254FpVectors(t *testing.T, filename string) bn254FpVectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir(), filename))
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf bn254FpVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("no vectors loaded from %s", filename)
	}
	return vf
}

func hexToBig(h string) *big.Int {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("hexToBig: invalid hex: " + h)
	}
	return new(big.Int).SetBytes(b)
}

// ---------------------------------------------------------------------------
// Contract sources — BN254 field arithmetic
// ---------------------------------------------------------------------------

const bn254AddContractSource = `
import { SmartContract, assert, bn254FieldAdd } from 'runar-lang';

class BN254AddVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bn254FieldAdd(a, b) === this.expected);
  }
}
`

const bn254SubContractSource = `
import { SmartContract, assert, bn254FieldSub } from 'runar-lang';

class BN254SubVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bn254FieldSub(a, b) === this.expected);
  }
}
`

const bn254MulContractSource = `
import { SmartContract, assert, bn254FieldMul } from 'runar-lang';

class BN254MulVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bn254FieldMul(a, b) === this.expected);
  }
}
`

const bn254InvContractSource = `
import { SmartContract, assert, bn254FieldInv } from 'runar-lang';

class BN254InvVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint) {
    assert(bn254FieldInv(a) === this.expected);
  }
}
`

// ---------------------------------------------------------------------------
// BN254 binary op vector runner
// ---------------------------------------------------------------------------

// runBN254BinaryOpVectors runs vectors that have both A and B fields (add/sub/mul).
// Callers must ensure the vector file contains binary-op vectors (B is non-nil).
func runBN254BinaryOpVectors(t *testing.T, source, fileName string, vf bn254FpVectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	t.Logf("compiled %s: %d bytes script", fileName, len(artifact.Script)/2)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 5.0)
	if err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, errS := helpers.SDKSignerFromWallet(wallet)
	if errS != nil {
		t.Fatalf("signer: %v", errS)
	}

	// Test a subset for speed (first 10 + every 30th)
	for i, vec := range vf.Vectors {
		if i >= 10 && i%30 != 0 {
			continue
		}
		vec := vec
		t.Run(fmt.Sprintf("%d_%s", i, vec.Desc), func(t *testing.T) {
			expected := hexToBig(vec.Expected)
			contract := runar.NewRunarContract(artifact, []interface{}{expected})

			_, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			a := hexToBig(vec.A)
			b := hexToBig(*vec.B)
			txid, _, err := contract.Call("verify", []interface{}{a, b}, provider, signer, nil)
			if err != nil {
				t.Fatalf("FAIL: %s — %v", vec.Desc, err)
			}
			t.Logf("PASS: %s → tx %s", vec.Desc, txid)
		})
	}
}

func runBN254UnaryOpVectors(t *testing.T, source, fileName string, vf bn254FpVectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	t.Logf("compiled %s: %d bytes script", fileName, len(artifact.Script)/2)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 5.0)
	if err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, errS := helpers.SDKSignerFromWallet(wallet)
	if errS != nil {
		t.Fatalf("signer: %v", errS)
	}

	for i, vec := range vf.Vectors {
		if i >= 10 && i%30 != 0 {
			continue
		}
		vec := vec
		t.Run(fmt.Sprintf("%d_%s", i, vec.Desc), func(t *testing.T) {
			expected := hexToBig(vec.Expected)
			contract := runar.NewRunarContract(artifact, []interface{}{expected})

			_, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			a := hexToBig(vec.A)
			txid, _, err := contract.Call("verify", []interface{}{a}, provider, signer, nil)
			if err != nil {
				t.Fatalf("FAIL: %s — %v", vec.Desc, err)
			}
			t.Logf("PASS: %s → tx %s", vec.Desc, txid)
		})
	}
}

// ---------------------------------------------------------------------------
// Test entry points — BN254 field arithmetic
// ---------------------------------------------------------------------------

func TestBN254_Vectors_Add(t *testing.T) {
	vf := loadBN254FpVectors(t, "bn254_fp_add.json")
	t.Logf("loaded %d addition vectors", len(vf.Vectors))
	runBN254BinaryOpVectors(t, bn254AddContractSource, "BN254AddVec.runar.ts", vf)
}

func TestBN254_Vectors_Sub(t *testing.T) {
	vf := loadBN254FpVectors(t, "bn254_fp_sub.json")
	t.Logf("loaded %d subtraction vectors", len(vf.Vectors))
	runBN254BinaryOpVectors(t, bn254SubContractSource, "BN254SubVec.runar.ts", vf)
}

func TestBN254_Vectors_Mul(t *testing.T) {
	vf := loadBN254FpVectors(t, "bn254_fp_mul.json")
	t.Logf("loaded %d multiplication vectors", len(vf.Vectors))
	runBN254BinaryOpVectors(t, bn254MulContractSource, "BN254MulVec.runar.ts", vf)
}

func TestBN254_Vectors_Inv(t *testing.T) {
	vf := loadBN254FpVectors(t, "bn254_fp_inv.json")
	t.Logf("loaded %d inverse vectors", len(vf.Vectors))
	runBN254UnaryOpVectors(t, bn254InvContractSource, "BN254InvVec.runar.ts", vf)
}

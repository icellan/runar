//go:build integration

package integration

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// JSON vector types for ext4
// ---------------------------------------------------------------------------

type ext4VectorFile struct {
	Field          string           `json:"field"`
	Prime          uint64           `json:"prime"`
	ExtensionDeg   uint32           `json:"extension_degree"`
	Vectors        []ext4TestVector `json:"vectors"`
}

type ext4TestVector struct {
	Op          string     `json:"op"`
	A           [4]uint64  `json:"a"`
	B           *[4]uint64 `json:"b,omitempty"`
	Expected    [4]uint64  `json:"expected"`
	Description string     `json:"description"`
}

func loadExt4Vectors(t *testing.T, filename string) ext4VectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir(), filename))
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf ext4VectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

// ---------------------------------------------------------------------------
// Contract sources — KoalaBear field arithmetic
// ---------------------------------------------------------------------------

const kbAddContractSource = `
import { SmartContract, assert, kbFieldAdd } from 'runar-lang';

class KBAddVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(kbFieldAdd(a, b) === this.expected);
  }
}
`

const kbSubContractSource = `
import { SmartContract, assert, kbFieldSub } from 'runar-lang';

class KBSubVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(kbFieldSub(a, b) === this.expected);
  }
}
`

const kbMulContractSource = `
import { SmartContract, assert, kbFieldMul } from 'runar-lang';

class KBMulVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(kbFieldMul(a, b) === this.expected);
  }
}
`

const kbInvContractSource = `
import { SmartContract, assert, kbFieldInv } from 'runar-lang';

class KBInvVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint) {
    assert(kbFieldInv(a) === this.expected);
  }
}
`

// ---------------------------------------------------------------------------
// Contract sources — KoalaBear ext4
// ---------------------------------------------------------------------------

const kbExt4MulContractSource = `
import { SmartContract, assert, kbExt4Mul0, kbExt4Mul1, kbExt4Mul2, kbExt4Mul3 } from 'runar-lang';

class KBExt4MulVec extends SmartContract {
  readonly e0: bigint;
  readonly e1: bigint;
  readonly e2: bigint;
  readonly e3: bigint;
  constructor(e0: bigint, e1: bigint, e2: bigint, e3: bigint) {
    super(e0, e1, e2, e3);
    this.e0 = e0; this.e1 = e1; this.e2 = e2; this.e3 = e3;
  }
  public verify(a0: bigint, a1: bigint, a2: bigint, a3: bigint,
                b0: bigint, b1: bigint, b2: bigint, b3: bigint) {
    assert(kbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3) === this.e0);
    assert(kbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3) === this.e1);
    assert(kbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3) === this.e2);
    assert(kbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3) === this.e3);
  }
}
`

const kbExt4InvContractSource = `
import { SmartContract, assert, kbExt4Inv0, kbExt4Inv1, kbExt4Inv2, kbExt4Inv3 } from 'runar-lang';

class KBExt4InvVec extends SmartContract {
  readonly e0: bigint;
  readonly e1: bigint;
  readonly e2: bigint;
  readonly e3: bigint;
  constructor(e0: bigint, e1: bigint, e2: bigint, e3: bigint) {
    super(e0, e1, e2, e3);
    this.e0 = e0; this.e1 = e1; this.e2 = e2; this.e3 = e3;
  }
  public verify(a0: bigint, a1: bigint, a2: bigint, a3: bigint) {
    assert(kbExt4Inv0(a0, a1, a2, a3) === this.e0);
    assert(kbExt4Inv1(a0, a1, a2, a3) === this.e1);
    assert(kbExt4Inv2(a0, a1, a2, a3) === this.e2);
    assert(kbExt4Inv3(a0, a1, a2, a3) === this.e3);
  }
}
`

// ---------------------------------------------------------------------------
// Ext4 test runners
// ---------------------------------------------------------------------------

// NOTE: uint64→int64 casts below are safe because the KoalaBear prime (2^31 - 2^24 + 1)
// fits comfortably in int64. All field elements are in [0, p-1] ⊂ [0, 2^31).
func runExt4MulVectors(t *testing.T, source, fileName string, vf ext4VectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}

	funded, err := helpers.SplitFundParallel(len(vf.Vectors), 100000)
	if err != nil {
		t.Fatalf("split fund: %v", err)
	}

	sem := make(chan struct{}, vectorParallelism())

	for i, vec := range vf.Vectors {
		i, vec := i, vec
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			fw := funded[i]
			provider := helpers.NewBatchRPCProvider()
			defer provider.MineAll()
			signer, err := helpers.SDKSignerFromWallet(fw.Wallet)
			if err != nil {
				t.Fatalf("signer: %v", err)
			}

			contract := runar.NewRunarContract(artifact, []interface{}{
				big.NewInt(int64(vec.Expected[0])),
				big.NewInt(int64(vec.Expected[1])),
				big.NewInt(int64(vec.Expected[2])),
				big.NewInt(int64(vec.Expected[3])),
			})

			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			b := vec.B
			_, _, err = contract.Call("verify", []interface{}{
				big.NewInt(int64(vec.A[0])), big.NewInt(int64(vec.A[1])),
				big.NewInt(int64(vec.A[2])), big.NewInt(int64(vec.A[3])),
				big.NewInt(int64(b[0])), big.NewInt(int64(b[1])),
				big.NewInt(int64(b[2])), big.NewInt(int64(b[3])),
			}, provider, signer, nil)
			if err != nil {
				t.Fatalf("a=%v, b=%v, expected=%v: %v", vec.A, b, vec.Expected, err)
			}
		})
	}

	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine: %v", err)
	}
}

func runExt4InvVectors(t *testing.T, source, fileName string, vf ext4VectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}

	funded, err := helpers.SplitFundParallel(len(vf.Vectors), 100000)
	if err != nil {
		t.Fatalf("split fund: %v", err)
	}

	sem := make(chan struct{}, vectorParallelism())

	for i, vec := range vf.Vectors {
		i, vec := i, vec
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			fw := funded[i]
			provider := helpers.NewBatchRPCProvider()
			defer provider.MineAll()
			signer, err := helpers.SDKSignerFromWallet(fw.Wallet)
			if err != nil {
				t.Fatalf("signer: %v", err)
			}

			contract := runar.NewRunarContract(artifact, []interface{}{
				big.NewInt(int64(vec.Expected[0])),
				big.NewInt(int64(vec.Expected[1])),
				big.NewInt(int64(vec.Expected[2])),
				big.NewInt(int64(vec.Expected[3])),
			})

			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			_, _, err = contract.Call("verify", []interface{}{
				big.NewInt(int64(vec.A[0])), big.NewInt(int64(vec.A[1])),
				big.NewInt(int64(vec.A[2])), big.NewInt(int64(vec.A[3])),
			}, provider, signer, nil)
			if err != nil {
				t.Fatalf("a=%v, expected=%v: %v", vec.A, vec.Expected, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test entry points — KoalaBear base field
// ---------------------------------------------------------------------------

func TestKB_Vectors_Add(t *testing.T) {
	vf := loadVectors(t, "koalabear_add.json")
	t.Logf("loaded %d addition vectors", len(vf.Vectors))
	runBinaryOpVectors(t, kbAddContractSource, "KBAddVec.runar.ts", vf)
}

func TestKB_Vectors_Sub(t *testing.T) {
	vf := loadVectors(t, "koalabear_sub.json")
	t.Logf("loaded %d subtraction vectors", len(vf.Vectors))
	runBinaryOpVectors(t, kbSubContractSource, "KBSubVec.runar.ts", vf)
}

func TestKB_Vectors_Mul(t *testing.T) {
	vf := loadVectors(t, "koalabear_mul.json")
	t.Logf("loaded %d multiplication vectors", len(vf.Vectors))
	runBinaryOpVectors(t, kbMulContractSource, "KBMulVec.runar.ts", vf)
}

func TestKB_Vectors_Inv(t *testing.T) {
	vf := loadVectors(t, "koalabear_inv.json")
	t.Logf("loaded %d inverse vectors", len(vf.Vectors))
	runUnaryOpVectors(t, kbInvContractSource, "KBInvVec.runar.ts", vf)
}

// ---------------------------------------------------------------------------
// Test entry points — KoalaBear ext4
// ---------------------------------------------------------------------------

func TestKB_Vectors_Ext4Mul(t *testing.T) {
	vf := loadExt4Vectors(t, "koalabear_ext4_mul.json")
	t.Logf("loaded %d ext4 multiplication vectors", len(vf.Vectors))
	runExt4MulVectors(t, kbExt4MulContractSource, "KBExt4MulVec.runar.ts", vf)
}

func TestKB_Vectors_Ext4Inv(t *testing.T) {
	vf := loadExt4Vectors(t, "koalabear_ext4_inv.json")
	t.Logf("loaded %d ext4 inverse vectors", len(vf.Vectors))
	runExt4InvVectors(t, kbExt4InvContractSource, "KBExt4InvVec.runar.ts", vf)
}

//go:build integration

package integration

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// selectRepresentative picks a small subset of vectors that cover the
// important cases: edge cases (wrap-around, identity, zero, p-1), one small
// value, one power-of-2, and up to 5 random values. Full vector coverage
// runs in codegen/script_correctness_test.go via go-sdk interpreter.
func selectRepresentative(vecs []testVector) []testVector {
	var selected []testVector
	seen := map[string]bool{}

	add := func(v testVector) {
		if !seen[v.Description] {
			seen[v.Description] = true
			selected = append(selected, v)
		}
	}

	// Edge cases — test modular reduction
	for _, v := range vecs {
		d := v.Description
		if strings.Contains(d, "wrap") || strings.Contains(d, "identity") ||
			strings.Contains(d, "p-1") || strings.Contains(d, "p-2") ||
			strings.Contains(d, "underflow") || strings.Contains(d, "(-1)") ||
			d == "0 + 0 = 0" || d == "0 - 0 = 0" || d == "0 * 0 = 0" ||
			strings.Contains(d, "inv(1)") || strings.Contains(d, "inv(-1)") {
			add(v)
		}
	}

	// One small value
	for _, v := range vecs {
		if !strings.Contains(v.Description, "random") && !strings.Contains(v.Description, "2^") && !seen[v.Description] {
			add(v)
			break
		}
	}

	// One power-of-2
	for _, v := range vecs {
		if strings.Contains(v.Description, "2^") && !seen[v.Description] {
			add(v)
			break
		}
	}

	// Up to 5 random
	randomCount := 0
	for _, v := range vecs {
		if strings.Contains(v.Description, "random") && randomCount < 5 {
			add(v)
			randomCount++
		}
	}

	return selected
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

// vectorParallelism returns max concurrent vector tests. Default 10, override
// with TEST_PARALLEL env var.
func vectorParallelism() int {
	if s := os.Getenv("TEST_PARALLEL"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 10
}

// runBinaryOpVectors compiles contract once, creates per-vector wallets with
// pre-funded UTXOs, runs vectors in parallel (bounded concurrency).
func runBinaryOpVectors(t *testing.T, source, fileName string, vf vectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}

	subset := selectRepresentative(vf.Vectors)

	funded, err := helpers.SplitFundParallel(len(subset), 100000)
	if err != nil {
		t.Fatalf("split fund: %v", err)
	}

	sem := make(chan struct{}, vectorParallelism())

	for i, vec := range subset {
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

			contract := runar.NewRunarContract(artifact, []interface{}{big.NewInt(int64(vec.Expected))})
			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			b := big.NewInt(int64(*vec.B))
			_, _, err = contract.Call("verify", []interface{}{big.NewInt(int64(vec.A)), b}, provider, signer, nil)
			if err != nil {
				t.Fatalf("a=%d, b=%d, expected=%d: %v", vec.A, *vec.B, vec.Expected, err)
			}
		})
	}
}

// runUnaryOpVectors — same bounded-parallel pattern for single-operand operations.
func runUnaryOpVectors(t *testing.T, source, fileName string, vf vectorFile) {
	t.Helper()

	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}

	subset := selectRepresentative(vf.Vectors)

	funded, err := helpers.SplitFundParallel(len(subset), 100000)
	if err != nil {
		t.Fatalf("split fund: %v", err)
	}

	sem := make(chan struct{}, vectorParallelism())

	for i, vec := range subset {
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

			contract := runar.NewRunarContract(artifact, []interface{}{big.NewInt(int64(vec.Expected))})
			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			_, _, err = contract.Call("verify", []interface{}{big.NewInt(int64(vec.A))}, provider, signer, nil)
			if err != nil {
				t.Fatalf("a=%d, expected=%d: %v", vec.A, vec.Expected, err)
			}
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

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
// JSON vector types (reuses vectorsDir() from babybear_vectors_test.go)
// ---------------------------------------------------------------------------

type merkleVectorFile struct {
	Hash    string         `json:"hash"`
	Vectors []merkleVector `json:"vectors"`
}

type merkleVector struct {
	TreeSize    int    `json:"tree_size"`
	Depth       int    `json:"depth"`
	LeafIndex   int    `json:"leaf_index"`
	Leaf        string `json:"leaf"`
	Proof       string `json:"proof"`
	Root        string `json:"root"`
	Expected    string `json:"expected"`
	Description string `json:"description"`
}

func merkleVectorsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "vectors")
}

func loadMerkleVectors(t *testing.T, filename string) merkleVectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(merkleVectorsDir(), filename))
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf merkleVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

// ---------------------------------------------------------------------------
// Contract source — parameterized by depth (compile-time constant)
// ---------------------------------------------------------------------------

func merkleAcceptSource(depth int) string {
	return fmt.Sprintf(`
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class MerkleAccept%d extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) { super(expectedRoot); this.expectedRoot = expectedRoot; }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, %dn);
    assert(root === this.expectedRoot);
  }
}
`, depth, depth)
}

// ---------------------------------------------------------------------------
// Test entry points
// ---------------------------------------------------------------------------

func TestMerkle_Vectors_Inclusion(t *testing.T) {
	vf := loadMerkleVectors(t, "merkle_inclusion.json")
	t.Logf("loaded %d inclusion vectors", len(vf.Vectors))

	// Group by depth since each depth needs a separate compiled contract
	byDepth := map[int][]merkleVector{}
	for _, v := range vf.Vectors {
		byDepth[v.Depth] = append(byDepth[v.Depth], v)
	}

	for depth, vectors := range byDepth {
		source := merkleAcceptSource(depth)
		fileName := fmt.Sprintf("MerkleAccept%d.runar.ts", depth)

		artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
		if err != nil {
			t.Fatalf("compile depth=%d: %v", depth, err)
		}
		t.Logf("compiled depth=%d: %d bytes script", depth, len(artifact.Script)/2)

		for i, vec := range vectors {
			vec := vec
			t.Run(fmt.Sprintf("d%d_%d_%s", depth, i, vec.Description), func(t *testing.T) {
				contract := runar.NewRunarContract(artifact, []interface{}{runar.ByteString(vec.Root)})

				wallet := helpers.NewWallet()
				helpers.RPCCall("importaddress", wallet.Address, "", false)
				_, err := helpers.FundWallet(wallet, 0.5)
				if err != nil {
					t.Fatalf("fund: %v", err)
				}

				provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
				signer, errS := helpers.SDKSignerFromWallet(wallet)
				if errS != nil {
					t.Fatalf("signer: %v", errS)
				}

				_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000})
				if err != nil {
					t.Fatalf("deploy: %v", err)
				}

				txid, _, err := contract.Call("verify", []interface{}{
					runar.ByteString(vec.Leaf),
					runar.ByteString(vec.Proof),
					big.NewInt(int64(vec.LeafIndex)),
				}, provider, signer, nil)
				if err != nil {
					t.Fatalf("FAIL: %v", err)
				}
				t.Logf("PASS: %s → tx %s", vec.Description, txid)
			})
		}
	}
}

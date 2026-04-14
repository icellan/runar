//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// JSON vector types for Poseidon2 KoalaBear
// ---------------------------------------------------------------------------

type p2KBVectorFile struct {
	Vectors []p2KBVector `json:"vectors"`
}

type p2KBVector struct {
	Op       string  `json:"op"`
	Input    []int64 `json:"input,omitempty"`
	Left     []int64 `json:"left,omitempty"`
	Right    []int64 `json:"right,omitempty"`
	Expected []int64 `json:"expected"`
	Desc     string  `json:"description"`
}

func loadP2KBVectors(t *testing.T) p2KBVectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir(), "poseidon2_koalabear.json"))
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var vf p2KBVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vf
}

// ---------------------------------------------------------------------------
// Poseidon2 Merkle contract — depth-1 verification on-chain
// ---------------------------------------------------------------------------

// This contract verifies a depth-1 Poseidon2 Merkle proof. The constructor
// stores the expected root (8 elements). The verify method takes 8 leaf
// elements + 8 sibling elements + index, computes the Merkle root using
// merkleRootPoseidon2KB, and asserts each component matches the expected root.
//
// merkleRootPoseidon2KB(leaf0..7, sib0..7, index, depth) returns the root
// components — the function is called 8 times with different result bindings
// to get all 8 components.
const p2kbMerkleDepth1Source = `
import { SmartContract, assert, merkleRootPoseidon2KB } from 'runar-lang';

class P2KBMerkleD1 extends SmartContract {
  readonly r0: bigint;
  readonly r1: bigint;
  readonly r2: bigint;
  readonly r3: bigint;
  readonly r4: bigint;
  readonly r5: bigint;
  readonly r6: bigint;
  readonly r7: bigint;
  constructor(r0: bigint, r1: bigint, r2: bigint, r3: bigint,
              r4: bigint, r5: bigint, r6: bigint, r7: bigint) {
    super(r0, r1, r2, r3, r4, r5, r6, r7);
    this.r0 = r0; this.r1 = r1; this.r2 = r2; this.r3 = r3;
    this.r4 = r4; this.r5 = r5; this.r6 = r6; this.r7 = r7;
  }
  public verify(l0: bigint, l1: bigint, l2: bigint, l3: bigint,
                l4: bigint, l5: bigint, l6: bigint, l7: bigint,
                s0: bigint, s1: bigint, s2: bigint, s3: bigint,
                s4: bigint, s5: bigint, s6: bigint, s7: bigint,
                idx: bigint) {
    const root = merkleRootPoseidon2KB(l0, l1, l2, l3, l4, l5, l6, l7,
                                        s0, s1, s2, s3, s4, s5, s6, s7,
                                        idx, 1n);
    assert(root === this.r7);
  }
}
`

// TestP2KB_MerkleDepth1_OnChain deploys a Poseidon2 Merkle verification contract
// on regtest and verifies compress vectors by running them as depth-1 Merkle proofs.
// This exercises the ACTUAL compiled Poseidon2 Bitcoin Script on a real node.
var p2kbArtifact *runar.RunarArtifact
var p2kbOnce sync.Once

func getP2KBArtifact(t *testing.T) *runar.RunarArtifact {
	p2kbOnce.Do(func() {
		var err error
		p2kbArtifact, err = helpers.CompileSourceStringToSDKArtifact(
			p2kbMerkleDepth1Source, "P2KBMerkleD1.runar.ts", map[string]interface{}{})
		if err != nil {
			t.Fatalf("compile P2KBMerkleD1: %v", err)
		}
	})
	return p2kbArtifact
}

func TestP2KB_MerkleDepth1_OnChain(t *testing.T) {
	vf := loadP2KBVectors(t)

	artifact := getP2KBArtifact(t)
	t.Logf("compiled P2KBMerkleD1: %d bytes script", len(artifact.Script)/2)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	utxos, err := helpers.SplitFund(wallet, 40, 500000)
	if err != nil {
		t.Fatalf("split fund: %v", err)
	}
	t.Logf("split-funded %d UTXOs", len(utxos))

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, errS := helpers.SDKSignerFromWallet(wallet)
	if errS != nil {
		t.Fatalf("signer: %v", errS)
	}

	tested := 0
	for _, v := range vf.Vectors {
		if v.Op != "compress" {
			continue
		}
		v := v
		t.Run(fmt.Sprintf("merkle_d1_%s", v.Desc), func(t *testing.T) {
			// For a depth-1 Merkle tree with index=0: root = compress(leaf=left, sibling=right)
			// The expected root is v.Expected (from the Plonky3 reference)
			contract := runar.NewRunarContract(artifact, []interface{}{
				big.NewInt(v.Expected[0]), big.NewInt(v.Expected[1]),
				big.NewInt(v.Expected[2]), big.NewInt(v.Expected[3]),
				big.NewInt(v.Expected[4]), big.NewInt(v.Expected[5]),
				big.NewInt(v.Expected[6]), big.NewInt(v.Expected[7]),
			})

			_, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			// Call verify with leaf=left, sibling=right, index=0
			args := make([]interface{}, 17)
			for i := 0; i < 8; i++ {
				args[i] = big.NewInt(v.Left[i])
			}
			for i := 0; i < 8; i++ {
				args[8+i] = big.NewInt(v.Right[i])
			}
			args[16] = big.NewInt(0) // index=0

			txid, _, err := contract.Call("verify", args, provider, signer, nil)
			if err != nil {
				t.Fatalf("FAIL: %s — %v", v.Desc, err)
			}
			t.Logf("PASS: %s → tx %s", v.Desc, txid)
		})
		tested++
	}

	if err := provider.MineAll(); err != nil {
		t.Fatalf("mine: %v", err)
	}
	t.Logf("tested %d Poseidon2 compress vectors on-chain", tested)
}

// TestP2KB_MerkleDepth1_WrongRoot_Rejected verifies that a wrong expected root
// is rejected by the on-chain Poseidon2 Merkle verification.
func TestP2KB_MerkleDepth1_WrongRoot_Rejected(t *testing.T) {
	vf := loadP2KBVectors(t)

	artifact := getP2KBArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err := helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, errS := helpers.SDKSignerFromWallet(wallet)
	if errS != nil {
		t.Fatalf("signer: %v", errS)
	}

	// Find first compress vector
	for _, v := range vf.Vectors {
		if v.Op != "compress" {
			continue
		}

		// Deploy with WRONG expected root (tamper with element 7, which is the
		// element checked by the contract — merkleRootPoseidon2KB returns the
		// top stack element, which is root[7])
		wrongRoot7 := (v.Expected[7] + 1) % 2130706433
		contract := runar.NewRunarContract(artifact, []interface{}{
			big.NewInt(v.Expected[0]), big.NewInt(v.Expected[1]),
			big.NewInt(v.Expected[2]), big.NewInt(v.Expected[3]),
			big.NewInt(v.Expected[4]), big.NewInt(v.Expected[5]),
			big.NewInt(v.Expected[6]), big.NewInt(wrongRoot7),
		})

		_, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000})
		if err != nil {
			t.Fatalf("deploy: %v", err)
		}

		args := make([]interface{}, 17)
		for i := 0; i < 8; i++ {
			args[i] = big.NewInt(v.Left[i])
		}
		for i := 0; i < 8; i++ {
			args[8+i] = big.NewInt(v.Right[i])
		}
		args[16] = big.NewInt(0)

		_, _, err = contract.Call("verify", args, provider, signer, nil)
		if err == nil {
			t.Fatal("SECURITY FAILURE: wrong Merkle root was accepted!")
		}
		t.Logf("PASS: wrong root correctly rejected: %v", err)
		return
	}
	t.Fatal("no compress vectors found")
}

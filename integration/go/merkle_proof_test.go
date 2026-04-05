//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Merkle tree helpers
// ---------------------------------------------------------------------------

func sha256Hex(hexStr string) string {
	data, _ := hex.DecodeString(hexStr)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type merkleTree struct {
	root   string
	leaves []string
	layers [][]string
}

func buildSha256Tree(leaves []string) *merkleTree {
	level := make([]string, len(leaves))
	copy(level, leaves)
	layers := [][]string{level}
	for len(level) > 1 {
		next := make([]string, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, sha256Hex(level[i]+level[i+1]))
		}
		level = next
		layers = append(layers, level)
	}
	return &merkleTree{root: level[0], leaves: leaves, layers: layers}
}

func (t *merkleTree) getProof(index int) (proof string, leaf string) {
	siblings := ""
	idx := index
	for d := 0; d < len(t.layers)-1; d++ {
		siblings += t.layers[d][idx^1]
		idx >>= 1
	}
	return siblings, t.leaves[index]
}

// Build a depth-4 SHA-256 tree (16 leaves)
func buildTestTree() *merkleTree {
	leaves := make([]string, 16)
	for i := 0; i < 16; i++ {
		leaves[i] = sha256Hex(hex.EncodeToString([]byte{byte(i)}))
	}
	return buildSha256Tree(leaves)
}

// ---------------------------------------------------------------------------
// Contract source
// ---------------------------------------------------------------------------

const merkleSha256Source = `
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class MerkleSha256Test extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }
}
`

// ---------------------------------------------------------------------------
// Test: merkleRootSha256 — verify leaf at index 0 (leftmost)
// ---------------------------------------------------------------------------

func TestMerkle_Sha256_LeafIndex0(t *testing.T) {
	tree := buildTestTree()
	proof, leaf := tree.getProof(0)

	artifact, err := helpers.CompileSourceStringToSDKArtifact(merkleSha256Source, "MerkleSha256Test.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{tree.root})

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

	txid, _, err := contract.Call("verify", []interface{}{leaf, proof, big.NewInt(0)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call verify: %v", err)
	}
	t.Logf("merkleRootSha256 leaf 0 TX confirmed: %s", txid)
}

// ---------------------------------------------------------------------------
// Test: merkleRootSha256 — verify leaf at index 7 (middle)
// ---------------------------------------------------------------------------

func TestMerkle_Sha256_LeafIndex7(t *testing.T) {
	tree := buildTestTree()
	proof, leaf := tree.getProof(7)

	artifact, err := helpers.CompileSourceStringToSDKArtifact(merkleSha256Source, "MerkleSha256Test.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{tree.root})

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

	txid, _, err := contract.Call("verify", []interface{}{leaf, proof, big.NewInt(7)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call verify: %v", err)
	}
	t.Logf("merkleRootSha256 leaf 7 TX confirmed: %s", txid)
}

// ---------------------------------------------------------------------------
// Test: merkleRootSha256 — wrong leaf rejected on-chain
// ---------------------------------------------------------------------------

func TestMerkle_Sha256_WrongLeaf_Rejected(t *testing.T) {
	tree := buildTestTree()
	proof, _ := tree.getProof(0)
	wrongLeaf := sha256Hex("ff")

	artifact, err := helpers.CompileSourceStringToSDKArtifact(merkleSha256Source, "MerkleSha256Test.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{tree.root})

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

	_, _, err = contract.Call("verify", []interface{}{wrongLeaf, proof, big.NewInt(0)}, provider, signer, nil)
	if err == nil {
		t.Fatalf("expected call with wrong leaf to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

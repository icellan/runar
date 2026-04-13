//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Helpers — hex-encoded values for the SDK (on-chain convention)
// ---------------------------------------------------------------------------

const bbPrime = 2013265921

func bbMulField(a, b int64) int64 {
	return (a * b) % bbPrime
}

func hexSha256(hexData string) string {
	data, _ := hex.DecodeString(hexData)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hexHash256(hexData string) string {
	return hexSha256(hexSha256(hexData))
}

func hexStateRoot(n int) string {
	return hexSha256(fmt.Sprintf("%02x", n))
}

func hexZeros32() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

type hexMerkleTree struct {
	root   string
	layers [][]string
	leaves []string
}

func buildHexMerkleTree(leaves []string) *hexMerkleTree {
	level := make([]string, len(leaves))
	copy(level, leaves)
	layers := [][]string{level}

	for len(level) > 1 {
		next := make([]string, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hexSha256(level[i]+level[i+1]))
		}
		level = next
		layers = append(layers, level)
	}
	return &hexMerkleTree{root: level[0], layers: layers, leaves: leaves}
}

func (t *hexMerkleTree) getProof(index int) (leaf, proof string) {
	var siblings []string
	idx := index
	for d := 0; d < len(t.layers)-1; d++ {
		siblings = append(siblings, t.layers[d][idx^1])
		idx >>= 1
	}
	p := ""
	for _, s := range siblings {
		p += s
	}
	return t.leaves[index], p
}

// Fixed test tree (computed once, reused)
var scTestTree *hexMerkleTree

func init() {
	leaves := make([]string, 16)
	for i := 0; i < 16; i++ {
		leaves[i] = hexSha256(fmt.Sprintf("%02x", i))
	}
	scTestTree = buildHexMerkleTree(leaves)
}

const scLeafIdx = 3

// ---------------------------------------------------------------------------
// Deploy helper
// ---------------------------------------------------------------------------

func deployStateCovenant(t *testing.T) (*runar.RunarContract, *helpers.Wallet) {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/state-covenant/StateCovenant.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("StateCovenant script: %d bytes (%d KB)", len(artifact.Script)/2, len(artifact.Script)/2/1024)

	// Constructor: (stateRoot, blockNumber, verifyingKeyHash)
	contract := runar.NewRunarContract(artifact, []interface{}{
		hexZeros32(),       // genesis state root
		int64(0),           // genesis block number
		scTestTree.root,    // verifying key hash = Merkle tree root
	})

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

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", txid)

	return contract, wallet
}

// buildCallArgs builds the arguments for a single advanceState call.
func buildCallArgs(preStateRoot string, newBlockNumber int64) []interface{} {
	newStateRoot := hexStateRoot(int(newBlockNumber))
	batchDataHash := hexHash256(preStateRoot + newStateRoot)
	proofA := int64(1000000)
	proofB := int64(2000000)
	proofC := bbMulField(proofA, proofB)
	leaf, proof := scTestTree.getProof(scLeafIdx)

	return []interface{}{
		newStateRoot,             // newStateRoot
		int64(newBlockNumber),    // newBlockNumber
		batchDataHash,            // batchDataHash
		preStateRoot,             // preStateRoot
		proofA,                   // proofFieldA
		proofB,                   // proofFieldB
		proofC,                   // proofFieldC
		leaf,                     // merkleLeaf
		proof,                    // merkleProof
		int64(scLeafIdx),         // merkleIndex
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestStateCovenant_Deploy(t *testing.T) {
	contract, _ := deployStateCovenant(t)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatal("no UTXO after deploy")
	}
}

func TestStateCovenant_AdvanceState(t *testing.T) {
	contract, wallet := deployStateCovenant(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	args := buildCallArgs(hexZeros32(), 1)
	txid, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err != nil {
		t.Fatalf("advanceState: %v", err)
	}
	t.Logf("advance 0->1 TX: %s", txid)
}

func TestStateCovenant_ChainAdvances(t *testing.T) {
	contract, wallet := deployStateCovenant(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pre := hexZeros32()
	for block := int64(1); block <= 3; block++ {
		args := buildCallArgs(pre, block)
		txid, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		t.Logf("advance to block %d TX: %s", block, txid)
		pre = hexStateRoot(int(block))
	}
	t.Log("chain: 0->1->2->3 succeeded")
}

func TestStateCovenant_WrongPreStateRoot_Rejected(t *testing.T) {
	contract, wallet := deployStateCovenant(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	args := buildCallArgs(hexZeros32(), 1)
	// Replace preStateRoot (index 3) with a wrong value
	args[3] = "ff" + hexZeros32()[2:]

	_, _, err = contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong pre-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestStateCovenant_InvalidBlockNumber_Rejected(t *testing.T) {
	contract, wallet := deployStateCovenant(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// First advance to block 1
	args1 := buildCallArgs(hexZeros32(), 1)
	_, _, err = contract.Call("advanceState", args1, provider, signer, nil)
	if err != nil {
		t.Fatalf("first advance: %v", err)
	}

	// Try to advance to block 0 (not increasing)
	pre := hexStateRoot(1)
	args2 := buildCallArgs(pre, 0)
	args2[1] = int64(0) // force block number 0

	_, _, err = contract.Call("advanceState", args2, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for non-increasing block number")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestStateCovenant_InvalidBabyBearProof_Rejected(t *testing.T) {
	contract, wallet := deployStateCovenant(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	args := buildCallArgs(hexZeros32(), 1)
	args[6] = int64(99999) // wrong proofFieldC

	_, _, err = contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for invalid Baby Bear proof")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestStateCovenant_InvalidMerkleProof_Rejected(t *testing.T) {
	contract, wallet := deployStateCovenant(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	args := buildCallArgs(hexZeros32(), 1)
	args[7] = "aa" + hexZeros32()[2:] // wrong merkleLeaf

	_, _, err = contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for invalid Merkle proof")
	}
	t.Logf("correctly rejected: %v", err)
}

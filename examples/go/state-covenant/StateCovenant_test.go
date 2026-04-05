package contract

import (
	"crypto/sha256"
	"fmt"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Helpers — Go mock ByteString is raw bytes (not hex-encoded)
// ---------------------------------------------------------------------------

const bbP = 2013265921

func bbMul(a, b int64) int64 {
	return (a * b) % bbP
}

func rawSha256(data string) string {
	h := sha256.Sum256([]byte(data))
	return string(h[:])
}

func rawHash256(data string) string {
	return rawSha256(rawSha256(data))
}

func stateRootForBlock(n int) string {
	return rawSha256(fmt.Sprintf("%d", n))
}

func zeros32() string {
	return string(make([]byte, 32))
}

// Build a depth-4 SHA-256 Merkle tree (16 leaves) using raw bytes.
type mTree struct {
	root   string
	layers [][]string
	leaves []string
}

func buildTree(leaves []string) *mTree {
	level := make([]string, len(leaves))
	copy(level, leaves)
	layers := [][]string{level}

	for len(level) > 1 {
		next := make([]string, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, rawSha256(level[i]+level[i+1]))
		}
		level = next
		layers = append(layers, level)
	}
	return &mTree{root: level[0], layers: layers, leaves: leaves}
}

func (t *mTree) getProof(index int) (leaf, proof string) {
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

var testTree *mTree

func init() {
	leaves := make([]string, 16)
	for i := 0; i < 16; i++ {
		leaves[i] = rawSha256(fmt.Sprintf("%d", i))
	}
	testTree = buildTree(leaves)
}

const leafIdx = 3

func newCovenant(stateRoot string, blockNumber int64) *StateCovenant {
	return &StateCovenant{
		StateRoot:        runar.ByteString(stateRoot),
		BlockNumber:      blockNumber,
		VerifyingKeyHash: runar.ByteString(testTree.root),
	}
}

type advArgs struct {
	newStateRoot  runar.ByteString
	newBlockNum   runar.Bigint
	batchDataHash runar.ByteString
	preStateRoot  runar.ByteString
	proofFieldA   runar.Bigint
	proofFieldB   runar.Bigint
	proofFieldC   runar.Bigint
	merkleLeaf    runar.ByteString
	merkleProof   runar.ByteString
	merkleIndex   runar.Bigint
}

func buildArgs(preStateRoot string, newBlockNumber int64) advArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchDataHash := rawHash256(preStateRoot + newStateRoot)
	a := int64(1000000)
	b := int64(2000000)
	c := bbMul(a, b)
	leaf, proof := testTree.getProof(leafIdx)

	return advArgs{
		newStateRoot:  runar.ByteString(newStateRoot),
		newBlockNum:   newBlockNumber,
		batchDataHash: runar.ByteString(batchDataHash),
		preStateRoot:  runar.ByteString(preStateRoot),
		proofFieldA:   a,
		proofFieldB:   b,
		proofFieldC:   c,
		merkleLeaf:    runar.ByteString(leaf),
		merkleProof:   runar.ByteString(proof),
		merkleIndex:   int64(leafIdx),
	}
}

func callAdv(c *StateCovenant, a advArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.batchDataHash, a.preStateRoot,
		a.proofFieldA, a.proofFieldB, a.proofFieldC,
		a.merkleLeaf, a.merkleProof, a.merkleIndex,
	)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestStateCovenant_InitialState(t *testing.T) {
	c := newCovenant(zeros32(), 0)
	if c.BlockNumber != 0 {
		t.Errorf("expected block number 0, got %d", c.BlockNumber)
	}
}

func TestStateCovenant_AdvanceState(t *testing.T) {
	c := newCovenant(zeros32(), 0)
	args := buildArgs(zeros32(), 1)
	callAdv(c, args)

	if string(c.StateRoot) != string(args.newStateRoot) {
		t.Error("state root not updated")
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestStateCovenant_ChainAdvances(t *testing.T) {
	c := newCovenant(zeros32(), 0)
	pre := zeros32()
	for block := int64(1); block <= 3; block++ {
		args := buildArgs(pre, block)
		callAdv(c, args)
		if c.BlockNumber != block {
			t.Errorf("expected block %d, got %d", block, c.BlockNumber)
		}
		pre = string(args.newStateRoot)
	}
}

func TestStateCovenant_WrongPreStateRoot_Rejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newCovenant(zeros32(), 0)
	args := buildArgs(zeros32(), 1)
	args.preStateRoot = runar.ByteString(string(make([]byte, 32)) + "x")[:32]
	// Make it different from zeros
	badRoot := make([]byte, 32)
	badRoot[0] = 0xff
	args.preStateRoot = runar.ByteString(badRoot)
	callAdv(c, args)
}

func TestStateCovenant_InvalidBlockNumber_Rejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newCovenant(zeros32(), 5)
	args := buildArgs(zeros32(), 3) // 3 < 5
	callAdv(c, args)
}

func TestStateCovenant_InvalidBabyBearProof_Rejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newCovenant(zeros32(), 0)
	args := buildArgs(zeros32(), 1)
	args.proofFieldC = 99999
	callAdv(c, args)
}

func TestStateCovenant_InvalidMerkleProof_Rejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newCovenant(zeros32(), 0)
	args := buildArgs(zeros32(), 1)
	badLeaf := make([]byte, 32)
	badLeaf[0] = 0xaa
	args.merkleLeaf = runar.ByteString(badLeaf)
	callAdv(c, args)
}

func TestStateCovenant_WrongBatchDataHash_Rejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newCovenant(zeros32(), 0)
	args := buildArgs(zeros32(), 1)
	badHash := make([]byte, 32)
	badHash[0] = 0xbb
	args.batchDataHash = runar.ByteString(badHash)
	callAdv(c, args)
}

func TestStateCovenant_Compile(t *testing.T) {
	if err := runar.CompileCheck("StateCovenant.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

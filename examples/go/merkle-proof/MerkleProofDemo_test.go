package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Merkle tree helper — builds a depth-4 tree (16 leaves)
// ---------------------------------------------------------------------------

type merkleTree struct {
	root   runar.ByteString
	leaves []runar.ByteString
	layers [][]runar.ByteString
}

func buildMerkleTree(leaves []runar.ByteString, hashFn func(runar.ByteString) runar.ByteString) merkleTree {
	level := make([]runar.ByteString, len(leaves))
	copy(level, leaves)
	layers := [][]runar.ByteString{level}

	for len(level) > 1 {
		next := make([]runar.ByteString, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashFn(level[i]+level[i+1]))
		}
		level = next
		layers = append(layers, level)
	}

	return merkleTree{
		root:   level[0],
		leaves: leaves,
		layers: layers,
	}
}

func (t *merkleTree) getProof(index int) (leaf, proof runar.ByteString) {
	var siblings []runar.ByteString
	idx := index
	for d := 0; d < len(t.layers)-1; d++ {
		siblingIdx := idx ^ 1
		siblings = append(siblings, t.layers[d][siblingIdx])
		idx >>= 1
	}
	var proofConcat runar.ByteString
	for _, s := range siblings {
		proofConcat += s
	}
	return t.leaves[index], proofConcat
}

// Create 16 leaves (32-byte SHA-256 hashes)
func makeLeaves() []runar.ByteString {
	leaves := make([]runar.ByteString, 16)
	for i := 0; i < 16; i++ {
		leaves[i] = runar.Sha256Hash(runar.ByteString([]byte{byte(i)}))
	}
	return leaves
}

// ---------------------------------------------------------------------------
// verifySha256 (merkleRootSha256, depth=4)
// ---------------------------------------------------------------------------

func TestMerkleProofDemo_VerifySha256_Index0(t *testing.T) {
	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Sha256Hash)
	leaf, proof := tree.getProof(0)

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifySha256(leaf, proof, 0)
}

func TestMerkleProofDemo_VerifySha256_Index7(t *testing.T) {
	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Sha256Hash)
	leaf, proof := tree.getProof(7)

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifySha256(leaf, proof, 7)
}

func TestMerkleProofDemo_VerifySha256_Index15(t *testing.T) {
	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Sha256Hash)
	leaf, proof := tree.getProof(15)

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifySha256(leaf, proof, 15)
}

func TestMerkleProofDemo_VerifySha256_WrongLeaf(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong leaf")
		}
	}()

	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Sha256Hash)
	_, proof := tree.getProof(0)
	wrongLeaf := runar.Sha256Hash(runar.ByteString([]byte{0xff}))

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifySha256(wrongLeaf, proof, 0)
}

func TestMerkleProofDemo_VerifySha256_WrongIndex(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong index")
		}
	}()

	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Sha256Hash)
	leaf, proof := tree.getProof(0)

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifySha256(leaf, proof, 1) // wrong index
}

// ---------------------------------------------------------------------------
// verifyHash256 (merkleRootHash256, depth=4)
// ---------------------------------------------------------------------------

func TestMerkleProofDemo_VerifyHash256_Index0(t *testing.T) {
	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Hash256)
	leaf, proof := tree.getProof(0)

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifyHash256(leaf, proof, 0)
}

func TestMerkleProofDemo_VerifyHash256_Index10(t *testing.T) {
	leaves := makeLeaves()
	tree := buildMerkleTree(leaves, runar.Hash256)
	leaf, proof := tree.getProof(10)

	c := &MerkleProofDemo{ExpectedRoot: tree.root}
	c.VerifyHash256(leaf, proof, 10)
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

func TestMerkleProofDemo_Compile(t *testing.T) {
	if err := runar.CompileCheck("MerkleProofDemo.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}

package compiler

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// R-056 / CL-BUG-099 — merkleRootPoseidon2KB must authenticate ALL EIGHT
// KoalaBear limbs of the Poseidon2 Merkle root, not just one of them.
//
// The emitter (codegen/poseidon2_merkle.go EmitPoseidon2MerkleRoot) leaves
// root_0..root_7 on the stack. Whatever the stack-lowering dispatch does with
// those eight items, the value a contract ends up comparing against MUST be a
// function of all eight — otherwise
// `assert(merkleRootPoseidon2KB(...) === expected)` authenticates against a
// single ~31-bit field element (p = 2^31-2^24+1), dropping second-preimage
// work to ~2^31 Poseidon2 permutations and birthday work to ~2^15.5.
//
// The test is deliberately ENCODING-AGNOSTIC. It does not hardcode how the
// eight limbs are folded into the single `bigint` the type system declares;
// it DISCOVERS which encoding the compiled script accepts for the honest root
// (the "detect the layout from the honest spend" pattern established by
// groth16_wa_binding_test.go), then requires that perturbing ANY ONE of the
// eight limbs of the expected root makes the spend fail under that same
// encoding. A fold that ignores limb i is caught by the limb-i case, and the
// test does not have to be rewritten if the fold changes.
//
// Why tampering the EXPECTED root is the fair construction: the attacker in
// the real threat model supplies the leaf/sibling preimage, and finding a
// second preimage that collides in one specific limb costs ~2^31 Poseidon2
// permutations — not something a unit test can do honestly. Tampering the
// expected root in limb i is the exact dual: it asks "is limb i load-bearing
// in the on-chain comparison?", which is precisely the property truncation
// violates, and it is decidable in one script execution per limb.
//
// The negative test this replaces (integration/go/poseidon2_kb_vectors_test.go
// TestP2KB_MerkleDepth1_WrongRoot_Rejected) perturbed root[7] SPECIFICALLY —
// the one limb the truncated check happened to look at — so it passed while
// leaving the 7-of-8 gap completely unexercised.
// ---------------------------------------------------------------------------

// koalaBearP is the KoalaBear prime, 2^31 - 2^24 + 1.
const koalaBearP = int64(2130706433)

// buildP2KBRootBindingSource generates a depth-`depth` Poseidon2/KoalaBear
// Merkle verifier. The expected root arrives as a METHOD parameter (not a
// constructor slot) so a spend is exactly [arg pushes | locking script] with
// no constructor splicing — the script under test is byte-for-byte what the
// compiler emitted.
func buildP2KBRootBindingSource(depth int) string {
	var params []string
	var callArgs []string
	for i := 0; i < 8; i++ {
		params = append(params, fmt.Sprintf("l%d: bigint", i))
		callArgs = append(callArgs, fmt.Sprintf("l%d", i))
	}
	for lvl := 0; lvl < depth; lvl++ {
		for i := 0; i < 8; i++ {
			params = append(params, fmt.Sprintf("s%d_%d: bigint", lvl, i))
			callArgs = append(callArgs, fmt.Sprintf("s%d_%d", lvl, i))
		}
	}
	params = append(params, "idx: bigint", "expected: bigint")
	callArgs = append(callArgs, "idx", fmt.Sprintf("%dn", depth))

	return fmt.Sprintf(`
import { SmartContract, assert, merkleRootPoseidon2KB } from 'runar-lang';

class P2KBRootBinding extends SmartContract {
  constructor() {
    super();
  }
  public verify(%s) {
    const root = merkleRootPoseidon2KB(%s);
    assert(root === expected);
  }
}
`, strings.Join(params, ", "), strings.Join(callArgs, ", "))
}

// ---------------------------------------------------------------------------
// Off-chain reference
// ---------------------------------------------------------------------------

// p2kbCompressVector is one `compress` entry of tests/vectors/poseidon2_koalabear.json.
type p2kbCompressVector struct {
	Op       string  `json:"op"`
	Left     []int64 `json:"left"`
	Right    []int64 `json:"right"`
	Expected []int64 `json:"expected"`
	Desc     string  `json:"description"`
}

func loadP2KBCompressVectors(t *testing.T) []p2kbCompressVector {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// compilers/go/compiler -> repo root
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	path := filepath.Join(repoRoot, "tests", "vectors", "poseidon2_koalabear.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var file struct {
		Vectors []p2kbCompressVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []p2kbCompressVector
	for _, v := range file.Vectors {
		if v.Op == "compress" && len(v.Left) == 8 && len(v.Right) == 8 && len(v.Expected) == 8 {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no usable compress vectors in %s", path)
	}
	return out
}

// TestMerkleRootPoseidon2KB_ReferenceMatchesPlonky3Vectors pins the off-chain
// reference (packages/runar-go MerkleRootPoseidon2KB) against the checked-in
// Plonky3 compress vectors. Without this, a wrong reference would make the
// limb-binding test below compare the script against fiction.
func TestMerkleRootPoseidon2KB_ReferenceMatchesPlonky3Vectors(t *testing.T) {
	for _, v := range loadP2KBCompressVectors(t) {
		var leaf [8]int64
		copy(leaf[:], v.Left)
		got := runar.MerkleRootPoseidon2KB(leaf, v.Right, 0, 1)
		for i := 0; i < 8; i++ {
			if got[i] != v.Expected[i] {
				t.Fatalf("%s: reference root[%d] = %d, Plonky3 vector says %d",
					v.Desc, i, got[i], v.Expected[i])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Candidate encodings of the 8-limb root into the single declared `bigint`
// ---------------------------------------------------------------------------

type rootEncoding struct {
	name string
	fn   func(root [8]int64) *big.Int
}

// candidateRootEncodings covers every single-limb truncation plus both
// base-2^32 packings of the full root. Each limb is < 2^31 < 2^32, so both
// packings are injective over the whole root.
func candidateRootEncodings() []rootEncoding {
	encs := make([]rootEncoding, 0, 10)
	for i := 0; i < 8; i++ {
		i := i
		encs = append(encs, rootEncoding{
			name: fmt.Sprintf("limb_%d_only", i),
			fn:   func(root [8]int64) *big.Int { return big.NewInt(root[i]) },
		})
	}
	shift := new(big.Int).Lsh(big.NewInt(1), 32)
	encs = append(encs, rootEncoding{
		name: "pack_limb0_most_significant",
		fn: func(root [8]int64) *big.Int {
			acc := big.NewInt(0)
			for i := 0; i < 8; i++ {
				acc.Mul(acc, shift)
				acc.Add(acc, big.NewInt(root[i]))
			}
			return acc
		},
	})
	encs = append(encs, rootEncoding{
		name: "pack_limb7_most_significant",
		fn: func(root [8]int64) *big.Int {
			acc := big.NewInt(0)
			for i := 7; i >= 0; i-- {
				acc.Mul(acc, shift)
				acc.Add(acc, big.NewInt(root[i]))
			}
			return acc
		},
	})
	return encs
}

// ---------------------------------------------------------------------------
// Script execution
// ---------------------------------------------------------------------------

// scriptNumBytes encodes n in Bitcoin Script number form (little-endian,
// sign-magnitude).
func scriptNumBytes(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{}
	}
	neg := n.Sign() < 0
	be := new(big.Int).Abs(n).Bytes()
	le := make([]byte, len(be))
	for i := range be {
		le[i] = be[len(be)-1-i]
	}
	if le[len(le)-1]&0x80 != 0 {
		le = append(le, 0)
	}
	if neg {
		le[len(le)-1] |= 0x80
	}
	return le
}

// p2kbSpend runs [arg pushes | locking script] through the go-sdk
// interpreter. Params are pushed in declaration order (param 0 deepest).
func p2kbSpend(t *testing.T, lock *script.Script, leaf [8]int64, proof []int64, index int64, expected *big.Int) error {
	t.Helper()
	unlock := &script.Script{}
	push := func(n *big.Int) {
		if err := unlock.AppendPushData(scriptNumBytes(n)); err != nil {
			t.Fatalf("append push: %v", err)
		}
	}
	for _, v := range leaf {
		push(big.NewInt(v))
	}
	for _, v := range proof {
		push(big.NewInt(v))
	}
	push(big.NewInt(index))
	push(expected)

	return interpreter.NewEngine().Execute(
		interpreter.WithScripts(lock, unlock),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}

func compileP2KBRootBinding(t *testing.T, depth int) *script.Script {
	t.Helper()
	res := CompileFromSourceStrWithResult(buildP2KBRootBindingSource(depth), "P2KBRootBinding.runar.ts")
	if res.Artifact == nil || res.Artifact.Script == "" {
		var msgs []string
		for _, d := range res.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile P2KBRootBinding(depth=%d): %s", depth, strings.Join(msgs, "; "))
	}
	lock, err := script.NewFromHex(res.Artifact.Script)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	t.Logf("compiled P2KBRootBinding(depth=%d): %d script bytes", depth, len(*lock))
	return lock
}

// TestMerkleRootPoseidon2KB_BindsEveryRootLimb is the R-056 regression.
//
// Step 1 (non-vacuity control): find the encoding(s) of the honest 8-limb root
// that the compiled script ACCEPTS. If none is accepted, the script rejects
// its own honest spend and no conclusion about limb binding is possible.
//
// Step 2 (the attack): under each accepted encoding, perturb exactly one limb
// of the expected root and require rejection. A limb whose perturbation is
// still accepted is a limb the on-chain check does not look at.
func TestMerkleRootPoseidon2KB_BindsEveryRootLimb(t *testing.T) {
	vecs := loadP2KBCompressVectors(t)
	vec := vecs[0]
	var vecLeaf [8]int64
	copy(vecLeaf[:], vec.Left)

	// An ASYMMETRIC vector, so the index=1 case genuinely exercises the
	// conditional-swap arm — with a symmetric vector (left == right) swapping
	// is a no-op and the arm goes untested.
	asym := vecs[0]
	for _, v := range vecs {
		if fmt.Sprint(v.Left) != fmt.Sprint(v.Right) {
			asym = v
			break
		}
	}
	var asymLeaf [8]int64
	copy(asymLeaf[:], asym.Left)
	t.Logf("asymmetric vector for the swap arm: %s", asym.Desc)

	cases := []struct {
		name  string
		depth int
		leaf  [8]int64
		proof []int64
		index int64
	}{
		// depth 1, index 0: root = compress(leaf, sibling), directly comparable
		// to the checked-in Plonky3 compress vector.
		{"depth1_index0_plonky3_vector", 1, vecLeaf, vec.Right, 0},
		// depth 1, index 1 exercises the conditional-swap arm of the emitter.
		{"depth1_index1_swapped", 1, asymLeaf, asym.Right, 1},
		// depth 2 exercises a multi-level walk: the pack must run once, after
		// the last level, not once per level.
		{"depth2_index2", 2, [8]int64{1, 2, 3, 4, 5, 6, 7, 8},
			[]int64{11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28}, 2},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			lock := compileP2KBRootBinding(t, tc.depth)
			root := runar.MerkleRootPoseidon2KB(tc.leaf, tc.proof, tc.index, int64(tc.depth))
			t.Logf("reference root: %v", root)

			var accepted []rootEncoding
			for _, enc := range candidateRootEncodings() {
				if err := p2kbSpend(t, lock, tc.leaf, tc.proof, tc.index, enc.fn(root)); err == nil {
					accepted = append(accepted, enc)
					t.Logf("honest spend ACCEPTED under encoding %q", enc.name)
				}
			}
			if len(accepted) == 0 {
				t.Fatal("the honest spend was rejected under EVERY candidate root encoding — " +
					"the compiled verifier does not accept a correct Merkle opening, so nothing " +
					"can be concluded about limb binding")
			}

			for _, enc := range accepted {
				for i := 0; i < 8; i++ {
					tampered := root
					tampered[i] = (tampered[i] + 1) % koalaBearP
					err := p2kbSpend(t, lock, tc.leaf, tc.proof, tc.index, enc.fn(tampered))
					if err == nil {
						t.Errorf("SECURITY FAILURE [%s]: an expected root differing from the true "+
							"root ONLY in limb %d was ACCEPTED — limb %d is not authenticated "+
							"on-chain (root truncation, CL-BUG-099)", enc.name, i, i)
						continue
					}
					t.Logf("limb %d perturbation rejected under %q", i, enc.name)
				}
			}
		})
	}
}

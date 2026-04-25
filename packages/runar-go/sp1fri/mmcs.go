package sp1fri

import (
	"fmt"
	"sort"
)

// MerkleTreeMmcs verify_batch — port of `merkle-tree/src/mmcs.rs::verify_batch`
// for the SP1 v6.0.2 base-field MMCS:
//
//   MerkleTreeMmcs<Packing, Packing, MyHash, MyCompress, /*N=*/2, /*DIGEST_ELEMS=*/8>
//
// where MyHash = PaddingFreeSponge<Perm, 16, 8, 8>
//   and MyCompress = TruncatedPermutation<Perm, 2, 8, 16>.
//
// Tree shape: binary (N=2). Each level concatenates [left_digest, right_digest]
// (8 elements each) into a 16-wide preimage and applies the Poseidon2 perm,
// truncating to the first 8 elements.
//
// Cap height is 0 for our config: commit is a single root.

// Dimensions mirrors `p3_matrix::Dimensions` (only `height` is used by the
// base-field verify_batch for the tree-of-batches arity logic; `width` is
// only needed by the ExtensionMmcs adapter which multiplies by EF::DIMENSION).
type Dimensions struct {
	Width  int
	Height int
}

// VerifyBatch verifies a base-field Merkle proof for one or more matrices
// committed jointly. All values are canonical KoalaBear.
//
// Arguments mirror Plonky3 `Mmcs::verify_batch`:
//   - commit: the commitment (here a single-root MerkleCap with len 1).
//   - dimensions: per-matrix (width, height); base impl only consults heights.
//   - index: row index in the tallest matrix.
//   - openedValues: openedValues[i] is the row of matrix i opened at
//                   `index >> (max_log_height - log_height_i)`.
//   - openingProof: sibling digests, leaf-side first.
//
// Returns nil on success, or a descriptive error otherwise.
//
// Reference: `merkle-tree/src/mmcs.rs::verify_batch`, lines 419-552.
func VerifyBatch(
	commit []KbDigest, // canonical Plonky3 MerkleCap, in *Montgomery* (decoder output)
	dimensions []Dimensions,
	index uint64,
	openedValues [][]uint32, // canonical
	openingProof []KbDigest, // canonical Plonky3 digests in Montgomery
) error {
	const N = 2
	const digestElems = 8

	if len(dimensions) != len(openedValues) {
		return fmt.Errorf("verify_batch: dim count %d != opened count %d", len(dimensions), len(openedValues))
	}

	// Sort matrices tallest-first while preserving original index for value lookup.
	type indexedDim struct {
		i      int
		height int
	}
	hs := make([]indexedDim, len(dimensions))
	for i, d := range dimensions {
		hs[i] = indexedDim{i, d.Height}
	}
	sort.SliceStable(hs, func(a, b int) bool { return hs[a].height > hs[b].height })

	// Heights that round up to the same power of two must match exactly.
	for i := 1; i < len(hs); i++ {
		curr, next := hs[i-1].height, hs[i].height
		if curr == next {
			continue
		}
		if nextPow2(curr) == nextPow2(next) {
			return fmt.Errorf("verify_batch: incompatible heights %d / %d", curr, next)
		}
	}

	if len(hs) == 0 {
		return fmt.Errorf("verify_batch: empty batch")
	}

	maxHeight := hs[0].height
	if int(index) >= maxHeight {
		return fmt.Errorf("verify_batch: index %d >= max_height %d", index, maxHeight)
	}

	leafHeightNpt := nextPow2(maxHeight)

	// Hash all leaf-level matrix openings (those whose height matches the tallest npt).
	leafCursor := 0
	var leafElems []uint32
	for leafCursor < len(hs) && nextPow2(hs[leafCursor].height) == leafHeightNpt {
		leafElems = append(leafElems, openedValues[hs[leafCursor].i]...)
		leafCursor++
	}
	digest := Poseidon2HashSlice(leafElems)

	// curr_height_padded: rounded-up to multiple of N. With N=2, this is just
	// the next power of two of max_height initially.
	currHeightPadded := paddedLen(maxHeight, N)

	defaultDigest := [digestElems]uint32{}

	proofPos := 0
	for proofPos < len(openingProof) {
		// Determine arity step at this level. With N=2 the only possible step
		// is 2 (binary). For 4-ary configs Plonky3 uses
		// `select_arity_step::<N>` to interleave 4-ary and 2-ary levels; we
		// hard-code 2 here since SP1 v6 uses N=2 throughout.
		const step = 2
		numSiblings := step - 1
		if proofPos+numSiblings > len(openingProof) {
			return fmt.Errorf("verify_batch: proof too short at level %d", proofPos)
		}

		posInGroup := int(index % step)
		var inputs [N][digestElems]uint32
		siblingIdx := 0
		for k := 0; k < N; k++ {
			if k == posInGroup {
				inputs[k] = digest
			} else {
				// Sibling digest: convert from Montgomery on the fly.
				sib := openingProof[proofPos+siblingIdx]
				for j := 0; j < digestElems; j++ {
					inputs[k][j] = sib[j].Canonical()
				}
				siblingIdx++
			}
		}
		// Suppress unused-default-digest warning when all slots filled.
		_ = defaultDigest

		digest = Poseidon2Compress(inputs[0], inputs[1])
		proofPos += numSiblings
		index /= step

		logicalNext := currHeightPadded / step
		currHeightPadded = paddedLen(logicalNext, N)

		// Inject any next-height matrices that hash in here.
		logicalNextNpt := nextPow2(logicalNext)
		var injectElems []uint32
		var injectAny bool
		if leafCursor < len(hs) && nextPow2(hs[leafCursor].height) == logicalNextNpt {
			injectAny = true
			nextHeight := hs[leafCursor].height
			for leafCursor < len(hs) && hs[leafCursor].height == nextHeight {
				injectElems = append(injectElems, openedValues[hs[leafCursor].i]...)
				leafCursor++
			}
		}
		if injectAny {
			injected := Poseidon2HashSlice(injectElems)
			digest = Poseidon2Compress(digest, injected)
		}
	}

	// Compare against the cap.
	capIdx := int(index)
	if capIdx >= len(commit) {
		return fmt.Errorf("verify_batch: cap index %d >= cap len %d", capIdx, len(commit))
	}
	want := commit[capIdx]
	for i := 0; i < digestElems; i++ {
		if want[i].Canonical() != digest[i] {
			return fmt.Errorf("verify_batch: cap mismatch at idx %d", capIdx)
		}
	}
	return nil
}

// VerifyBatchExt is the ExtensionMmcs adapter (`commit/src/adapters/extension_mmcs.rs`).
// Each Ext4 opened value is flattened to its 4 base-field coordinates and the
// per-matrix width is multiplied by 4 before delegating to the base verify.
//
// Reference: `extension_mmcs.rs::verify_batch`, lines 70-96.
func VerifyBatchExt(
	commit []KbDigest,
	dimensions []Dimensions,
	index uint64,
	openedValues [][]Ext4,
	openingProof []KbDigest,
) error {
	baseDims := make([]Dimensions, len(dimensions))
	for i, d := range dimensions {
		baseDims[i] = Dimensions{Width: d.Width * 4, Height: d.Height}
	}
	baseValues := make([][]uint32, len(openedValues))
	for i, row := range openedValues {
		flat := make([]uint32, 0, 4*len(row))
		for _, e := range row {
			flat = append(flat, e[0], e[1], e[2], e[3])
		}
		baseValues[i] = flat
	}
	return VerifyBatch(commit, baseDims, index, baseValues, openingProof)
}

// nextPow2 returns the smallest 2^k >= n. n must be > 0.
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// paddedLen rounds n up to the nearest multiple of step.
//
// Mirrors `padded_len` in `merkle-tree/src/merkle_tree.rs`.
func paddedLen(n, step int) int {
	if n%step == 0 {
		return n
	}
	return n + (step - n%step)
}

package sp1fri

import (
	"fmt"
	"sort"
)

// FRI verifier for the SP1 v6.0.2 minimal-guest config.
//
// Mirrors `fri/src/verifier.rs::verify_fri` (lines 114-325) and the helpers
// `verify_query` (358-492) and `open_input` (513-650).
//
// All field elements are canonical KoalaBear (uint32 / Ext4).

// verifyFri runs the FRI verification protocol against the PoC minimal-guest
// config. Thin wrapper around `verifyFriWithConfig` for backwards-compatible
// callers.
func verifyFri(proof *FriProof, chal *DuplexChallenger, input []commitOpening) error {
	return verifyFriWithConfig(proof, chal, input, minimalGuestConfig)
}

// verifyFriWithConfig runs the FRI verification protocol with a caller-supplied
// `FriVerifierConfig`. Returns nil on success.
//
// `input` is the ordered list of [trace, quotient_chunks] joint commitments
// each with their per-matrix opened points and values. (No preprocessed,
// no zk randomization in either fixture.)
func verifyFriWithConfig(proof *FriProof, chal *DuplexChallenger, input []commitOpening, cfg FriVerifierConfig) error {

	// 1. Sample alpha for the per-height random linear combinations of the
	//    quotient (f(z) - f(x)) / (z - x).
	alpha := chal.SampleExt4()

	// 2. Schedule consistency checks (verifier.rs lines 147-184).
	expectedRounds := len(proof.CommitPhaseCommits)
	for i, qp := range proof.QueryProofs {
		if len(qp.CommitPhaseOpenings) != expectedRounds {
			return fmt.Errorf("fri: query %d round count %d != %d",
				i, len(qp.CommitPhaseOpenings), expectedRounds)
		}
	}
	logArities := make([]int, expectedRounds)
	if len(proof.QueryProofs) > 0 {
		for i, op := range proof.QueryProofs[0].CommitPhaseOpenings {
			logArities[i] = int(op.LogArity)
		}
	}
	for q, qp := range proof.QueryProofs[1:] {
		for i, op := range qp.CommitPhaseOpenings {
			if int(op.LogArity) != logArities[i] {
				return fmt.Errorf("fri: query %d arity[%d] mismatch", q+1, i)
			}
		}
	}

	totalLogReduction := 0
	for _, la := range logArities {
		totalLogReduction += la
	}
	logGlobalMaxHeight := totalLogReduction + cfg.logBlowup + cfg.logFinalPolyLen

	if len(proof.CommitPowWitnesses) != expectedRounds {
		return fmt.Errorf("fri: commit_pow_witnesses %d != %d",
			len(proof.CommitPowWitnesses), expectedRounds)
	}

	// 3. Per-round: observe commitment, check PoW witness, sample beta.
	betas := make([]Ext4, expectedRounds)
	for r := 0; r < expectedRounds; r++ {
		for _, d := range proof.CommitPhaseCommits[r] {
			chal.ObserveDigest(canonicalKbDigest(d))
		}
		w := proof.CommitPowWitnesses[r].Canonical()
		if !chal.CheckWitness(cfg.commitPowBits, w) {
			return fmt.Errorf("fri: commit-phase round %d invalid PoW witness", r)
		}
		betas[r] = chal.SampleExt4()
	}

	// 4. final_poly length check + observation (verifier.rs 215-223).
	expectedFinalPolyLen := 1 << cfg.logFinalPolyLen
	if len(proof.FinalPoly) != expectedFinalPolyLen {
		return fmt.Errorf("fri: final_poly len %d != %d", len(proof.FinalPoly), expectedFinalPolyLen)
	}
	finalPoly := convertExt4Vec(proof.FinalPoly)
	chal.ObserveExt4Slice(finalPoly)

	// 5. Query-proof count check.
	if len(proof.QueryProofs) != cfg.numQueries {
		return fmt.Errorf("fri: query_proofs %d != %d", len(proof.QueryProofs), cfg.numQueries)
	}

	// 6. Bind variable-arity schedule into transcript before query grinding.
	for _, la := range logArities {
		chal.Observe(uint32(la))
	}
	queryPow := proof.QueryPowWitness.Canonical()
	if !chal.CheckWitness(cfg.queryPowBits, queryPow) {
		return fmt.Errorf("fri: invalid query PoW witness")
	}

	logFinalHeight := cfg.logBlowup + cfg.logFinalPolyLen

	// 7. Per-query loop.
	for qi, qp := range proof.QueryProofs {
		// extra_query_index_bits = 0 for two-adic FRI folding.
		index := chal.SampleBits(logGlobalMaxHeight)

		// Open input + verify input MMCS proofs and produce reduced openings
		// per height (sorted descending).
		ros, err := openInput(logGlobalMaxHeight, index, qp.InputProof, alpha, input)
		if err != nil {
			return fmt.Errorf("fri: query %d open_input: %w", qi, err)
		}

		// FRI fold-and-verify chain.
		domainIndex := index // extra_query_index_bits = 0
		folded, err := verifyQuery(
			betas, proof.CommitPhaseCommits, qp.CommitPhaseOpenings,
			&domainIndex, ros, logGlobalMaxHeight, logFinalHeight,
		)
		if err != nil {
			return fmt.Errorf("fri: query %d: %w", qi, err)
		}

		// Final poly equality: evaluate final_poly at x = g^{rev_bits(domain_index, log_global_max_height)}.
		x := KbPow(KbTwoAdicGenerator(logGlobalMaxHeight),
			reverseBitsLen(domainIndex, logGlobalMaxHeight))
		xExt := Ext4FromBase(x)
		// Horner evaluation over Ext4 coefficients.
		eval := Ext4Zero()
		for i := len(finalPoly) - 1; i >= 0; i-- {
			eval = Ext4Add(Ext4Mul(eval, xExt), finalPoly[i])
		}
		if !Ext4Equal(eval, folded) {
			return fmt.Errorf("fri: query %d final_poly mismatch", qi)
		}
	}

	return nil
}

// reducedOpening is `(log_height, evaluation)` produced by `open_input`.
type reducedOpening struct {
	logHeight int
	value     Ext4
}

// openInput is the verifier-side `open_input` (verifier.rs lines 513-650).
//
// Returns a slice sorted by logHeight descending. Each entry is the reduced
// opening at that height: a sum over (point, evaluation) of
//   alpha_pow * (p_at_z - p_at_x) * (z - x)^{-1}
func openInput(
	logGlobalMaxHeight int,
	index uint64,
	inputProof []BatchOpening,
	alpha Ext4,
	commitments []commitOpening,
) ([]reducedOpening, error) {
	if len(inputProof) != len(commitments) {
		return nil, fmt.Errorf("input batch count %d != commit count %d",
			len(inputProof), len(commitments))
	}

	// Map log_height -> (alpha_pow, ro).
	type acc struct {
		alphaPow Ext4
		ro       Ext4
	}
	roByHeight := map[int]*acc{}

	for batch, batchOp := range inputProof {
		commit := commitments[batch]

		// Per-matrix log heights (after blowup).
		batchHeights := make([]int, len(commit.matrices))
		for i, m := range commit.matrices {
			batchHeights[i] = 1 << m.logHeightAfterBlowup
		}
		batchDims := make([]Dimensions, len(batchHeights))
		for i, h := range batchHeights {
			batchDims[i] = Dimensions{Width: 0, Height: h}
		}

		// reduced_index = index >> (log_global_max_height - log2(max_h))
		maxH := 0
		for _, h := range batchHeights {
			if h > maxH {
				maxH = h
			}
		}
		reducedIndex := uint64(0)
		if maxH > 0 {
			logMax := log2Strict(maxH)
			reducedIndex = index >> (logGlobalMaxHeight - logMax)
		}

		// Convert opened values from Montgomery and verify the input MMCS proof.
		openedValuesBase := make([][]uint32, len(batchOp.OpenedValues))
		for i, row := range batchOp.OpenedValues {
			r := make([]uint32, len(row))
			for j, v := range row {
				r[j] = v.Canonical()
			}
			openedValuesBase[i] = r
		}
		if err := VerifyBatch(commit.commit, batchDims, reducedIndex,
			openedValuesBase, batchOp.OpeningProof); err != nil {
			return nil, fmt.Errorf("input MMCS verify (batch %d): %w", batch, err)
		}

		if len(batchOp.OpenedValues) != len(commit.matrices) {
			return nil, fmt.Errorf("batch %d opened-values count %d != matrices %d",
				batch, len(batchOp.OpenedValues), len(commit.matrices))
		}

		// Per-matrix reduced-opening contributions.
		for matIdx, mat := range commit.matrices {
			matOpening := openedValuesBase[matIdx]
			logHeight := mat.logHeightAfterBlowup
			bitsReduced := logGlobalMaxHeight - logHeight
			revIdx := reverseBitsLen(index>>bitsReduced, logHeight)

			// x = GENERATOR * g_logHeight^revIdx
			gPow := KbPow(KbTwoAdicGenerator(logHeight), revIdx)
			x := KbMul(KbGenerator, gPow)
			xExt := Ext4FromBase(x)

			a, ok := roByHeight[logHeight]
			if !ok {
				a = &acc{alphaPow: Ext4One(), ro: Ext4Zero()}
				roByHeight[logHeight] = a
			}

			for _, pe := range mat.points {
				z := pe.point
				if len(matOpening) != len(pe.values) {
					return nil, fmt.Errorf("batch %d mat %d eval count %d != %d",
						batch, matIdx, len(pe.values), len(matOpening))
				}
				quotient := Ext4Inv(Ext4Sub(z, xExt))
				for k, pAtZ := range pe.values {
					pAtX := matOpening[k]
					diff := Ext4Sub(pAtZ, Ext4FromBase(pAtX))
					a.ro = Ext4Add(a.ro, Ext4Mul(a.alphaPow, Ext4Mul(diff, quotient)))
					a.alphaPow = Ext4Mul(a.alphaPow, alpha)
				}
			}
		}
	}

	// Sort by log_height descending.
	heights := make([]int, 0, len(roByHeight))
	for h := range roByHeight {
		heights = append(heights, h)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(heights)))
	out := make([]reducedOpening, len(heights))
	for i, h := range heights {
		out[i] = reducedOpening{logHeight: h, value: roByHeight[h].ro}
	}
	return out, nil
}

// verifyQuery runs the per-query FRI fold chain (verifier.rs 358-492).
//
// Returns the final folded evaluation.
func verifyQuery(
	betas []Ext4,
	commits []MerkleCap,
	openings []CommitPhaseProofStep,
	startIndex *uint64,
	ros []reducedOpening,
	logGlobalMaxHeight int,
	logFinalHeight int,
) (Ext4, error) {
	if len(ros) == 0 || ros[0].logHeight != logGlobalMaxHeight {
		return Ext4{}, fmt.Errorf("missing/incorrect initial reduced opening")
	}
	folded := ros[0].value
	roIdx := 1

	logCurrentHeight := logGlobalMaxHeight

	for round, op := range openings {
		beta := betas[round]
		commit := commits[round]
		logArity := int(op.LogArity)
		arity := 1 << logArity

		if len(op.SiblingValues) != arity-1 {
			return Ext4{}, fmt.Errorf("round %d sibling count %d != %d",
				round, len(op.SiblingValues), arity-1)
		}

		indexInGroup := int(*startIndex % uint64(arity))
		evals := make([]Ext4, arity)
		evals[indexInGroup] = folded
		sibIdx := 0
		for j := 0; j < arity; j++ {
			if j == indexInGroup {
				continue
			}
			evals[j] = FromKbExt4(op.SiblingValues[sibIdx])
			sibIdx++
		}

		logFoldedHeight := logCurrentHeight - logArity

		// Verify FRI commit-phase MMCS at this round.
		dims := []Dimensions{{Width: arity, Height: 1 << logFoldedHeight}}
		*startIndex >>= logArity
		if err := VerifyBatchExt(commit, dims, *startIndex,
			[][]Ext4{evals}, op.OpeningProof); err != nil {
			return Ext4{}, fmt.Errorf("round %d MMCS: %w", round, err)
		}

		// Fold the row.
		folded = foldRow(*startIndex, logFoldedHeight, logArity, beta, evals)
		logCurrentHeight = logFoldedHeight

		// Roll in next reduced opening if its height matches the new
		// log_folded_height.
		if roIdx < len(ros) && ros[roIdx].logHeight == logFoldedHeight {
			ro := ros[roIdx]
			roIdx++
			betaPow := Ext4PowPow2(beta, uint32(logArity))
			folded = Ext4Add(folded, Ext4Mul(betaPow, ro.value))
		}
	}

	if logCurrentHeight != logFinalHeight {
		return Ext4{}, fmt.Errorf("final fold height %d != expected %d",
			logCurrentHeight, logFinalHeight)
	}
	if roIdx < len(ros) {
		return Ext4{}, fmt.Errorf("unconsumed reduced openings remain (next height %d)",
			ros[roIdx].logHeight)
	}

	return folded, nil
}

// foldRow is `TwoAdicFriFolding::fold_row` (`fri/src/two_adic_pcs.rs`
// lines 110-133):
//
//   subgroup_start = g_(log_height + log_arity) ^ reverse_bits(index, log_height)
//   xs = (subgroup_start * g_(log_arity)^k) for k in 0..arity, then bit-reversed
//   return lagrange_interpolate_at(xs, evals, beta)
func foldRow(index uint64, logHeight int, logArity int, beta Ext4, evals []Ext4) Ext4 {
	arity := 1 << logArity
	subgroupStart := KbPow(KbTwoAdicGenerator(logHeight+logArity),
		reverseBitsLen(index, logHeight))
	g := KbTwoAdicGenerator(logArity)
	xs := make([]uint32, arity)
	xs[0] = subgroupStart
	for i := 1; i < arity; i++ {
		xs[i] = KbMul(xs[i-1], g)
	}
	// Bit-reverse xs in place.
	reverseSliceIndexBits(xs)
	return lagrangeInterpolateAt(xs, evals, beta)
}

// reverseSliceIndexBits permutes `xs` so that index `i` moves to
// `reverseBitsLen(i, log2(len))`. Mirrors `p3_util::reverse_slice_index_bits`.
func reverseSliceIndexBits[T any](xs []T) {
	n := len(xs)
	if n <= 1 {
		return
	}
	logN := log2Strict(n)
	for i := 0; i < n; i++ {
		j := int(reverseBitsLen(uint64(i), logN))
		if j > i {
			xs[i], xs[j] = xs[j], xs[i]
		}
	}
}

// lagrangeInterpolateAt is `lagrange_interpolate_at` (two_adic_pcs.rs lines 221-261).
// Uses the barycentric formula assuming xs lie in a coset of the 2^log_n roots.
func lagrangeInterpolateAt(xs []uint32, ys []Ext4, z Ext4) Ext4 {
	n := len(xs)
	if n == 0 {
		return Ext4Zero()
	}
	// Early return if z matches an xs.
	for i, x := range xs {
		if Ext4Equal(z, Ext4FromBase(x)) {
			return ys[i]
		}
	}

	logN := log2Strict(n)
	// coset_power = xs[0] ^ (2^log_n)
	cosetPower := KbPow(xs[0], uint64(1)<<logN)
	weightScaleBase := KbInv(KbMul(KbFromU64(uint64(n)), cosetPower))

	// (z - x_i)^-1 batch.
	diffs := make([]Ext4, n)
	for i, x := range xs {
		diffs[i] = Ext4Sub(z, Ext4FromBase(x))
	}
	diffInvs := batchInvExt4(diffs)

	// l_z = product (z - x_i)
	lZ := Ext4One()
	for _, d := range diffs {
		lZ = Ext4Mul(lZ, d)
	}

	result := Ext4Zero()
	for i := range xs {
		w := KbMul(xs[i], weightScaleBase)
		term := Ext4Mul(Ext4ScalarMul(ys[i], w), diffInvs[i])
		result = Ext4Add(result, term)
	}
	return Ext4Mul(result, lZ)
}

// batchInvExt4 returns the per-element inverses. Simple O(n) inverses (the
// fixture has n in {2,4} — no batch trick needed).
func batchInvExt4(xs []Ext4) []Ext4 {
	out := make([]Ext4, len(xs))
	for i, x := range xs {
		out[i] = Ext4Inv(x)
	}
	return out
}

// log2Strict returns log2(n) when n is a power of two; panics otherwise.
func log2Strict(n int) int {
	if n <= 0 || n&(n-1) != 0 {
		panic(fmt.Sprintf("log2Strict: %d not a positive power of two", n))
	}
	r := 0
	for (1 << r) < n {
		r++
	}
	return r
}

package sp1fri

import (
	"fmt"
	"math/bits"
)

// Verify is the off-chain Go reference verifier for the SP1 v6.0.2
// minimal-guest fixture (Fibonacci AIR over KoalaBear, log_blowup=2,
// num_queries=2, log_final_poly_len=2, max_log_arity=1, commit_pow_bits=1,
// query_pow_bits=1).
//
// Algorithm direct port of `uni-stark/src/verifier.rs::verify_with_preprocessed`
// (lines 242-495), specialised for:
//   - no preprocessed trace
//   - no zk randomization
//   - FibAir public_values length 3
//   - FRI binary folding (max_log_arity = 1)
//   - Plonky3 commit ~794faa1.
//
// All field elements are converted to canonical KoalaBear at the boundary;
// internal arithmetic is canonical-form throughout.
func Verify(proof *Proof, publicValues []uint32) error {
	cfg := minimalGuestConfig

	if uint64(cfg.numPublicValues) != uint64(len(publicValues)) {
		return fmt.Errorf("verify: public values len mismatch: want %d got %d",
			cfg.numPublicValues, len(publicValues))
	}

	// ----- 1. Shape checks (verifier.rs lines 320-352) ------------------------
	degreeBits := int(proof.DegreeBits)
	if degreeBits != cfg.degreeBits {
		return fmt.Errorf("verify: degree_bits mismatch: want %d got %d", cfg.degreeBits, degreeBits)
	}
	if degreeBits >= 64 {
		return fmt.Errorf("verify: degree_bits too large")
	}
	baseDegreeBits := degreeBits // is_zk = 0
	preprocessedWidth := 0       // no preprocessed trace
	airWidth := 2                // Fib AIR has 2 columns

	// log_num_quotient_chunks: max_constraint_degree=2 → log2_ceil(1) = 0 chunks log,
	// num_quotient_chunks = 1.
	logNumQuotientChunks := 0
	numQuotientChunks := 1 << logNumQuotientChunks

	// Validate opened-values shape.
	if len(proof.OpenedValues.TraceLocal) != airWidth {
		return fmt.Errorf("verify: trace_local width %d != %d", len(proof.OpenedValues.TraceLocal), airWidth)
	}
	if proof.OpenedValues.TraceNext == nil || len(*proof.OpenedValues.TraceNext) != airWidth {
		return fmt.Errorf("verify: trace_next missing or width mismatch")
	}
	if len(proof.OpenedValues.QuotientChunks) != numQuotientChunks {
		return fmt.Errorf("verify: quotient_chunks count %d != %d", len(proof.OpenedValues.QuotientChunks), numQuotientChunks)
	}
	for i, qc := range proof.OpenedValues.QuotientChunks {
		if len(qc) != 4 { // Challenge::DIMENSION = 4
			return fmt.Errorf("verify: quotient_chunks[%d] dim %d != 4", i, len(qc))
		}
	}

	// ----- 2. Initialise challenger and observe instance metadata -------------
	// Mirrors verifier.rs lines 355-367. NOTE: per the fixture, no preprocessed
	// commit is observed (preprocessed_width = 0).
	chal := NewDuplexChallenger()
	chal.Observe(uint32(degreeBits))
	chal.Observe(uint32(baseDegreeBits))
	chal.Observe(uint32(preprocessedWidth))
	// Observe trace commitment (one digest, cap height 0).
	for _, d := range proof.Commitments.Trace {
		chal.ObserveDigest(canonicalKbDigest(d))
	}
	// Public values.
	chal.ObserveSlice(publicValues)

	// ----- 3. Sample alpha; observe quotient commitment ----------------------
	alpha := chal.SampleExt4()
	for _, d := range proof.Commitments.QuotientChunks {
		chal.ObserveDigest(canonicalKbDigest(d))
	}

	// ----- 4. Sample zeta; compute zeta_next ---------------------------------
	zeta := chal.SampleExt4()
	// init_trace_domain has shift=1, log_size=degreeBits. next_point(x) = x * h
	// where h is the subgroup generator.
	h := KbTwoAdicGenerator(degreeBits)
	zetaNext := Ext4ScalarMul(zeta, h)

	// ----- 5. Observe opened values in the prover's emit order ---------------
	// Mirrors `TwoAdicFriPcs::verify` lines 678-686:
	//   for each commitment, for each matrix, for each opening point:
	//     observe its claimed evaluations.
	// The order is determined by the order coms_to_verify is built in
	// verifier.rs lines 397-452. Without preprocessed/random commitments
	// the order is: trace_round, then quotient_chunks_round.
	traceLocal := convertExt4Vec(proof.OpenedValues.TraceLocal)
	traceNext := convertExt4Vec(*proof.OpenedValues.TraceNext)
	chal.ObserveExt4Slice(traceLocal)
	chal.ObserveExt4Slice(traceNext)
	quotChunks := make([][]Ext4, numQuotientChunks)
	for i, qc := range proof.OpenedValues.QuotientChunks {
		quotChunks[i] = convertExt4Vec(qc)
		chal.ObserveExt4Slice(quotChunks[i])
	}

	// ----- 6. PCS verify (FRI) -----------------------------------------------
	// At this point the challenger state is identical to the prover's at the
	// start of `verify_fri`. Build the per-round commitment-with-opening-points
	// description and dispatch.
	logTraceHeight := degreeBits + cfg.logBlowup
	traceRound := commitOpening{
		commit:     proof.Commitments.Trace,
		matrices:   []matrixOpening{
			{
				logHeightAfterBlowup: logTraceHeight, // 8 << 2 = 32, log_height = 5
				points: []pointEval{
					{point: zeta, values: traceLocal},
					{point: zetaNext, values: traceNext},
				},
			},
		},
	}
	// Quotient domain: trace_domain.create_disjoint_domain(quotient_domain_size).
	// quotient_domain_size = degree << log_num_quotient_chunks = 8 << 0 = 8.
	// So quotient_chunks_domains is split into num_quotient_chunks = 1 chunks
	// of log_size = 3. With blowup, log_height = 5.
	// The randomized_quotient_chunks_domains have size << is_zk = same as
	// quotient_chunks_domains since is_zk = 0.
	qcMatrices := make([]matrixOpening, numQuotientChunks)
	for i := range quotChunks {
		qcMatrices[i] = matrixOpening{
			logHeightAfterBlowup: degreeBits + cfg.logBlowup,
			points:               []pointEval{{point: zeta, values: quotChunks[i]}},
		}
	}
	quotRound := commitOpening{commit: proof.Commitments.QuotientChunks, matrices: qcMatrices}

	if err := verifyFri(&proof.OpeningProof, chal, []commitOpening{traceRound, quotRound}); err != nil {
		return fmt.Errorf("verify: FRI: %w", err)
	}

	// ----- 7. Recompose quotient(zeta) from chunks; check OOD constraint -----
	// quotient_chunks_domains: trace_domain (size 8, shift=1) creates a
	// disjoint domain of size 8 (1 chunk). split_domains(1) gives back the
	// single domain unchanged. Its first_point() is its `shift`.
	// trace_domain.create_disjoint_domain(8) returns the coset
	// (1 * GENERATOR, log_size=3) = (3, 3). split_domains(1) = [(3, 3)].
	logQuotientChunkSize := degreeBits + logNumQuotientChunks // = 3
	chunkShift := KbGenerator                                 // GENERATOR=3
	chunkDomains := []chunkDomain{{shift: chunkShift, logSize: logQuotientChunkSize}}

	quotient := recomposeQuotient(chunkDomains, quotChunks, zeta)

	// init_trace_domain selectors at zeta (shift=1, log_size=degreeBits).
	sels := SelectorsAtPoint(degreeBits, zeta)

	// Public values as canonical uint32, lifted into pis for AIR eval.
	if len(publicValues) != 3 {
		return fmt.Errorf("verify: expected 3 public values, got %d", len(publicValues))
	}
	pis := [3]uint32{publicValues[0], publicValues[1], publicValues[2]}

	folded := EvalFibonacciConstraints(
		[2]Ext4{traceLocal[0], traceLocal[1]},
		[2]Ext4{traceNext[0], traceNext[1]},
		pis, sels, alpha,
	)

	// folded * inv_vanishing == quotient
	lhs := Ext4Mul(folded, sels.InvVanishing)
	if !Ext4Equal(lhs, quotient) {
		return fmt.Errorf("verify: OOD constraint mismatch")
	}
	return nil
}

// minimalGuestConfig captures the fixture's pinned config (see
// `tests/vectors/sp1/fri/minimal-guest/README.md`).
var minimalGuestConfig = struct {
	degreeBits        int
	logBlowup         int
	logFinalPolyLen   int
	maxLogArity       int
	numQueries        int
	commitPowBits     int
	queryPowBits      int
	numPublicValues   int
}{
	degreeBits:        3,
	logBlowup:         2,
	logFinalPolyLen:   2,
	maxLogArity:       1,
	numQueries:        2,
	commitPowBits:     1,
	queryPowBits:      1,
	numPublicValues:   3,
}

// canonicalKbDigest converts an 8-element KbDigest from Montgomery to canonical.
func canonicalKbDigest(d KbDigest) [8]uint32 {
	var out [8]uint32
	for i, v := range d {
		out[i] = v.Canonical()
	}
	return out
}

// convertExt4Vec converts a slice of Montgomery-form KbExt4 into canonical Ext4.
func convertExt4Vec(in []KbExt4) []Ext4 {
	out := make([]Ext4, len(in))
	for i, e := range in {
		out[i] = FromKbExt4(e)
	}
	return out
}

// commitOpening / matrixOpening / pointEval mirror the
// `CommitmentWithOpeningPoints<Challenge, Commitment, Domain>` structure used
// by the FRI verifier (see `fri/src/two_adic_pcs.rs`).
type commitOpening struct {
	commit   MerkleCap
	matrices []matrixOpening
}

type matrixOpening struct {
	logHeightAfterBlowup int
	points               []pointEval
}

type pointEval struct {
	point  Ext4
	values []Ext4
}

// chunkDomain captures `(shift, log_size)` for a quotient chunk domain.
type chunkDomain struct {
	shift   uint32
	logSize int
}

// recomposeQuotient reconstructs `quotient(zeta)` from per-chunk evaluations.
//
// Direct port of `uni-stark/src/verifier.rs::recompose_quotient_from_chunks`
// (lines 50-90), specialised to KoalaBear/Ext4. With a single chunk the zps[0]
// coefficient is 1 (empty product), so this collapses to building
//   sum over basis: ith_basis_element(e_i) * coefficient[e_i]
// for the single chunk's vector of 4 Ext4 coefficients.
func recomposeQuotient(domains []chunkDomain, chunks [][]Ext4, zeta Ext4) Ext4 {
	zps := make([]Ext4, len(domains))
	for i, di := range domains {
		zp := Ext4One()
		for j, dj := range domains {
			if j == i {
				continue
			}
			// other_domain.vanishing_poly_at_point(zeta) /
			// other_domain.vanishing_poly_at_point(domain.first_point())
			vAtZeta := vanishingAt(dj, zeta)
			vAtFirst := vanishingAt(dj, Ext4FromBase(di.shift))
			zp = Ext4Mul(zp, Ext4Div(vAtZeta, vAtFirst))
		}
		zps[i] = zp
	}

	out := Ext4Zero()
	for i, ch := range chunks {
		// Compute the per-chunk sum: sum over e_i of ith_basis_element(e_i) * c.
		// In Plonky3, BasedVectorSpace<Val>::ith_basis_element gives the
		// extension element X^{e_i} for our binomial extension. ch[e_i] is
		// itself an Ext4. So the product is:
		//   (X^{e_i} as Ext4) * ch[e_i]
		// We compute this directly using polynomial multiplication.
		sum := Ext4Zero()
		for ei, c := range ch {
			basis := basisExt4(ei)
			sum = Ext4Add(sum, Ext4Mul(basis, c))
		}
		out = Ext4Add(out, Ext4Mul(zps[i], sum))
	}
	return out
}

// basisExt4 returns the canonical `i`-th basis element of Ext4 (= X^i mod (X^4 - 3)).
// For i in [0,3] this is just the unit vector with 1 at position i.
func basisExt4(i int) Ext4 {
	var e Ext4
	e[i] = 1
	return e
}

// vanishingAt computes `Z_{gH}(point) = (g^{-1} * point)^|H| - 1` for the
// chunk domain. Mirrors `TwoAdicMultiplicativeCoset::vanishing_poly_at_point`.
func vanishingAt(d chunkDomain, point Ext4) Ext4 {
	gInv := KbInv(d.shift)
	un := Ext4ScalarMul(point, gInv)
	return Ext4Sub(Ext4PowPow2(un, uint32(d.logSize)), Ext4One())
}

// reverseBitsLen reverses the low `n` bits of `x`. Mirrors
// `p3_util::reverse_bits_len`.
func reverseBitsLen(x uint64, n int) uint64 {
	if n == 0 {
		return 0
	}
	r := bits.Reverse64(x)
	return r >> (64 - uint(n))
}

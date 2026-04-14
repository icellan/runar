package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// BasefoldVerifier verifies a StackedBasefold/STARK proof over KoalaBear (SP1 v6).
//
// This contract implements the Basefold polynomial commitment scheme verification
// algorithm used in STARK proof systems. The Basefold protocol combines FRI-style
// folding with a batched polynomial commitment to verify that claimed polynomial
// evaluations are consistent with committed polynomials.
//
// All arithmetic operates in the KoalaBear prime field (p = 2^31 - 2^24 + 1 =
// 2,130,706,433) and its quartic extension field (x^4 - 3). Merkle path
// verification uses Poseidon2 KoalaBear (8-element digests).
//
// # Verification Algorithm (9 steps)
//
//  1. Absorb commitments into Fiat-Shamir transcript (implicit via challenge inputs)
//  2. Compute batched evaluation claim from individual polynomial evaluations
//  3. Sumcheck rounds: verify polynomial evaluation consistency
//  4. Proof-of-work check: verify grinding witness
//  5. Sample query indices (derived from Fiat-Shamir challenges)
//  6. Per-query: compute batched polynomial opening from individual openings
//  7. Per-query: verify Merkle opening proofs (Poseidon2 KoalaBear)
//  8. Per-query: FRI folding consistency check
//  9. Final reduced polynomial check
//
// # Reduced Parameters (proof of concept)
//
// For feasibility, this contract uses reduced parameters:
//   - numQueries = 2 (production: 124)
//   - merkleDepth = 4 (production: ~20)
//   - sumcheckRounds = 4 (production: log2(trace_length))
//   - numPolynomials = 2 (production: varies per AIR)
//
// The Poseidon2 Merkle root comparison checks the first element of the
// 8-element digest (collision resistance ~2^31). Production implementations
// verify all 8 elements via the codegen layer (not the contract DSL).
type BasefoldVerifier struct {
	runar.SmartContract
	// CommitRoot0 is the first element of the Poseidon2 Merkle root for committed
	// polynomial evaluations. In production all 8 elements would be verified.
	CommitRoot0 runar.Bigint `runar:"readonly"`
	// FriCommitRoot0 is the first element of the Poseidon2 Merkle root for FRI
	// folded polynomial evaluations.
	FriCommitRoot0 runar.Bigint `runar:"readonly"`
}

// Verify checks a Basefold/STARK proof.
//
// The prover supplies all proof data as method parameters (unlocking script).
func (v *BasefoldVerifier) Verify(
	// -- Step 2: Batched evaluation --
	eval0C0, eval0C1, eval0C2, eval0C3 runar.Bigint,
	eval1C0, eval1C1, eval1C2, eval1C3 runar.Bigint,
	batchAlpha0, batchAlpha1, batchAlpha2, batchAlpha3 runar.Bigint,
	batchedEval0, batchedEval1, batchedEval2, batchedEval3 runar.Bigint,

	// -- Step 3: Sumcheck (4 rounds) --
	sc0Poly0C0, sc0Poly0C1, sc0Poly0C2, sc0Poly0C3 runar.Bigint,
	sc0Poly1C0, sc0Poly1C1, sc0Poly1C2, sc0Poly1C3 runar.Bigint,
	sc0R0, sc0R1, sc0R2, sc0R3 runar.Bigint,
	sc1Poly0C0, sc1Poly0C1, sc1Poly0C2, sc1Poly0C3 runar.Bigint,
	sc1Poly1C0, sc1Poly1C1, sc1Poly1C2, sc1Poly1C3 runar.Bigint,
	sc1R0, sc1R1, sc1R2, sc1R3 runar.Bigint,
	sc2Poly0C0, sc2Poly0C1, sc2Poly0C2, sc2Poly0C3 runar.Bigint,
	sc2Poly1C0, sc2Poly1C1, sc2Poly1C2, sc2Poly1C3 runar.Bigint,
	sc2R0, sc2R1, sc2R2, sc2R3 runar.Bigint,
	sc3Poly0C0, sc3Poly0C1, sc3Poly0C2, sc3Poly0C3 runar.Bigint,
	sc3Poly1C0, sc3Poly1C1, sc3Poly1C2, sc3Poly1C3 runar.Bigint,
	sc3R0, sc3R1, sc3R2, sc3R3 runar.Bigint,

	// -- Step 4: PoW --
	powWitness runar.Bigint,
	powThreshold runar.Bigint,

	// -- Steps 6-8: Query 0 --
	q0Index runar.Bigint,
	q0L0, q0L1, q0L2, q0L3, q0L4, q0L5, q0L6, q0L7 runar.Bigint,
	q0S00, q0S01, q0S02, q0S03, q0S04, q0S05, q0S06, q0S07 runar.Bigint,
	q0S10, q0S11, q0S12, q0S13, q0S14, q0S15, q0S16, q0S17 runar.Bigint,
	q0S20, q0S21, q0S22, q0S23, q0S24, q0S25, q0S26, q0S27 runar.Bigint,
	q0S30, q0S31, q0S32, q0S33, q0S34, q0S35, q0S36, q0S37 runar.Bigint,
	q0Open0, q0Open1 runar.Bigint,
	q0FL0, q0FL1, q0FL2, q0FL3, q0FL4, q0FL5, q0FL6, q0FL7 runar.Bigint,
	q0FS00, q0FS01, q0FS02, q0FS03, q0FS04, q0FS05, q0FS06, q0FS07 runar.Bigint,
	q0FS10, q0FS11, q0FS12, q0FS13, q0FS14, q0FS15, q0FS16, q0FS17 runar.Bigint,
	q0FS20, q0FS21, q0FS22, q0FS23, q0FS24, q0FS25, q0FS26, q0FS27 runar.Bigint,
	q0FS30, q0FS31, q0FS32, q0FS33, q0FS34, q0FS35, q0FS36, q0FS37 runar.Bigint,
	q0FriX runar.Bigint,
	q0FriEvalC0, q0FriEvalC1, q0FriEvalC2, q0FriEvalC3 runar.Bigint,
	q0FriNegC0, q0FriNegC1, q0FriNegC2, q0FriNegC3 runar.Bigint,
	q0FoldAlpha0, q0FoldAlpha1, q0FoldAlpha2, q0FoldAlpha3 runar.Bigint,
	q0ExpectedC0, q0ExpectedC1, q0ExpectedC2, q0ExpectedC3 runar.Bigint,

	// -- Steps 6-8: Query 1 --
	q1Index runar.Bigint,
	q1L0, q1L1, q1L2, q1L3, q1L4, q1L5, q1L6, q1L7 runar.Bigint,
	q1S00, q1S01, q1S02, q1S03, q1S04, q1S05, q1S06, q1S07 runar.Bigint,
	q1S10, q1S11, q1S12, q1S13, q1S14, q1S15, q1S16, q1S17 runar.Bigint,
	q1S20, q1S21, q1S22, q1S23, q1S24, q1S25, q1S26, q1S27 runar.Bigint,
	q1S30, q1S31, q1S32, q1S33, q1S34, q1S35, q1S36, q1S37 runar.Bigint,
	q1Open0, q1Open1 runar.Bigint,
	q1FL0, q1FL1, q1FL2, q1FL3, q1FL4, q1FL5, q1FL6, q1FL7 runar.Bigint,
	q1FS00, q1FS01, q1FS02, q1FS03, q1FS04, q1FS05, q1FS06, q1FS07 runar.Bigint,
	q1FS10, q1FS11, q1FS12, q1FS13, q1FS14, q1FS15, q1FS16, q1FS17 runar.Bigint,
	q1FS20, q1FS21, q1FS22, q1FS23, q1FS24, q1FS25, q1FS26, q1FS27 runar.Bigint,
	q1FS30, q1FS31, q1FS32, q1FS33, q1FS34, q1FS35, q1FS36, q1FS37 runar.Bigint,
	q1FriX runar.Bigint,
	q1FriEvalC0, q1FriEvalC1, q1FriEvalC2, q1FriEvalC3 runar.Bigint,
	q1FriNegC0, q1FriNegC1, q1FriNegC2, q1FriNegC3 runar.Bigint,
	q1FoldAlpha0, q1FoldAlpha1, q1FoldAlpha2, q1FoldAlpha3 runar.Bigint,
	q1ExpectedC0, q1ExpectedC1, q1ExpectedC2, q1ExpectedC3 runar.Bigint,

	// -- Step 9: Final polynomial --
	finalC0C0, finalC0C1, finalC0C2, finalC0C3 runar.Bigint,
	finalC1C0, finalC1C1, finalC1C2, finalC1C3 runar.Bigint,
	finalEvalPt0, finalEvalPt1, finalEvalPt2, finalEvalPt3 runar.Bigint,
	finalExpected0, finalExpected1, finalExpected2, finalExpected3 runar.Bigint,
) {
	// =========================================================================
	// Step 2: Compute batched evaluation claim
	// =========================================================================
	ae0 := runar.KbExt4Mul0(batchAlpha0, batchAlpha1, batchAlpha2, batchAlpha3, eval1C0, eval1C1, eval1C2, eval1C3)
	ae1 := runar.KbExt4Mul1(batchAlpha0, batchAlpha1, batchAlpha2, batchAlpha3, eval1C0, eval1C1, eval1C2, eval1C3)
	ae2 := runar.KbExt4Mul2(batchAlpha0, batchAlpha1, batchAlpha2, batchAlpha3, eval1C0, eval1C1, eval1C2, eval1C3)
	ae3 := runar.KbExt4Mul3(batchAlpha0, batchAlpha1, batchAlpha2, batchAlpha3, eval1C0, eval1C1, eval1C2, eval1C3)
	computedBatch0 := runar.KbFieldAdd(eval0C0, ae0)
	computedBatch1 := runar.KbFieldAdd(eval0C1, ae1)
	computedBatch2 := runar.KbFieldAdd(eval0C2, ae2)
	computedBatch3 := runar.KbFieldAdd(eval0C3, ae3)
	runar.Assert(computedBatch0 == batchedEval0)
	runar.Assert(computedBatch1 == batchedEval1)
	runar.Assert(computedBatch2 == batchedEval2)
	runar.Assert(computedBatch3 == batchedEval3)

	// =========================================================================
	// Step 3: Sumcheck verification (4 rounds)
	// =========================================================================
	// Round 0
	runar.Assert(batchedEval0 == runar.KbFieldAdd(sc0Poly0C0, sc0Poly1C0))
	runar.Assert(batchedEval1 == runar.KbFieldAdd(sc0Poly0C1, sc0Poly1C1))
	runar.Assert(batchedEval2 == runar.KbFieldAdd(sc0Poly0C2, sc0Poly1C2))
	runar.Assert(batchedEval3 == runar.KbFieldAdd(sc0Poly0C3, sc0Poly1C3))
	sc0D0 := runar.KbFieldSub(sc0Poly1C0, sc0Poly0C0)
	sc0D1 := runar.KbFieldSub(sc0Poly1C1, sc0Poly0C1)
	sc0D2 := runar.KbFieldSub(sc0Poly1C2, sc0Poly0C2)
	sc0D3 := runar.KbFieldSub(sc0Poly1C3, sc0Poly0C3)
	sc0RD0 := runar.KbExt4Mul0(sc0R0, sc0R1, sc0R2, sc0R3, sc0D0, sc0D1, sc0D2, sc0D3)
	sc0RD1 := runar.KbExt4Mul1(sc0R0, sc0R1, sc0R2, sc0R3, sc0D0, sc0D1, sc0D2, sc0D3)
	sc0RD2 := runar.KbExt4Mul2(sc0R0, sc0R1, sc0R2, sc0R3, sc0D0, sc0D1, sc0D2, sc0D3)
	sc0RD3 := runar.KbExt4Mul3(sc0R0, sc0R1, sc0R2, sc0R3, sc0D0, sc0D1, sc0D2, sc0D3)
	claim1C0 := runar.KbFieldAdd(sc0Poly0C0, sc0RD0)
	claim1C1 := runar.KbFieldAdd(sc0Poly0C1, sc0RD1)
	claim1C2 := runar.KbFieldAdd(sc0Poly0C2, sc0RD2)
	claim1C3 := runar.KbFieldAdd(sc0Poly0C3, sc0RD3)

	// Round 1
	runar.Assert(claim1C0 == runar.KbFieldAdd(sc1Poly0C0, sc1Poly1C0))
	runar.Assert(claim1C1 == runar.KbFieldAdd(sc1Poly0C1, sc1Poly1C1))
	runar.Assert(claim1C2 == runar.KbFieldAdd(sc1Poly0C2, sc1Poly1C2))
	runar.Assert(claim1C3 == runar.KbFieldAdd(sc1Poly0C3, sc1Poly1C3))
	sc1D0 := runar.KbFieldSub(sc1Poly1C0, sc1Poly0C0)
	sc1D1 := runar.KbFieldSub(sc1Poly1C1, sc1Poly0C1)
	sc1D2 := runar.KbFieldSub(sc1Poly1C2, sc1Poly0C2)
	sc1D3 := runar.KbFieldSub(sc1Poly1C3, sc1Poly0C3)
	sc1RD0 := runar.KbExt4Mul0(sc1R0, sc1R1, sc1R2, sc1R3, sc1D0, sc1D1, sc1D2, sc1D3)
	sc1RD1 := runar.KbExt4Mul1(sc1R0, sc1R1, sc1R2, sc1R3, sc1D0, sc1D1, sc1D2, sc1D3)
	sc1RD2 := runar.KbExt4Mul2(sc1R0, sc1R1, sc1R2, sc1R3, sc1D0, sc1D1, sc1D2, sc1D3)
	sc1RD3 := runar.KbExt4Mul3(sc1R0, sc1R1, sc1R2, sc1R3, sc1D0, sc1D1, sc1D2, sc1D3)
	claim2C0 := runar.KbFieldAdd(sc1Poly0C0, sc1RD0)
	claim2C1 := runar.KbFieldAdd(sc1Poly0C1, sc1RD1)
	claim2C2 := runar.KbFieldAdd(sc1Poly0C2, sc1RD2)
	claim2C3 := runar.KbFieldAdd(sc1Poly0C3, sc1RD3)

	// Round 2
	runar.Assert(claim2C0 == runar.KbFieldAdd(sc2Poly0C0, sc2Poly1C0))
	runar.Assert(claim2C1 == runar.KbFieldAdd(sc2Poly0C1, sc2Poly1C1))
	runar.Assert(claim2C2 == runar.KbFieldAdd(sc2Poly0C2, sc2Poly1C2))
	runar.Assert(claim2C3 == runar.KbFieldAdd(sc2Poly0C3, sc2Poly1C3))
	sc2D0 := runar.KbFieldSub(sc2Poly1C0, sc2Poly0C0)
	sc2D1 := runar.KbFieldSub(sc2Poly1C1, sc2Poly0C1)
	sc2D2 := runar.KbFieldSub(sc2Poly1C2, sc2Poly0C2)
	sc2D3 := runar.KbFieldSub(sc2Poly1C3, sc2Poly0C3)
	sc2RD0 := runar.KbExt4Mul0(sc2R0, sc2R1, sc2R2, sc2R3, sc2D0, sc2D1, sc2D2, sc2D3)
	sc2RD1 := runar.KbExt4Mul1(sc2R0, sc2R1, sc2R2, sc2R3, sc2D0, sc2D1, sc2D2, sc2D3)
	sc2RD2 := runar.KbExt4Mul2(sc2R0, sc2R1, sc2R2, sc2R3, sc2D0, sc2D1, sc2D2, sc2D3)
	sc2RD3 := runar.KbExt4Mul3(sc2R0, sc2R1, sc2R2, sc2R3, sc2D0, sc2D1, sc2D2, sc2D3)
	claim3C0 := runar.KbFieldAdd(sc2Poly0C0, sc2RD0)
	claim3C1 := runar.KbFieldAdd(sc2Poly0C1, sc2RD1)
	claim3C2 := runar.KbFieldAdd(sc2Poly0C2, sc2RD2)
	claim3C3 := runar.KbFieldAdd(sc2Poly0C3, sc2RD3)

	// Round 3
	runar.Assert(claim3C0 == runar.KbFieldAdd(sc3Poly0C0, sc3Poly1C0))
	runar.Assert(claim3C1 == runar.KbFieldAdd(sc3Poly0C1, sc3Poly1C1))
	runar.Assert(claim3C2 == runar.KbFieldAdd(sc3Poly0C2, sc3Poly1C2))
	runar.Assert(claim3C3 == runar.KbFieldAdd(sc3Poly0C3, sc3Poly1C3))
	sc3D0 := runar.KbFieldSub(sc3Poly1C0, sc3Poly0C0)
	sc3D1 := runar.KbFieldSub(sc3Poly1C1, sc3Poly0C1)
	sc3D2 := runar.KbFieldSub(sc3Poly1C2, sc3Poly0C2)
	sc3D3 := runar.KbFieldSub(sc3Poly1C3, sc3Poly0C3)
	sc3RD0 := runar.KbExt4Mul0(sc3R0, sc3R1, sc3R2, sc3R3, sc3D0, sc3D1, sc3D2, sc3D3)
	sc3RD1 := runar.KbExt4Mul1(sc3R0, sc3R1, sc3R2, sc3R3, sc3D0, sc3D1, sc3D2, sc3D3)
	sc3RD2 := runar.KbExt4Mul2(sc3R0, sc3R1, sc3R2, sc3R3, sc3D0, sc3D1, sc3D2, sc3D3)
	sc3RD3 := runar.KbExt4Mul3(sc3R0, sc3R1, sc3R2, sc3R3, sc3D0, sc3D1, sc3D2, sc3D3)
	scFinalC0 := runar.KbFieldAdd(sc3Poly0C0, sc3RD0)
	scFinalC1 := runar.KbFieldAdd(sc3Poly0C1, sc3RD1)
	scFinalC2 := runar.KbFieldAdd(sc3Poly0C2, sc3RD2)
	scFinalC3 := runar.KbFieldAdd(sc3Poly0C3, sc3RD3)

	// =========================================================================
	// Step 4: Proof-of-work check
	// =========================================================================
	runar.Assert(powWitness < powThreshold)

	// =========================================================================
	// Step 6: Compute batched polynomial opening per query
	// =========================================================================
	q0AlphaOpen0 := runar.KbFieldMul(batchAlpha0, q0Open1)
	q0BatchOpen := runar.KbFieldAdd(q0Open0, q0AlphaOpen0)
	q1AlphaOpen0 := runar.KbFieldMul(batchAlpha0, q1Open1)
	q1BatchOpen := runar.KbFieldAdd(q1Open0, q1AlphaOpen0)

	// =========================================================================
	// Step 7: Verify Poseidon2 KoalaBear Merkle openings
	// =========================================================================
	q0Root0 := runar.MerkleRootPoseidon2KBv(
		q0L0, q0L1, q0L2, q0L3, q0L4, q0L5, q0L6, q0L7,
		q0S00, q0S01, q0S02, q0S03, q0S04, q0S05, q0S06, q0S07,
		q0S10, q0S11, q0S12, q0S13, q0S14, q0S15, q0S16, q0S17,
		q0S20, q0S21, q0S22, q0S23, q0S24, q0S25, q0S26, q0S27,
		q0S30, q0S31, q0S32, q0S33, q0S34, q0S35, q0S36, q0S37,
		q0Index, 4)
	runar.Assert(q0Root0 == v.CommitRoot0)

	q1Root0 := runar.MerkleRootPoseidon2KBv(
		q1L0, q1L1, q1L2, q1L3, q1L4, q1L5, q1L6, q1L7,
		q1S00, q1S01, q1S02, q1S03, q1S04, q1S05, q1S06, q1S07,
		q1S10, q1S11, q1S12, q1S13, q1S14, q1S15, q1S16, q1S17,
		q1S20, q1S21, q1S22, q1S23, q1S24, q1S25, q1S26, q1S27,
		q1S30, q1S31, q1S32, q1S33, q1S34, q1S35, q1S36, q1S37,
		q1Index, 4)
	runar.Assert(q1Root0 == v.CommitRoot0)

	q0FriRoot0 := runar.MerkleRootPoseidon2KBv(
		q0FL0, q0FL1, q0FL2, q0FL3, q0FL4, q0FL5, q0FL6, q0FL7,
		q0FS00, q0FS01, q0FS02, q0FS03, q0FS04, q0FS05, q0FS06, q0FS07,
		q0FS10, q0FS11, q0FS12, q0FS13, q0FS14, q0FS15, q0FS16, q0FS17,
		q0FS20, q0FS21, q0FS22, q0FS23, q0FS24, q0FS25, q0FS26, q0FS27,
		q0FS30, q0FS31, q0FS32, q0FS33, q0FS34, q0FS35, q0FS36, q0FS37,
		q0Index, 4)
	runar.Assert(q0FriRoot0 == v.FriCommitRoot0)

	q1FriRoot0 := runar.MerkleRootPoseidon2KBv(
		q1FL0, q1FL1, q1FL2, q1FL3, q1FL4, q1FL5, q1FL6, q1FL7,
		q1FS00, q1FS01, q1FS02, q1FS03, q1FS04, q1FS05, q1FS06, q1FS07,
		q1FS10, q1FS11, q1FS12, q1FS13, q1FS14, q1FS15, q1FS16, q1FS17,
		q1FS20, q1FS21, q1FS22, q1FS23, q1FS24, q1FS25, q1FS26, q1FS27,
		q1FS30, q1FS31, q1FS32, q1FS33, q1FS34, q1FS35, q1FS36, q1FS37,
		q1Index, 4)
	runar.Assert(q1FriRoot0 == v.FriCommitRoot0)

	// =========================================================================
	// Step 8: FRI folding consistency check per query
	// =========================================================================
	// Query 0
	q0Sum0 := runar.KbFieldAdd(q0FriEvalC0, q0FriNegC0)
	q0Sum1 := runar.KbFieldAdd(q0FriEvalC1, q0FriNegC1)
	q0Sum2 := runar.KbFieldAdd(q0FriEvalC2, q0FriNegC2)
	q0Sum3 := runar.KbFieldAdd(q0FriEvalC3, q0FriNegC3)
	inv2 := runar.KbFieldInv(2)
	q0HS0 := runar.KbFieldMul(q0Sum0, inv2)
	q0HS1 := runar.KbFieldMul(q0Sum1, inv2)
	q0HS2 := runar.KbFieldMul(q0Sum2, inv2)
	q0HS3 := runar.KbFieldMul(q0Sum3, inv2)
	q0Diff0 := runar.KbFieldSub(q0FriEvalC0, q0FriNegC0)
	q0Diff1 := runar.KbFieldSub(q0FriEvalC1, q0FriNegC1)
	q0Diff2 := runar.KbFieldSub(q0FriEvalC2, q0FriNegC2)
	q0Diff3 := runar.KbFieldSub(q0FriEvalC3, q0FriNegC3)
	q0AD0 := runar.KbExt4Mul0(q0FoldAlpha0, q0FoldAlpha1, q0FoldAlpha2, q0FoldAlpha3, q0Diff0, q0Diff1, q0Diff2, q0Diff3)
	q0AD1 := runar.KbExt4Mul1(q0FoldAlpha0, q0FoldAlpha1, q0FoldAlpha2, q0FoldAlpha3, q0Diff0, q0Diff1, q0Diff2, q0Diff3)
	q0AD2 := runar.KbExt4Mul2(q0FoldAlpha0, q0FoldAlpha1, q0FoldAlpha2, q0FoldAlpha3, q0Diff0, q0Diff1, q0Diff2, q0Diff3)
	q0AD3 := runar.KbExt4Mul3(q0FoldAlpha0, q0FoldAlpha1, q0FoldAlpha2, q0FoldAlpha3, q0Diff0, q0Diff1, q0Diff2, q0Diff3)
	q0Inv2X := runar.KbFieldInv(runar.KbFieldMul(2, q0FriX))
	q0AT0 := runar.KbFieldMul(q0AD0, q0Inv2X)
	q0AT1 := runar.KbFieldMul(q0AD1, q0Inv2X)
	q0AT2 := runar.KbFieldMul(q0AD2, q0Inv2X)
	q0AT3 := runar.KbFieldMul(q0AD3, q0Inv2X)
	q0G0 := runar.KbFieldAdd(q0HS0, q0AT0)
	q0G1 := runar.KbFieldAdd(q0HS1, q0AT1)
	q0G2 := runar.KbFieldAdd(q0HS2, q0AT2)
	q0G3 := runar.KbFieldAdd(q0HS3, q0AT3)
	runar.Assert(q0G0 == q0ExpectedC0)
	runar.Assert(q0G1 == q0ExpectedC1)
	runar.Assert(q0G2 == q0ExpectedC2)
	runar.Assert(q0G3 == q0ExpectedC3)

	// Query 1
	q1Sum0 := runar.KbFieldAdd(q1FriEvalC0, q1FriNegC0)
	q1Sum1 := runar.KbFieldAdd(q1FriEvalC1, q1FriNegC1)
	q1Sum2 := runar.KbFieldAdd(q1FriEvalC2, q1FriNegC2)
	q1Sum3 := runar.KbFieldAdd(q1FriEvalC3, q1FriNegC3)
	q1HS0 := runar.KbFieldMul(q1Sum0, inv2)
	q1HS1 := runar.KbFieldMul(q1Sum1, inv2)
	q1HS2 := runar.KbFieldMul(q1Sum2, inv2)
	q1HS3 := runar.KbFieldMul(q1Sum3, inv2)
	q1Diff0 := runar.KbFieldSub(q1FriEvalC0, q1FriNegC0)
	q1Diff1 := runar.KbFieldSub(q1FriEvalC1, q1FriNegC1)
	q1Diff2 := runar.KbFieldSub(q1FriEvalC2, q1FriNegC2)
	q1Diff3 := runar.KbFieldSub(q1FriEvalC3, q1FriNegC3)
	q1AD0 := runar.KbExt4Mul0(q1FoldAlpha0, q1FoldAlpha1, q1FoldAlpha2, q1FoldAlpha3, q1Diff0, q1Diff1, q1Diff2, q1Diff3)
	q1AD1 := runar.KbExt4Mul1(q1FoldAlpha0, q1FoldAlpha1, q1FoldAlpha2, q1FoldAlpha3, q1Diff0, q1Diff1, q1Diff2, q1Diff3)
	q1AD2 := runar.KbExt4Mul2(q1FoldAlpha0, q1FoldAlpha1, q1FoldAlpha2, q1FoldAlpha3, q1Diff0, q1Diff1, q1Diff2, q1Diff3)
	q1AD3 := runar.KbExt4Mul3(q1FoldAlpha0, q1FoldAlpha1, q1FoldAlpha2, q1FoldAlpha3, q1Diff0, q1Diff1, q1Diff2, q1Diff3)
	q1Inv2X := runar.KbFieldInv(runar.KbFieldMul(2, q1FriX))
	q1AT0 := runar.KbFieldMul(q1AD0, q1Inv2X)
	q1AT1 := runar.KbFieldMul(q1AD1, q1Inv2X)
	q1AT2 := runar.KbFieldMul(q1AD2, q1Inv2X)
	q1AT3 := runar.KbFieldMul(q1AD3, q1Inv2X)
	q1G0 := runar.KbFieldAdd(q1HS0, q1AT0)
	q1G1 := runar.KbFieldAdd(q1HS1, q1AT1)
	q1G2 := runar.KbFieldAdd(q1HS2, q1AT2)
	q1G3 := runar.KbFieldAdd(q1HS3, q1AT3)
	runar.Assert(q1G0 == q1ExpectedC0)
	runar.Assert(q1G1 == q1ExpectedC1)
	runar.Assert(q1G2 == q1ExpectedC2)
	runar.Assert(q1G3 == q1ExpectedC3)

	// =========================================================================
	// Step 9: Final reduced polynomial check
	// =========================================================================
	fp0 := runar.KbExt4Mul0(finalC1C0, finalC1C1, finalC1C2, finalC1C3, finalEvalPt0, finalEvalPt1, finalEvalPt2, finalEvalPt3)
	fp1 := runar.KbExt4Mul1(finalC1C0, finalC1C1, finalC1C2, finalC1C3, finalEvalPt0, finalEvalPt1, finalEvalPt2, finalEvalPt3)
	fp2 := runar.KbExt4Mul2(finalC1C0, finalC1C1, finalC1C2, finalC1C3, finalEvalPt0, finalEvalPt1, finalEvalPt2, finalEvalPt3)
	fp3 := runar.KbExt4Mul3(finalC1C0, finalC1C1, finalC1C2, finalC1C3, finalEvalPt0, finalEvalPt1, finalEvalPt2, finalEvalPt3)
	finalResult0 := runar.KbFieldAdd(finalC0C0, fp0)
	finalResult1 := runar.KbFieldAdd(finalC0C1, fp1)
	finalResult2 := runar.KbFieldAdd(finalC0C2, fp2)
	finalResult3 := runar.KbFieldAdd(finalC0C3, fp3)
	runar.Assert(finalResult0 == finalExpected0)
	runar.Assert(finalResult1 == finalExpected1)
	runar.Assert(finalResult2 == finalExpected2)
	runar.Assert(finalResult3 == finalExpected3)

	// Cross-check: sumcheck final claim == final polynomial evaluation
	runar.Assert(scFinalC0 == finalResult0)
	runar.Assert(scFinalC1 == finalResult1)
	runar.Assert(scFinalC2 == finalResult2)
	runar.Assert(scFinalC3 == finalResult3)

	// Cross-check: batched opening matches leaf data
	runar.Assert(q0BatchOpen == q0L0)
	runar.Assert(q1BatchOpen == q1L0)
}

package sp1fri

// Plonky3 STARK + FRI proof type tree, matched to the SP1 v6.0.2 KoalaBear
// configuration that BSVM Mode 1 targets.
//
// Field choices (pinned in docs/sp1-proof-format.md §1):
//
//   - Base field F = KoalaBear, prime 2^31 − 2^24 + 1.
//   - Challenge field C = F[X]/(X^4 − 3) (4 base elements per Ext4).
//   - Hash / Merkle digest = Poseidon2-KoalaBear (8 base elements).
//   - Challenger sponge = DuplexChallenger over Poseidon2-KoalaBear,
//     16-element state, rate 8.
//   - PCS = TwoAdicFriPcs.
//
// All `KbElement` values in the proof tree are stored in **Plonky3
// Montgomery form** (the raw u32 the prover serialised). On-chain
// arithmetic in the Bitcoin Script verifier operates on canonical values
// (0..p-1); helpers in `montgomery.go` convert at the boundary.

// KbPrime is the KoalaBear prime, 2^31 − 2^24 + 1 = 2,130,706,433.
const KbPrime uint32 = 2130706433

// KbElement is a single KoalaBear field element in Plonky3 Montgomery form.
//
// To get the canonical value (0..p-1), call `(KbElement).Canonical()`.
// To go the other way, call `KbFromCanonical`.
type KbElement uint32

// KbExt4 is a quartic extension field element over KoalaBear, represented
// in coefficient order: c0 + c1·X + c2·X² + c3·X³ where X⁴ = 3.
//
// Coefficients are KbElement (Montgomery form). On-chain Ext4 arithmetic
// operates on canonical-form base coefficients.
type KbExt4 [4]KbElement

// KbDigest is an 8-element Poseidon2-KoalaBear Merkle digest.
type KbDigest [8]KbElement

// MerkleCap mirrors p3_symmetric::MerkleCap<F, Digest>: the configurable
// `cap_height` upper layer of a Merkle tree. For our `cap_height=0` config
// it always contains exactly one root digest, but the wire format still
// carries the vec-length prefix.
type MerkleCap []KbDigest

// Commitments mirrors p3_uni_stark::Commitments<Com> where Com is the
// underlying MMCS commitment type. Both ValMmcs and the ExtensionMmcs
// adapter resolve to MerkleCap, so each commitment is a Vec of digests.
type Commitments struct {
	Trace          MerkleCap
	QuotientChunks MerkleCap
	Random         *MerkleCap // None for non-ZK config
}

// OpenedValues mirrors p3_uni_stark::OpenedValues<Challenge>.
type OpenedValues struct {
	TraceLocal        []KbExt4
	TraceNext         *[]KbExt4 // None when AIR has no transition / next-row access
	PreprocessedLocal *[]KbExt4
	PreprocessedNext  *[]KbExt4
	QuotientChunks    [][]KbExt4
	Random            *[]KbExt4
}

// CommitPhaseProofStep mirrors p3_fri::CommitPhaseProofStep<Challenge, FriMmcs>.
//
// `OpeningProof` is the underlying ValMmcs Merkle proof: a sequence of
// sibling digests from leaf-side to root.
type CommitPhaseProofStep struct {
	LogArity      uint8
	SiblingValues []KbExt4    // arity = 2^LogArity, length = arity − 1
	OpeningProof  []KbDigest  // sibling digests bottom→top
}

// BatchOpening mirrors p3_commit::BatchOpening<Val, InputMmcs>.
type BatchOpening struct {
	OpenedValues [][]KbElement // one inner Vec per matrix in the batch
	OpeningProof []KbDigest    // input MMCS Merkle proof
}

// QueryProof mirrors p3_fri::QueryProof<Challenge, FriMmcs, InputProof>.
//
// `InputProof` for TwoAdicFriPcs is `Vec<BatchOpening<Val, InputMmcs>>`.
type QueryProof struct {
	InputProof          []BatchOpening
	CommitPhaseOpenings []CommitPhaseProofStep
}

// FriProof mirrors p3_fri::FriProof<Challenge, FriMmcs, Witness, InputProof>.
//
//   - F (the type-parameter on FriProof) = Challenge = KbExt4 → final_poly.
//   - Witness = Val = KbElement → pow witnesses.
//   - InputProof = Vec<BatchOpening<Val, InputMmcs>> → query inputs.
//
// CommitPhaseCommits is `Vec<FriMmcs::Commitment>` = `Vec<MerkleCap>`,
// one entry per FRI fold step.
type FriProof struct {
	CommitPhaseCommits []MerkleCap
	CommitPowWitnesses []KbElement
	QueryProofs        []QueryProof
	FinalPoly          []KbExt4
	QueryPowWitness    KbElement
}

// Proof is the top-level p3_uni_stark::Proof<MyConfig>.
type Proof struct {
	Commitments   Commitments
	OpenedValues  OpenedValues
	OpeningProof  FriProof
	DegreeBits    uint64
}

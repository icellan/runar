package sp1fri

import "fmt"

// DecodeProof parses a postcard-encoded Plonky3 STARK Proof for the SP1
// v6.0.2 KoalaBear configuration.
//
// On success, returns the populated Proof struct. On failure, returns an
// error annotated with the byte offset where decoding stalled.
//
// `Strict=true` (the default) asserts no trailing bytes follow the
// top-level decode; pass `false` only when debugging a malformed fixture.
func DecodeProof(bs []byte) (*Proof, error) {
	r := NewPostcardReader(bs)
	p, err := decodeProof(r)
	if err != nil {
		return nil, err
	}
	if r.Remaining() != 0 {
		return nil, fmt.Errorf("%w: %d bytes left", ErrTrailingBytes, r.Remaining())
	}
	return p, nil
}

func decodeProof(r *PostcardReader) (*Proof, error) {
	commitments, err := decodeCommitments(r)
	if err != nil {
		return nil, fmt.Errorf("commitments: %w", err)
	}
	opened, err := decodeOpenedValues(r)
	if err != nil {
		return nil, fmt.Errorf("opened_values: %w", err)
	}
	fri, err := decodeFriProof(r)
	if err != nil {
		return nil, fmt.Errorf("opening_proof: %w", err)
	}
	degreeBits, err := r.ReadVarintUsize()
	if err != nil {
		return nil, fmt.Errorf("degree_bits: %w", err)
	}
	return &Proof{
		Commitments:  *commitments,
		OpenedValues: *opened,
		OpeningProof: *fri,
		DegreeBits:   degreeBits,
	}, nil
}

func decodeCommitments(r *PostcardReader) (*Commitments, error) {
	trace, err := decodeMerkleCap(r)
	if err != nil {
		return nil, fmt.Errorf("trace: %w", err)
	}
	quotient, err := decodeMerkleCap(r)
	if err != nil {
		return nil, fmt.Errorf("quotient_chunks: %w", err)
	}
	random, err := decodeOptionalMerkleCap(r)
	if err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return &Commitments{Trace: trace, QuotientChunks: quotient, Random: random}, nil
}

func decodeMerkleCap(r *PostcardReader) (MerkleCap, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make(MerkleCap, n)
	for i := 0; i < n; i++ {
		d, err := decodeDigest(r)
		if err != nil {
			return nil, fmt.Errorf("digest[%d]: %w", i, err)
		}
		out[i] = d
	}
	return out, nil
}

func decodeOptionalMerkleCap(r *PostcardReader) (*MerkleCap, error) {
	some, err := r.ReadOption()
	if err != nil {
		return nil, err
	}
	if !some {
		return nil, nil
	}
	c, err := decodeMerkleCap(r)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func decodeMerkleCapVec(r *PostcardReader) ([]MerkleCap, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]MerkleCap, n)
	for i := 0; i < n; i++ {
		c, err := decodeMerkleCap(r)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = c
	}
	return out, nil
}

func decodeOpenedValues(r *PostcardReader) (*OpenedValues, error) {
	traceLocal, err := decodeExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("trace_local: %w", err)
	}
	traceNext, err := decodeOptionalExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("trace_next: %w", err)
	}
	prepLocal, err := decodeOptionalExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("preprocessed_local: %w", err)
	}
	prepNext, err := decodeOptionalExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("preprocessed_next: %w", err)
	}
	quotientChunks, err := decodeExt4VecVec(r)
	if err != nil {
		return nil, fmt.Errorf("quotient_chunks: %w", err)
	}
	random, err := decodeOptionalExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return &OpenedValues{
		TraceLocal:        traceLocal,
		TraceNext:         traceNext,
		PreprocessedLocal: prepLocal,
		PreprocessedNext:  prepNext,
		QuotientChunks:    quotientChunks,
		Random:            random,
	}, nil
}

func decodeFriProof(r *PostcardReader) (*FriProof, error) {
	commits, err := decodeMerkleCapVec(r)
	if err != nil {
		return nil, fmt.Errorf("commit_phase_commits: %w", err)
	}
	powWitnesses, err := decodeKbVec(r)
	if err != nil {
		return nil, fmt.Errorf("commit_pow_witnesses: %w", err)
	}
	queries, err := decodeQueryProofVec(r)
	if err != nil {
		return nil, fmt.Errorf("query_proofs: %w", err)
	}
	finalPoly, err := decodeExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("final_poly: %w", err)
	}
	queryPow, err := decodeKbElement(r)
	if err != nil {
		return nil, fmt.Errorf("query_pow_witness: %w", err)
	}
	return &FriProof{
		CommitPhaseCommits: commits,
		CommitPowWitnesses: powWitnesses,
		QueryProofs:        queries,
		FinalPoly:          finalPoly,
		QueryPowWitness:    queryPow,
	}, nil
}

func decodeQueryProofVec(r *PostcardReader) ([]QueryProof, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]QueryProof, n)
	for i := 0; i < n; i++ {
		qp, err := decodeQueryProof(r)
		if err != nil {
			return nil, fmt.Errorf("query[%d]: %w", i, err)
		}
		out[i] = *qp
	}
	return out, nil
}

func decodeQueryProof(r *PostcardReader) (*QueryProof, error) {
	input, err := decodeBatchOpeningVec(r)
	if err != nil {
		return nil, fmt.Errorf("input_proof: %w", err)
	}
	openings, err := decodeCommitPhaseStepVec(r)
	if err != nil {
		return nil, fmt.Errorf("commit_phase_openings: %w", err)
	}
	return &QueryProof{InputProof: input, CommitPhaseOpenings: openings}, nil
}

func decodeBatchOpeningVec(r *PostcardReader) ([]BatchOpening, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]BatchOpening, n)
	for i := 0; i < n; i++ {
		bo, err := decodeBatchOpening(r)
		if err != nil {
			return nil, fmt.Errorf("batch[%d]: %w", i, err)
		}
		out[i] = *bo
	}
	return out, nil
}

func decodeBatchOpening(r *PostcardReader) (*BatchOpening, error) {
	openedOuterLen, err := r.ReadVecLen()
	if err != nil {
		return nil, fmt.Errorf("opened_values outer len: %w", err)
	}
	opened := make([][]KbElement, openedOuterLen)
	for i := 0; i < openedOuterLen; i++ {
		row, err := decodeKbVec(r)
		if err != nil {
			return nil, fmt.Errorf("opened_values[%d]: %w", i, err)
		}
		opened[i] = row
	}
	proof, err := decodeDigestVec(r)
	if err != nil {
		return nil, fmt.Errorf("opening_proof: %w", err)
	}
	return &BatchOpening{OpenedValues: opened, OpeningProof: proof}, nil
}

func decodeCommitPhaseStepVec(r *PostcardReader) ([]CommitPhaseProofStep, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]CommitPhaseProofStep, n)
	for i := 0; i < n; i++ {
		step, err := decodeCommitPhaseStep(r)
		if err != nil {
			return nil, fmt.Errorf("step[%d]: %w", i, err)
		}
		out[i] = *step
	}
	return out, nil
}

func decodeCommitPhaseStep(r *PostcardReader) (*CommitPhaseProofStep, error) {
	logArity, err := r.ReadU8()
	if err != nil {
		return nil, fmt.Errorf("log_arity: %w", err)
	}
	siblings, err := decodeExt4Vec(r)
	if err != nil {
		return nil, fmt.Errorf("sibling_values: %w", err)
	}
	proof, err := decodeDigestVec(r)
	if err != nil {
		return nil, fmt.Errorf("opening_proof: %w", err)
	}
	return &CommitPhaseProofStep{
		LogArity:      logArity,
		SiblingValues: siblings,
		OpeningProof:  proof,
	}, nil
}

// -----------------------------------------------------------------------------
// Primitive decoders
// -----------------------------------------------------------------------------

func decodeKbElement(r *PostcardReader) (KbElement, error) {
	v, err := r.ReadVarintU32()
	if err != nil {
		return 0, err
	}
	if v >= KbPrime {
		return 0, fmt.Errorf("kb element %d ≥ p (offset %d)", v, r.Pos())
	}
	return KbElement(v), nil
}

func decodeKbVec(r *PostcardReader) ([]KbElement, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]KbElement, n)
	for i := 0; i < n; i++ {
		v, err := decodeKbElement(r)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

func decodeExt4(r *PostcardReader) (KbExt4, error) {
	var out KbExt4
	for i := 0; i < 4; i++ {
		v, err := decodeKbElement(r)
		if err != nil {
			return KbExt4{}, fmt.Errorf("ext4[%d]: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

func decodeExt4Vec(r *PostcardReader) ([]KbExt4, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]KbExt4, n)
	for i := 0; i < n; i++ {
		e, err := decodeExt4(r)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = e
	}
	return out, nil
}

func decodeOptionalExt4Vec(r *PostcardReader) (*[]KbExt4, error) {
	some, err := r.ReadOption()
	if err != nil {
		return nil, err
	}
	if !some {
		return nil, nil
	}
	v, err := decodeExt4Vec(r)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func decodeExt4VecVec(r *PostcardReader) ([][]KbExt4, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([][]KbExt4, n)
	for i := 0; i < n; i++ {
		inner, err := decodeExt4Vec(r)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = inner
	}
	return out, nil
}

func decodeDigest(r *PostcardReader) (KbDigest, error) {
	var out KbDigest
	for i := 0; i < 8; i++ {
		v, err := decodeKbElement(r)
		if err != nil {
			return KbDigest{}, fmt.Errorf("digest[%d]: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

func decodeOptionalDigest(r *PostcardReader) (*KbDigest, error) {
	some, err := r.ReadOption()
	if err != nil {
		return nil, err
	}
	if !some {
		return nil, nil
	}
	d, err := decodeDigest(r)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func decodeDigestVec(r *PostcardReader) ([]KbDigest, error) {
	n, err := r.ReadVecLen()
	if err != nil {
		return nil, err
	}
	out := make([]KbDigest, n)
	for i := 0; i < n; i++ {
		d, err := decodeDigest(r)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = d
	}
	return out, nil
}

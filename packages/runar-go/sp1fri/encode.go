package sp1fri

import (
	"bytes"
	"fmt"
)

// EncodeProof emits a Plonky3 STARK Proof in postcard wire format,
// matching DecodeProof. Used by round-trip tests to validate the decoder
// against a fixture without depending on a Rust postcard binding.
func EncodeProof(p *Proof) ([]byte, error) {
	var buf bytes.Buffer
	w := NewPostcardWriter(&buf)
	if err := encodeCommitments(w, &p.Commitments); err != nil {
		return nil, fmt.Errorf("commitments: %w", err)
	}
	if err := encodeOpenedValues(w, &p.OpenedValues); err != nil {
		return nil, fmt.Errorf("opened_values: %w", err)
	}
	if err := encodeFriProof(w, &p.OpeningProof); err != nil {
		return nil, fmt.Errorf("opening_proof: %w", err)
	}
	if err := w.WriteVarintUsize(p.DegreeBits); err != nil {
		return nil, fmt.Errorf("degree_bits: %w", err)
	}
	return buf.Bytes(), nil
}

func encodeCommitments(w *PostcardWriter, c *Commitments) error {
	if err := encodeMerkleCap(w, c.Trace); err != nil {
		return fmt.Errorf("trace: %w", err)
	}
	if err := encodeMerkleCap(w, c.QuotientChunks); err != nil {
		return fmt.Errorf("quotient_chunks: %w", err)
	}
	return encodeOptionalMerkleCap(w, c.Random)
}

func encodeMerkleCap(w *PostcardWriter, c MerkleCap) error {
	if err := w.WriteVecLen(len(c)); err != nil {
		return err
	}
	for _, d := range c {
		if err := encodeDigest(w, d); err != nil {
			return err
		}
	}
	return nil
}

func encodeOptionalMerkleCap(w *PostcardWriter, p *MerkleCap) error {
	if p == nil {
		return w.WriteOption(false)
	}
	if err := w.WriteOption(true); err != nil {
		return err
	}
	return encodeMerkleCap(w, *p)
}

func encodeMerkleCapVec(w *PostcardWriter, cs []MerkleCap) error {
	if err := w.WriteVecLen(len(cs)); err != nil {
		return err
	}
	for _, c := range cs {
		if err := encodeMerkleCap(w, c); err != nil {
			return err
		}
	}
	return nil
}

func encodeOpenedValues(w *PostcardWriter, v *OpenedValues) error {
	if err := encodeExt4Vec(w, v.TraceLocal); err != nil {
		return fmt.Errorf("trace_local: %w", err)
	}
	if err := encodeOptionalExt4Vec(w, v.TraceNext); err != nil {
		return fmt.Errorf("trace_next: %w", err)
	}
	if err := encodeOptionalExt4Vec(w, v.PreprocessedLocal); err != nil {
		return fmt.Errorf("preprocessed_local: %w", err)
	}
	if err := encodeOptionalExt4Vec(w, v.PreprocessedNext); err != nil {
		return fmt.Errorf("preprocessed_next: %w", err)
	}
	if err := encodeExt4VecVec(w, v.QuotientChunks); err != nil {
		return fmt.Errorf("quotient_chunks: %w", err)
	}
	return encodeOptionalExt4Vec(w, v.Random)
}

func encodeFriProof(w *PostcardWriter, f *FriProof) error {
	if err := encodeMerkleCapVec(w, f.CommitPhaseCommits); err != nil {
		return fmt.Errorf("commit_phase_commits: %w", err)
	}
	if err := encodeKbVec(w, f.CommitPowWitnesses); err != nil {
		return fmt.Errorf("commit_pow_witnesses: %w", err)
	}
	if err := encodeQueryProofVec(w, f.QueryProofs); err != nil {
		return fmt.Errorf("query_proofs: %w", err)
	}
	if err := encodeExt4Vec(w, f.FinalPoly); err != nil {
		return fmt.Errorf("final_poly: %w", err)
	}
	return encodeKbElement(w, f.QueryPowWitness)
}

func encodeQueryProofVec(w *PostcardWriter, qs []QueryProof) error {
	if err := w.WriteVecLen(len(qs)); err != nil {
		return err
	}
	for i, q := range qs {
		if err := encodeQueryProof(w, &q); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

func encodeQueryProof(w *PostcardWriter, q *QueryProof) error {
	if err := encodeBatchOpeningVec(w, q.InputProof); err != nil {
		return fmt.Errorf("input_proof: %w", err)
	}
	return encodeCommitPhaseStepVec(w, q.CommitPhaseOpenings)
}

func encodeBatchOpeningVec(w *PostcardWriter, bs []BatchOpening) error {
	if err := w.WriteVecLen(len(bs)); err != nil {
		return err
	}
	for i, b := range bs {
		if err := encodeBatchOpening(w, &b); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

func encodeBatchOpening(w *PostcardWriter, b *BatchOpening) error {
	if err := w.WriteVecLen(len(b.OpenedValues)); err != nil {
		return err
	}
	for i, row := range b.OpenedValues {
		if err := encodeKbVec(w, row); err != nil {
			return fmt.Errorf("opened_values[%d]: %w", i, err)
		}
	}
	return encodeDigestVec(w, b.OpeningProof)
}

func encodeCommitPhaseStepVec(w *PostcardWriter, ss []CommitPhaseProofStep) error {
	if err := w.WriteVecLen(len(ss)); err != nil {
		return err
	}
	for i, s := range ss {
		if err := encodeCommitPhaseStep(w, &s); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

func encodeCommitPhaseStep(w *PostcardWriter, s *CommitPhaseProofStep) error {
	if err := w.WriteU8(s.LogArity); err != nil {
		return err
	}
	if err := encodeExt4Vec(w, s.SiblingValues); err != nil {
		return fmt.Errorf("sibling_values: %w", err)
	}
	return encodeDigestVec(w, s.OpeningProof)
}

func encodeKbElement(w *PostcardWriter, v KbElement) error {
	return w.WriteVarintU32(uint32(v))
}

func encodeKbVec(w *PostcardWriter, vs []KbElement) error {
	if err := w.WriteVecLen(len(vs)); err != nil {
		return err
	}
	for _, v := range vs {
		if err := encodeKbElement(w, v); err != nil {
			return err
		}
	}
	return nil
}

func encodeExt4(w *PostcardWriter, e KbExt4) error {
	for _, c := range e {
		if err := encodeKbElement(w, c); err != nil {
			return err
		}
	}
	return nil
}

func encodeExt4Vec(w *PostcardWriter, es []KbExt4) error {
	if err := w.WriteVecLen(len(es)); err != nil {
		return err
	}
	for _, e := range es {
		if err := encodeExt4(w, e); err != nil {
			return err
		}
	}
	return nil
}

func encodeOptionalExt4Vec(w *PostcardWriter, p *[]KbExt4) error {
	if p == nil {
		return w.WriteOption(false)
	}
	if err := w.WriteOption(true); err != nil {
		return err
	}
	return encodeExt4Vec(w, *p)
}

func encodeExt4VecVec(w *PostcardWriter, ess [][]KbExt4) error {
	if err := w.WriteVecLen(len(ess)); err != nil {
		return err
	}
	for _, es := range ess {
		if err := encodeExt4Vec(w, es); err != nil {
			return err
		}
	}
	return nil
}

func encodeDigest(w *PostcardWriter, d KbDigest) error {
	for _, v := range d {
		if err := encodeKbElement(w, v); err != nil {
			return err
		}
	}
	return nil
}

func encodeOptionalDigest(w *PostcardWriter, p *KbDigest) error {
	if p == nil {
		return w.WriteOption(false)
	}
	if err := w.WriteOption(true); err != nil {
		return err
	}
	return encodeDigest(w, *p)
}

func encodeDigestVec(w *PostcardWriter, ds []KbDigest) error {
	if err := w.WriteVecLen(len(ds)); err != nil {
		return err
	}
	for _, d := range ds {
		if err := encodeDigest(w, d); err != nil {
			return err
		}
	}
	return nil
}

package sp1fri

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-126: `Verify` adjudicates adversary-authored proof bytes, so every
// malformed or structurally short proof must come back as an error — never a
// panic. The original defect: `verifyFriWithConfig` indexed
// `QueryProofs[1:]` before the query-count check, so a proof with zero query
// proofs panicked with "slice bounds out of range [1:0]".
//
// What these tests prove: for the honest minimal-guest vector with one shape
// field emptied / shortened / inflated at a time (and for every byte prefix of
// the encoded vector), Verify and VerifyWithConfig return an error and do not
// panic — under the pinned config AND under a copy with both PoW bit counts
// zeroed, which stands in for an attacker who grinds the (1-bit) PoW so the
// malformed shape reaches the query loop instead of dying at a PoW check.
//
// What they do not prove: that the verifier is sound against well-formed
// forgeries (that is TestRejectMutatedProof and the corruption vectors), nor
// that every possible malformed proof is panic-free — only the shapes
// enumerated here. Ext4Inv(0) inside open_input stays reachable only by
// grinding the transcript to land zeta on a base-field point (~2^-93), which
// is not exercised.

// noPowConfig returns cfg with the grinding requirements removed, so shape
// mutations are not masked by an incidental PoW failure.
func noPowConfig(cfg FriVerifierConfig) FriVerifierConfig {
	cfg.commitPowBits = 0
	cfg.queryPowBits = 0
	return cfg
}

// mustRejectWithoutPanic runs fn, failing the test if it panics or returns nil.
func mustRejectWithoutPanic(t *testing.T, label string, fn func() error) {
	t.Helper()
	var err error
	panicked := func() (p any) {
		defer func() { p = recover() }()
		err = fn()
		return nil
	}()
	if panicked != nil {
		t.Errorf("%s: verifier PANICKED on a malformed proof: %v", label, panicked)
		return
	}
	if err == nil {
		t.Errorf("%s: verifier ACCEPTED a malformed proof", label)
	}
}

// TestVerifyRejectsZeroQueryProofsWithoutPanic is the CL-BUG-092 repro.
func TestVerifyRejectsZeroQueryProofsWithoutPanic(t *testing.T) {
	p := loadMinimalGuestProof(t)
	p.OpeningProof.QueryProofs = nil
	var err error
	mustRejectWithoutPanic(t, "zero query proofs", func() error {
		err = Verify(p, []uint32{0, 1, 21})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "query_proofs 0 != 2") {
		t.Fatalf("expected the query-count rejection, got: %v", err)
	}
}

// TestVerifyRejectsMalformedShapesWithoutPanic truncates / inflates every
// length-bearing field of the honest vector, one at a time.
func TestVerifyRejectsMalformedShapesWithoutPanic(t *testing.T) {
	pis := []uint32{0, 1, 21}
	type mut struct {
		name string
		f    func(p *Proof)
	}
	muts := []mut{
		{"query_proofs=0", func(p *Proof) { p.OpeningProof.QueryProofs = nil }},
		{"query_proofs=1", func(p *Proof) { p.OpeningProof.QueryProofs = p.OpeningProof.QueryProofs[:1] }},
		{"query_proofs=3", func(p *Proof) {
			p.OpeningProof.QueryProofs = append(p.OpeningProof.QueryProofs, p.OpeningProof.QueryProofs[0])
		}},
		{"commit_phase_commits=0", func(p *Proof) { p.OpeningProof.CommitPhaseCommits = nil }},
		// The minimal-guest vector has exactly one FRI round, so "short" is 0
		// and the other direction is one round too many.
		{"commit_phase_commits+1", func(p *Proof) {
			p.OpeningProof.CommitPhaseCommits = append(p.OpeningProof.CommitPhaseCommits, p.OpeningProof.CommitPhaseCommits[0])
		}},
		{"commit_phase_commits[0] cap=0", func(p *Proof) { p.OpeningProof.CommitPhaseCommits[0] = nil }},
		{"commit_pow_witnesses=0", func(p *Proof) { p.OpeningProof.CommitPowWitnesses = nil }},
		{"commit_pow_witnesses+1", func(p *Proof) {
			p.OpeningProof.CommitPowWitnesses = append(p.OpeningProof.CommitPowWitnesses, p.OpeningProof.CommitPowWitnesses[0])
		}},
		{"final_poly=0", func(p *Proof) { p.OpeningProof.FinalPoly = nil }},
		{"final_poly=1", func(p *Proof) { p.OpeningProof.FinalPoly = p.OpeningProof.FinalPoly[:1] }},
		{"q0 commit_phase_openings=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].CommitPhaseOpenings = nil }},
		{"q0 commit_phase_openings+1", func(p *Proof) {
			ops := p.OpeningProof.QueryProofs[0].CommitPhaseOpenings
			p.OpeningProof.QueryProofs[0].CommitPhaseOpenings = append(ops, ops[0])
		}},
		// One extra round everywhere (consistent counts, schedule too long for
		// the input matrices).
		{"one extra round everywhere", func(p *Proof) {
			p.OpeningProof.CommitPhaseCommits = append(p.OpeningProof.CommitPhaseCommits, p.OpeningProof.CommitPhaseCommits[0])
			p.OpeningProof.CommitPowWitnesses = append(p.OpeningProof.CommitPowWitnesses, p.OpeningProof.CommitPowWitnesses[0])
			for i := range p.OpeningProof.QueryProofs {
				ops := p.OpeningProof.QueryProofs[i].CommitPhaseOpenings
				p.OpeningProof.QueryProofs[i].CommitPhaseOpenings = append(ops, ops[0])
			}
		}},
		// Zero FRI rounds everywhere: every round-count check agrees, so
		// log_global_max_height collapses below the input matrix height
		// (the old code then shifted by a negative amount in open_input).
		{"zero rounds everywhere", func(p *Proof) {
			p.OpeningProof.CommitPhaseCommits = nil
			p.OpeningProof.CommitPowWitnesses = nil
			for i := range p.OpeningProof.QueryProofs {
				p.OpeningProof.QueryProofs[i].CommitPhaseOpenings = nil
			}
		}},
		// Consistent but oversized arity: inflates log_global_max_height past
		// the field's two-adicity (old code: SampleBits / KbTwoAdicGenerator panic).
		{"log_arity=40 everywhere", func(p *Proof) {
			for i := range p.OpeningProof.QueryProofs {
				p.OpeningProof.QueryProofs[i].CommitPhaseOpenings[0].LogArity = 40
			}
		}},
		{"log_arity=255 everywhere", func(p *Proof) {
			for i := range p.OpeningProof.QueryProofs {
				p.OpeningProof.QueryProofs[i].CommitPhaseOpenings[0].LogArity = 255
			}
		}},
		{"log_arity=0 everywhere", func(p *Proof) {
			for i := range p.OpeningProof.QueryProofs {
				p.OpeningProof.QueryProofs[i].CommitPhaseOpenings[0].LogArity = 0
			}
		}},
		{"log_arity mismatch q1", func(p *Proof) { p.OpeningProof.QueryProofs[1].CommitPhaseOpenings[0].LogArity = 2 }},
		{"q0 step0 siblings=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].CommitPhaseOpenings[0].SiblingValues = nil }},
		{"q0 step0 opening_proof=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].CommitPhaseOpenings[0].OpeningProof = nil }},
		{"q0 input_proof=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].InputProof = nil }},
		{"q0 input_proof=1", func(p *Proof) {
			p.OpeningProof.QueryProofs[0].InputProof = p.OpeningProof.QueryProofs[0].InputProof[:1]
		}},
		{"q0 batch0 opened_values=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].InputProof[0].OpenedValues = nil }},
		{"q0 batch0 opened_values[0]=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].InputProof[0].OpenedValues[0] = nil }},
		{"q0 batch0 opening_proof=0", func(p *Proof) { p.OpeningProof.QueryProofs[0].InputProof[0].OpeningProof = nil }},
		{"trace commitment cap=0", func(p *Proof) { p.Commitments.Trace = nil }},
		{"quotient commitment cap=0", func(p *Proof) { p.Commitments.QuotientChunks = nil }},
		{"trace_local=0", func(p *Proof) { p.OpenedValues.TraceLocal = nil }},
		{"trace_next=None", func(p *Proof) { p.OpenedValues.TraceNext = nil }},
		{"quotient_chunks=0", func(p *Proof) { p.OpenedValues.QuotientChunks = nil }},
		{"quotient_chunks[0]=1", func(p *Proof) { p.OpenedValues.QuotientChunks[0] = p.OpenedValues.QuotientChunks[0][:1] }},
		{"degree_bits=64", func(p *Proof) { p.DegreeBits = 64 }},
	}

	cfgs := []struct {
		name string
		cfg  FriVerifierConfig
	}{
		{"pinned", minimalGuestConfig},
		{"pow-ground", noPowConfig(minimalGuestConfig)},
	}
	for _, c := range cfgs {
		for _, m := range muts {
			p := loadMinimalGuestProof(t)
			m.f(p)
			mustRejectWithoutPanic(t, fmt.Sprintf("[%s] %s", c.name, m.name), func() error {
				return VerifyWithConfig(p, pis, c.cfg)
			})
		}
	}

	mustRejectWithoutPanic(t, "nil proof", func() error { return Verify(nil, pis) })
}

// TestVerifyRejectsTruncatedEncodingWithoutPanic feeds every strict byte
// prefix of the honest encoding through decode + verify.
func TestVerifyRejectsTruncatedEncodingWithoutPanic(t *testing.T) {
	abs, err := filepath.Abs(minimalGuestProofRel)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	bs, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for n := 0; n < len(bs); n++ {
		prefix := bs[:n]
		mustRejectWithoutPanic(t, fmt.Sprintf("prefix %d/%d", n, len(bs)), func() error {
			p, err := DecodeProof(prefix)
			if err != nil {
				return err
			}
			return Verify(p, []uint32{0, 1, 21})
		})
	}
}

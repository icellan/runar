package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// ---------------------------------------------------------------------------
// F-007 (CL-BUG-037) — the SP1 FRI verifier is refused for v1, and the body
// it would emit is fail-closed.
//
// The deployable body `codegen.EmitFullSP1FriVerifierBody` derives every FRI
// query index and then DROPS it: no per-query MMCS opening, no fold /
// colinearity step, no final-poly equality, and no Steps 6/7 out-of-domain
// constraint check is ever emitted. It then pushed OP_1. So a proof whose
// every per-query opening is garbage — but whose transcript fields, grinding
// witnesses and Step 1 binding are honest — was ACCEPTED on-chain while the
// off-chain reference verifier rejects it.
//
// User decision (dispatcher-resolutions R6): v1 does not ship the verifier.
// The body ends in OP_0 OP_VERIFY, so it can never accept, and compiling
// verifySP1FRI is always refused — the `@acknowledgeUnsoundSP1FriVerifier`
// directive and the `--acknowledge-unsound-sp1-fri` / AcknowledgeUnsoundSP1Fri
// escape hatch are gone.
// ---------------------------------------------------------------------------

// lowerSP1FriPocBypassingRefusal lowers the PoC covenant through the same
// passes CompileFromSource runs (parse, typecheck, expand, ANF, fold, EC
// optimizer, stack lowering, peephole, emit) but skips the two refusals —
// frontend.Validate's and the --ir guard in CompileFromProgram — because since
// F-007 those refuse verifySP1FRI unconditionally and there is no production
// path to the emitted body any more. TEST-ONLY: it exists so the body's
// on-chain behaviour can still be executed against the real ABI.
func lowerSP1FriPocBypassingRefusal(t *testing.T, params *codegen.SP1FriVerifierParams) *codegen.EmitResult {
	t.Helper()
	path := sp1PocContractPath(t)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PoC contract: %v", err)
	}
	pr := frontend.ParseSource(src, path)
	if len(pr.Errors) > 0 || pr.Contract == nil {
		t.Fatalf("parse PoC contract: %v", pr.ErrorStrings())
	}
	if tc := frontend.TypeCheck(pr.Contract); len(tc.Errors) > 0 {
		t.Fatalf("typecheck PoC contract: %v", tc.ErrorStrings())
	}
	ex := frontend.ExpandFixedArrays(pr.Contract)
	if len(ex.Errors) > 0 {
		t.Fatalf("expand PoC contract: %v", ex.Errors)
	}
	program := frontend.LowerToANF(ex.Contract)
	program = frontend.FoldConstants(program)
	program = frontend.OptimizeEC(program)
	methods, err := codegen.LowerToStack(program, codegen.LowerToStackOptions{SP1FriParams: params})
	if err != nil {
		t.Fatalf("stack-lower PoC contract: %v", err)
	}
	for i := range methods {
		methods[i].Ops = codegen.OptimizeStackOps(methods[i].Ops)
	}
	res, err := codegen.Emit(methods)
	if err != nil {
		t.Fatalf("emit PoC contract: %v", err)
	}
	return res
}

// garbageEveryQueryOpening overwrites every per-query opening of the proof —
// opened rows and Merkle paths of every input batch, and sibling values and
// Merkle paths of every commit-phase step — with one constant field element.
// Transcript fields (commitments, OOD opened values, final poly, PoW witnesses,
// log arities) are untouched, so the Fiat-Shamir replay, both grinding checks
// and the Step 1 binding stay honest. This is the attack attempt 1 reproduced.
func garbageEveryQueryOpening(proof *sp1fri.Proof) {
	g := sp1fri.KbElement(0x1234567)
	for qi := range proof.OpeningProof.QueryProofs {
		qp := &proof.OpeningProof.QueryProofs[qi]
		for bi := range qp.InputProof {
			for mi := range qp.InputProof[bi].OpenedValues {
				for k := range qp.InputProof[bi].OpenedValues[mi] {
					qp.InputProof[bi].OpenedValues[mi][k] = g
				}
			}
			for di := range qp.InputProof[bi].OpeningProof {
				for k := 0; k < 8; k++ {
					qp.InputProof[bi].OpeningProof[di][k] = g
				}
			}
		}
		for si := range qp.CommitPhaseOpenings {
			st := &qp.CommitPhaseOpenings[si]
			for vi := range st.SiblingValues {
				for k := 0; k < 4; k++ {
					st.SiblingValues[vi][k] = g
				}
			}
			for di := range st.OpeningProof {
				for k := 0; k < 8; k++ {
					st.OpeningProof[di][k] = g
				}
			}
		}
	}
}

// TestF007_EmittedVerifierBodyFailsClosed executes the body the Go codegen
// emits for the PoC covenant under the go-sdk interpreter.
//
// Proves: the emitted verifier rejects (a) the crafted garbage-openings proof
// the pre-fix body ACCEPTED, and (b) the honest canonical minimal-guest proof —
// i.e. it is fail-closed, not merely stricter. The off-chain reference is
// consulted so (a) is known to be a real forgery and (b) a real valid proof.
//
// Does NOT prove: that any SP1 FRI proof is verified. Nothing is; the missing
// checks are listed in docs/sp1-fri-verifier.md as the post-v1 plan.
func TestF007_EmittedVerifierBodyFailsClosed(t *testing.T) {
	root := sp1FixturesRoot(t)
	res := lowerSP1FriPocBypassingRefusal(t, nil)
	lock, err := script.NewFromHex(res.ScriptHex)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	params := sp1fri.MinimalGuestParams()
	proofBytes, err := os.ReadFile(filepath.Join(root, "minimal-guest", "proof.postcard"))
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, pubVals := readPublicValuesBytes(t, filepath.Join(root, "minimal-guest", "public_values.hex"))

	t.Run("garbage_openings_rejected", func(t *testing.T) {
		proof, err := sp1fri.DecodeProof(proofBytes)
		if err != nil {
			t.Fatal(err)
		}
		garbageEveryQueryOpening(proof)
		if refErr := sp1fri.Verify(proof, pubVals); refErr == nil {
			t.Fatal("reference verifier accepted the garbage-openings proof — attack input is wrong")
		}
		unlocking, err := sp1fri.EncodeUnlockingScript(proof, nil, pubBytes, nil, params)
		if err != nil {
			t.Fatal(err)
		}
		if execErr := runSpend(lock, unlocking); execErr == nil {
			t.Fatal("F-007: the emitted SP1 FRI verifier ACCEPTS a proof whose every per-query " +
				"opening is garbage (the per-query chain is never emitted and the body ends in OP_1)")
		} else {
			t.Logf("garbage-openings proof rejected: %v", execErr)
		}
	})

	t.Run("honest_canonical_proof_rejected", func(t *testing.T) {
		proof, err := sp1fri.DecodeProof(proofBytes)
		if err != nil {
			t.Fatal(err)
		}
		if refErr := sp1fri.Verify(proof, pubVals); refErr != nil {
			t.Fatalf("reference verifier rejected the canonical fixture: %v", refErr)
		}
		unlocking, err := sp1fri.EncodeUnlockingScript(proof, nil, pubBytes, nil, params)
		if err != nil {
			t.Fatal(err)
		}
		if execErr := runSpend(lock, unlocking); execErr == nil {
			t.Fatal("F-007: the emitted SP1 FRI verifier ACCEPTED the canonical proof; for v1 the " +
				"body must be fail-closed and accept nothing")
		} else {
			t.Logf("canonical proof rejected (fail-closed): %v", execErr)
		}
	})
}

// TestF007_CompilingVerifySP1FRIIsAlwaysRefused pins that there is no way to
// compile verifySP1FRI in v1: not with the old source directive, not without
// it, and not through the --ir entry points.
//
// Proves: every in-process compile entry point refuses, and the refusal says
// the verifier is not implemented for v1. The CLI (including the removed
// --acknowledge-unsound-sp1-fri flag) is pinned separately in
// compilers/go/cli_sp1_fri_ir_guard_test.go.
func TestF007_CompilingVerifySP1FRIIsAlwaysRefused(t *testing.T) {
	check := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("F-007: %s COMPILED a verifySP1FRI contract; v1 must always refuse it", what)
		}
		if !strings.Contains(err.Error(), "not implemented for v1") {
			t.Errorf("%s: refusal must say the verifier is not implemented for v1; got: %v", what, err)
		}
		if strings.Contains(err.Error(), "acknowledge") {
			t.Errorf("%s: refusal must not advertise an acknowledgement escape hatch; got: %v", what, err)
		}
	}

	// The PoC source, with and without the old `@acknowledgeUnsoundSP1FriVerifier`
	// directive: the directive must now be inert.
	pocSrc, err := os.ReadFile(sp1PocContractPath(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CompileFromSource(sp1PocContractPath(t))
	check(t, "CompileFromSource(PoC)", err)

	withDirective := strings.Replace(string(pocSrc), "package contracts\n",
		"package contracts\n\n// @acknowledgeUnsoundSP1FriVerifier\n", 1)
	if !strings.Contains(withDirective, "@acknowledgeUnsoundSP1FriVerifier") {
		t.Fatal("test scaffold: failed to insert the old directive")
	}
	dir := t.TempDir()
	acked := filepath.Join(dir, "Sp1FriVerifierPoc.runar.go")
	if err := os.WriteFile(acked, []byte(withDirective), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = CompileFromSource(acked)
	check(t, "CompileFromSource(PoC with old directive)", err)

	for name, src := range map[string]string{"without directive": string(pocSrc), "with old directive": withDirective} {
		res := CompileFromSourceStrWithResult(src, "Sp1FriVerifierPoc.runar.go")
		if res.Success || res.Artifact != nil {
			t.Fatalf("F-007: CompileFromSourceStrWithResult (%s) compiled a verifySP1FRI contract", name)
		}
	}

	_, err = CompileFromIRBytes([]byte(sp1FriIRCall))
	check(t, "CompileFromIRBytes", err)
	_, err = CompileFromProgram(mustLoadIR(t, sp1FriIRCall))
	check(t, "CompileFromProgram", err)
}

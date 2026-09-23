package compiler

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// R-062 / CL-BUG-105 — the acknowledged SP1 FRI path reaches a value-bearing
// deployment with no friction.
//
// R-012 closed the COMPILE side: `verifySP1FRI` was refused unless the author
// wrote `@acknowledgeUnsoundSP1FriVerifier`, or the invoker passed
// `--acknowledge-unsound-sp1-fri` (both removed by F-007). What neither
// covered was everything downstream. The reviewer enumerated the artifact's top-level keys — abi, asm,
// buildTimestamp, compilerVersion, constructorSlots, contractName, parentClass,
// script, version — and found nothing recording that the script contains a
// verifier the project itself calls unsound, and
// `grep -rln "acknowledgeUnsound|unsoundSP1|UnsoundSP1" packages/` matched in
// none of the seven SDKs.
//
// So the acknowledgement stopped at the person who ran the compiler. Anyone
// handed the resulting artifact — a deployer, a reviewer, another team's SDK —
// sees an ordinary contract, and every SDK funds it without a word.
//
// The artifact now carries the fact. `unsoundPrimitives` is omitted entirely
// from every other artifact (`omitempty`), so this changes nothing for any
// contract that does not reach the verifier, and the SDK-side deploy guards key
// on it.
//
// F-007: the verifier is not implemented for v1 and every compile that reaches
// it is refused, so no artifact this compiler emits can carry the marker; the
// stamping was removed as dead code (the schema field stays for the SDKs).
//
// Was: an acknowledged compile produced an artifact marked
// unsoundPrimitives:["verifySP1FRI"].
// F-007: rewritten to expect refusal — the acknowledgement override was removed, so there is no artifact to mark.
func TestArtifact_MarksUnsoundSP1FriVerifier(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(sp1FriIRCall))
	if err == nil {
		t.Fatalf("F-007: compile of verifySP1FRI IR must be refused; got an artifact (marker %v)",
			artifact.UnsoundPrimitives)
	}
	if !strings.Contains(err.Error(), "not implemented for v1") {
		t.Fatalf("refusal must say the verifier is not implemented for v1; got: %v", err)
	}
}

// The marker's input is the SAME detector the --ir soundness refusal consults,
// so the two cannot disagree about whether a program reaches the verifier.
// F-007: the guard now refuses every such shape; the detector is what it keys on.
//
// Asserted on the detector rather than on a compiled artifact because a
// `verifySP1FRI` call nested inside an `if` arm does not survive stack lowering
// at all (the verifier's lowering pre-pushes a layer and assumes method-level
// position) — so there is no nested artifact to inspect. The refusal path is
// what a nested call actually meets, and it is checked here too.
func TestArtifact_MarkerDetectorSeesNestedCalls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		irJSON string
	}{
		{"top-level call", sp1FriIRCall},
		{"nested in if/loop", sp1FriIRNested},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := ir.LoadIRFromBytes([]byte(tc.irJSON))
			if err != nil {
				t.Fatalf("load IR: %v", err)
			}
			if !programCallsSP1FriVerifier(program) {
				t.Fatal("detector missed the verifier call, so the artifact would be marked sound")
			}
			if _, err := CompileFromIRBytes([]byte(tc.irJSON)); err == nil {
				t.Fatal("the same shape must be REFUSED")
			}
		})
	}
}

// The control, and the reason `omitempty` matters: an ordinary contract's
// artifact must be byte-identical to what it was before this field existed.
// Every SDK's deploy guard keys on the field's presence, so a stray empty array
// would put every contract in the repo through the SDK acknowledgement path.
func TestArtifact_OrdinaryContractCarriesNoMarker(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(controlIR))
	if err != nil {
		t.Fatalf("ordinary IR must compile: %v", err)
	}
	if got := artifact.UnsoundPrimitives; len(got) != 0 {
		t.Fatalf("ordinary contract must carry no marker; got %v", got)
	}
	raw, err := ArtifactToJSON(artifact)
	if err != nil {
		t.Fatalf("ArtifactToJSON: %v", err)
	}
	if strings.Contains(string(raw), "unsoundPrimitives") {
		t.Fatalf("ordinary artifact must not mention unsoundPrimitives:\n%s", raw)
	}
}

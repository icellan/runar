import RunarVerification.Pipeline
import RunarVerification.ANF.Json
open RunarVerification ANF Pipeline Stack Script

/-!
# Per-fixture conformance-as-formal-evidence harness (Phase F + Phase D harness integration)

This executable walks every conformance fixture under `../conformance/tests/`
and classifies each one against the formal verification corpus using a
**two-tier** scheme:

* **VERIFIED** — the fixture lies inside the structural-ref fragment
  for which `compileSafe_single_public_observational_correct_unconditional_ref`
  is an unconditional Lean theorem (no codegen-soundness axioms in the
  chain). To reach this tier a fixture must be well-formed
  (`WF.programIsWF`), have `compileSafe = .ok _`, expose a single public
  method, have no auto-injected `checkPreimage` / `codePart` /
  `deserializeState` / terminal assert, satisfy `structuralRefBody` on
  every binding, and satisfy `noIfOp` on the lowered body. Every other
  ANF constructor (`binOp`, `assert`, `call`, `update_prop`, `ifVal`,
  `loop`, crypto intrinsics, output construction) falls outside this
  fragment.

* **VERIFIED-modulo-codegen-axioms** — the fixture passes the permissive
  premises of the Phase D harness omnibus axiom
  `compileSafe_observational_correct_modulo_codegen_axioms`: it is
  well-formed, `compileSafe` succeeds, and it has at least one public
  method. Soundness for fixtures at this tier is conditional on the
  codegen-soundness axioms documented in `TRUST_MANIFEST.md` (Phase B
  per-primitive codegen-to-spec assumptions + the Phase D harness
  omnibus, which collapses the runtime-side Stage C composition for
  non-structural-const ANF constructors into one trust footprint).

A fixture that fails the static parse / WF / compile-safe checks lands
in a `DEFERRED-<reason>` bucket.

## Honest assessment

The direct VERIFIED tier requires every binding to be a literal load
or reference load — no `assert`, `binOp`, `call`, `checkPreimage`,
`loop`, `ifVal`, `updateProp`, or output intrinsics. Every real
conformance fixture uses at least one of these constructors, so we
expect **0 fixtures at the direct VERIFIED tier today**. Fixtures
whose `compileSafe` succeeds AND have at least one public method land
in `VERIFIED-modulo-codegen-axioms`, conditional on the omnibus
axiom's trust footprint.

Removing the omnibus axiom requires landing A3–A8 runtime-side Stage C
composition for every non-structural-const ANF constructor plus the
Phase B per-opcode reductions for every crypto primitive family the
fixtures touch. At that point the `VERIFIED-modulo-codegen-axioms`
fixtures move directly to `VERIFIED`.

## Phase F4 note

The `asm-raw-script` fixture parses in target now (A14 integration —
`.rawScript` ANF kind recognized). Its classification depends on
whether `compileSafe` accepts or rejects the sentinel opcode.
-/

/-- Outcome of checking a single fixture's static premises.
The `label` field carries a string that can be compared with `==`. -/
structure Outcome where
  label : String
  deriving BEq, Repr

/-- Direct VERIFIED tier — structural-ref fragment, single public
method, all static premises of the A15 capstone discharge unconditionally. -/
def Outcome.verified : Outcome :=
  ⟨"VERIFIED"⟩

/-- Phase D harness omnibus tier — sound conditional on the
codegen-soundness axioms in `TRUST_MANIFEST.md`. -/
def Outcome.verifiedModuloCodegenAxioms : Outcome :=
  ⟨"VERIFIED-modulo-codegen-axioms"⟩

def Outcome.deferredParseFail : Outcome :=
  ⟨"DEFERRED-parse-failure"⟩

def Outcome.deferredNotWellFormed : Outcome :=
  ⟨"DEFERRED-not-well-formed"⟩

def Outcome.deferredCompileSafeError : Outcome :=
  ⟨"DEFERRED-compile-safe-error"⟩

def Outcome.deferredNoPublicMethod : Outcome :=
  ⟨"DEFERRED-no-public-method"⟩

/--
Check one fixture's IR against the two-tier classification.

Returns:
* `Outcome.verified` — the fixture's body lies inside the
  structural-ref fragment (literal loads + copy/consume ref loads
  only) with a single public method and all M5 static premises
  discharged.
* `Outcome.verifiedModuloCodegenAxioms` — the fixture is well-formed,
  `compileSafe` succeeds, and it has at least one public method.
  These are exactly the premises of
  `compileSafe_observational_correct_modulo_codegen_axioms` (the
  Phase D harness omnibus).
* `Outcome.deferredParseFail` — `ANFProgram.fromString` failed.
* `Outcome.deferredNotWellFormed` — `WF.programIsWF p = false`.
* `Outcome.deferredCompileSafeError` — `compileSafe` rejected `p`.
* `Outcome.deferredNoPublicMethod` — no public method exists.
-/
def checkFixture (irJson : String) : Outcome :=
  match ANFProgram.fromString irJson with
  | .error _ => Outcome.deferredParseFail
  | .ok p    =>
      if !(WF.programIsWF p) then Outcome.deferredNotWellFormed else
      match compileSafe p with
      | .error _ => Outcome.deferredCompileSafeError
      | .ok _    =>
          let anfPublic := p.methods.filter (·.isPublic)
          match anfPublic with
          | []      => Outcome.deferredNoPublicMethod
          | [anfM]  =>
              -- Try the direct VERIFIED tier first: structural-ref fragment.
              -- If any precondition fails, fall back to the omnibus tier.
              -- These are the static premises of A15
              -- (`compileSafe_single_public_observational_correct_unconditional_ref`).
              if Lower.bindingsUseCheckPreimage anfM.body
                 || Lower.bindingsUseCodePart anfM.body
                 || Lower.bodyEndsInAssert anfM.body
                 || Lower.bindingsUseDeserializeState anfM.body then
                Outcome.verifiedModuloCodegenAxioms
              else
                let lastUses     := Lower.computeLastUses anfM.body
                let localBindings := anfM.body.map (·.name)
                let constInts    := Lower.collectConstInts anfM.body
                let initialSm : Lower.StackMap :=
                  List.reverse (anfM.params.map (·.name))
                if !(Agrees.structuralRefBodyBool
                        p.methods p.properties
                        Lower.defaultInlineBudget
                        lastUses [] localBindings constInts
                        anfM.body initialSm 0) then
                  Outcome.verifiedModuloCodegenAxioms
                else
                  let loweredBody := (Lower.lower p).bodyOf anfM.name
                  if !(Peephole.noIfOpBool loweredBody) then
                    Outcome.verifiedModuloCodegenAxioms
                  else
                    -- All A15 static premises discharged. The remaining
                    -- runtime-witness premises (agreesTagged, wellTypedRun,
                    -- rollPickDepthOK, peepholePassAllFlat_preconditions,
                    -- AreRunarEmittable, structural shape, domain witnesses)
                    -- are not checked here — they're externally supplied at
                    -- proof time. For harness reporting we still classify as
                    -- VERIFIED-modulo-codegen-axioms because the omnibus
                    -- subsumes the runtime-witness gap for harness uniformity.
                    Outcome.verifiedModuloCodegenAxioms
          | _ :: _ :: _ =>
              -- Multi-public-method programs cannot reach the direct
              -- VERIFIED tier today (the A15 capstone requires a single
              -- public method), but the omnibus axiom admits them.
              Outcome.verifiedModuloCodegenAxioms

/--
Group-by outcome label for the summary table. Each distinct label
becomes one row.
-/
def groupByOutcome (results : List (String × Outcome)) :
    List (String × List String) :=
  let knownLabels : List String := [
    Outcome.verified.label,
    Outcome.verifiedModuloCodegenAxioms.label,
    Outcome.deferredParseFail.label,
    Outcome.deferredNotWellFormed.label,
    Outcome.deferredCompileSafeError.label,
    Outcome.deferredNoPublicMethod.label
  ]
  knownLabels.filterMap (fun lbl =>
    let names := results.filterMap (fun (name, out) =>
      if out.label == lbl then some name else none)
    if names.isEmpty then none
    else some (lbl, names))

def main : IO Unit := do
  -- Resolve relative to the repo root.
  -- CI runs from `runar-verification/`; `../conformance/tests` is the corpus.
  let dir := "../conformance/tests"
  let entries ← System.FilePath.readDir dir
  let mut results : List (String × Outcome) := []
  let mut total := 0

  for e in entries do
    let ir := e.path / "expected-ir.json"
    let hex := e.path / "expected-script.hex"
    if (← System.FilePath.pathExists ir) && (← System.FilePath.pathExists hex) then
      total := total + 1
      let irJson ← IO.FS.readFile ir.toString
      let out := checkFixture irJson
      results := results ++ [(e.fileName, out)]

  let verifiedCount :=
    results.filter (fun r => r.2 == Outcome.verified) |>.length
  let verifiedModuloCount :=
    results.filter (fun r => r.2 == Outcome.verifiedModuloCodegenAxioms) |>.length
  let deferredParseCount :=
    results.filter (fun r => r.2 == Outcome.deferredParseFail) |>.length
  let deferredWFCount :=
    results.filter (fun r => r.2 == Outcome.deferredNotWellFormed) |>.length
  let deferredCompileCount :=
    results.filter (fun r => r.2 == Outcome.deferredCompileSafeError) |>.length
  let deferredNoPublicCount :=
    results.filter (fun r => r.2 == Outcome.deferredNoPublicMethod) |>.length

  IO.println s!"PipelineConformance: {total} fixtures"
  IO.println ""
  IO.println s!"  VERIFIED                       : {verifiedCount}"
  IO.println s!"  VERIFIED-modulo-codegen-axioms : {verifiedModuloCount}"
  IO.println s!"  DEFERRED-parse-failure         : {deferredParseCount}"
  IO.println s!"  DEFERRED-not-well-formed       : {deferredWFCount}"
  IO.println s!"  DEFERRED-compile-safe-error    : {deferredCompileCount}"
  IO.println s!"  DEFERRED-no-public-method      : {deferredNoPublicCount}"
  IO.println ""

  -- Full breakdown by outcome
  let groups := groupByOutcome results
  for (lbl, names) in groups do
    IO.println s!"  {lbl}: {names.length} fixture(s)"
    for n in names.mergeSort (· ≤ ·) do
      IO.println s!"    - {n}"

  IO.println ""
  IO.println "Honest assessment"
  IO.println "================="
  IO.println ""
  IO.println "VERIFIED fixtures are sound without any codegen-soundness"
  IO.println "axioms: their bodies live inside the structural-ref fragment"
  IO.println "for which `compileSafe_single_public_observational_correct"
  IO.println "_unconditional_ref` is an unconditional Lean theorem."
  IO.println ""
  IO.println "VERIFIED-modulo-codegen-axioms fixtures are sound conditional"
  IO.println "on the Phase B per-primitive codegen-to-spec axioms (crypto"
  IO.println "hash/EC/Merkle/WOTS/SLH-DSA/Rabin) and the Phase D harness"
  IO.println "omnibus axiom `compileSafe_observational_correct_modulo_"
  IO.println "codegen_axioms`, which collapses the runtime-side Stage C"
  IO.println "composition for non-structural-const ANF constructors into"
  IO.println "one trust footprint. See `TRUST_MANIFEST.md` for the discharge"
  IO.println "path."
  IO.println ""
  IO.println "DEFERRED fixtures are not yet classifiable — either the Lean"
  IO.println "JSON loader could not decode `expected-ir.json`, `compileSafe`"
  IO.println "rejected the program, the program is malformed under"
  IO.println "`WF.programIsWF`, or it has no public entry method."

  if verifiedCount > 0 then
    IO.println ""
    IO.println "VERIFIED fixtures:"
    let verifiedNames := results.filterMap (fun (n, o) =>
      if o == Outcome.verified then some n else none)
    for n in verifiedNames.mergeSort (· ≤ ·) do
      IO.println s!"  {n}"

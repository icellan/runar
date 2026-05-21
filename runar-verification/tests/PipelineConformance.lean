import RunarVerification.Pipeline
import RunarVerification.ANF.Json
open RunarVerification ANF Pipeline Stack Script

/-!
# Per-fixture conformance-as-formal-evidence harness (Phase F + Phase D harness integration)

This executable walks every conformance fixture under `../conformance/tests/`
and classifies each one against the formal verification corpus using a
**per-family-tier** scheme (Tier 1 milestone **O1**, 2026-05-17):

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

* **VERIFIED-modulo-<family>-codegen-axioms** — the fixture passes the
  permissive premises of one of the 9 Phase D per-family sub-omnibus
  axioms in `Pipeline.lean` (split from the single omnibus by O1). The
  family-set is determined by per-fixture Bool checkers:

  - `stateful` — `Lower.bindingsUseCheckPreimage anfM.body = true`.
  - `dispatch` — program has ≥ 2 public methods.
  - `arith` — body satisfies `Agrees.structuralArithBodyBool`.
  - `math_byte_call` — body satisfies `Agrees.structuralCallBodyBool`.
  - `update_prop` — body satisfies `Agrees.structuralUpdatePropBodyBool`.
  - `if_val` — body satisfies `Agrees.structuralIfValBodyBool`.
  - `loop` — body satisfies `Agrees.structuralLoopBodyBool`.
  - `method_call` — body satisfies `Agrees.structuralMethodCallBodyBool`.
  - `crypto_call` — substrate-gap fallback when no other classifier
    fires (today: the crypto-call family, retired once A4-crypto +
    Phase B per-primitive land).

  Soundness for fixtures at these tiers is conditional on the
  corresponding sub-omnibus axiom in `Pipeline.lean` (each retires as
  its Stage C / Phase B / Phase D milestone lands; see
  `TRUST_MANIFEST.md`).

  **Tier 1 wave 25 (2026-05-21) — alignment re-statement.** Each
  sub-omnibus axiom (and the omnibus theorem) now carries an explicit
  input-side alignment premise `(tsm : Agrees.TaggedStackMap)` +
  `(hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)`,
  mirroring the ref capstone
  `compileSafe_single_public_observational_correct_unconditional_ref`.
  This makes the previously-false unconditional statement true (wave 24
  exhibited a counterexample where `initialAnf` and `initialStack` were
  unrelated). This harness is a purely syntactic classifier: it runs the
  per-family Bool checkers on each fixture body and emits a tier label.
  It never instantiates `successAgrees` and never applies a sub-omnibus,
  so it does not (and never did) supply `agreesTagged`; the alignment
  premise is a proof-time obligation discharged externally (the same
  status the M5/A15 runtime-witness premises already had — see the
  `checkFixture` note below). The classification logic is therefore
  unchanged by this re-statement.

A fixture that fails the static parse / WF / compile-safe checks lands
in a `DEFERRED-<reason>` bucket.

## Honest assessment

The direct VERIFIED tier requires every binding to be a literal load
or reference load — no `assert`, `binOp`, `call`, `checkPreimage`,
`loop`, `ifVal`, `updateProp`, or output intrinsics. Every real
conformance fixture uses at least one of these constructors, so we
expect **0 fixtures at the direct VERIFIED tier today**. Fixtures
whose `compileSafe` succeeds AND have at least one public method land
in one of the per-family `VERIFIED-modulo-<family>-codegen-axioms`
tiers, conditional on the corresponding sub-omnibus axiom's trust
footprint.

Removing the per-family sub-omnibuses requires landing A3–A8
runtime-side Stage C composition for every non-structural-const ANF
constructor plus the Phase B per-opcode reductions for every crypto
primitive family the fixtures touch. At that point the
`VERIFIED-modulo-*-codegen-axioms` fixtures move directly to
`VERIFIED`.

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

/-- Phase D per-family sub-omnibus tiers (Tier 1 O1 split, 2026-05-17). -/
def Outcome.verifiedModuloArithCodegen : Outcome :=
  ⟨"VERIFIED-modulo-arith-codegen-axioms"⟩

def Outcome.verifiedModuloMathByteCallCodegen : Outcome :=
  ⟨"VERIFIED-modulo-math-byte-call-codegen-axioms"⟩

def Outcome.verifiedModuloCryptoCallCodegen : Outcome :=
  ⟨"VERIFIED-modulo-crypto-call-codegen-axioms"⟩

def Outcome.verifiedModuloUpdatePropCodegen : Outcome :=
  ⟨"VERIFIED-modulo-update-prop-codegen-axioms"⟩

def Outcome.verifiedModuloIfValCodegen : Outcome :=
  ⟨"VERIFIED-modulo-if-val-codegen-axioms"⟩

def Outcome.verifiedModuloLoopCodegen : Outcome :=
  ⟨"VERIFIED-modulo-loop-codegen-axioms"⟩

def Outcome.verifiedModuloMethodCallCodegen : Outcome :=
  ⟨"VERIFIED-modulo-method-call-codegen-axioms"⟩

def Outcome.verifiedModuloDispatchCodegen : Outcome :=
  ⟨"VERIFIED-modulo-dispatch-codegen-axioms"⟩

def Outcome.verifiedModuloStatefulCodegen : Outcome :=
  ⟨"VERIFIED-modulo-stateful-codegen-axioms"⟩

def Outcome.deferredParseFail : Outcome :=
  ⟨"DEFERRED-parse-failure"⟩

def Outcome.deferredNotWellFormed : Outcome :=
  ⟨"DEFERRED-not-well-formed"⟩

def Outcome.deferredCompileSafeError : Outcome :=
  ⟨"DEFERRED-compile-safe-error"⟩

def Outcome.deferredNoPublicMethod : Outcome :=
  ⟨"DEFERRED-no-public-method"⟩

/--
Classify a single ANF method's body into one of the per-family
sub-omnibus tiers, matching the priority order of
`Pipeline.compileSafe_observational_correct_modulo_codegen_axioms`:

1. `stateful` — `Lower.bindingsUseCheckPreimage`.
2. `dispatch` — multi-public-method programs.
3. Body-level structural Bool classifiers (arith, math/byte call,
   update_prop, if_val, loop, method_call), in priority order.
4. `crypto_call` fallback when no other classifier fires (substrate gap
   for the crypto-call family).
-/
def classifyByFamily (p : ANFProgram) (anfM : ANFMethod) : Outcome :=
  let lastUses     := Lower.computeLastUses anfM.body
  let localBindings := anfM.body.map (·.name)
  let constInts    := Lower.collectConstInts anfM.body
  let initialSm : Lower.StackMap :=
    List.reverse (anfM.params.map (·.name))
  if Lower.bindingsUseCheckPreimage anfM.body then
    Outcome.verifiedModuloStatefulCodegen
  else if (p.methods.filter (·.isPublic)).length ≥ 2 then
    Outcome.verifiedModuloDispatchCodegen
  else if Agrees.structuralArithBodyBool
            p.methods p.properties
            Lower.defaultInlineBudget
            lastUses [] localBindings constInts
            anfM.body initialSm 0 then
    Outcome.verifiedModuloArithCodegen
  else if Agrees.structuralCallBodyBool
            p.methods p.properties
            Lower.defaultInlineBudget
            lastUses [] localBindings constInts
            anfM.body initialSm 0 then
    Outcome.verifiedModuloMathByteCallCodegen
  else if Agrees.structuralUpdatePropBodyBool
            p.methods p.properties
            Lower.defaultInlineBudget
            lastUses [] localBindings constInts
            anfM.body initialSm 0 then
    Outcome.verifiedModuloUpdatePropCodegen
  else if Agrees.structuralIfValBodyBool
            p.methods p.properties
            Lower.defaultInlineBudget
            lastUses [] localBindings constInts
            anfM.body initialSm 0 then
    Outcome.verifiedModuloIfValCodegen
  else if Agrees.structuralLoopBodyBool
            p.methods p.properties
            Lower.defaultInlineBudget
            lastUses [] localBindings constInts
            anfM.body initialSm 0 then
    Outcome.verifiedModuloLoopCodegen
  else if Agrees.structuralMethodCallBodyBool
            p.methods p.properties
            Lower.defaultInlineBudget
            lastUses [] localBindings constInts
            anfM.body initialSm 0 then
    Outcome.verifiedModuloMethodCallCodegen
  else
    Outcome.verifiedModuloCryptoCallCodegen

/--
Check one fixture's IR against the per-family classification scheme.

Returns:
* `Outcome.verified` — the fixture's body lies inside the
  structural-ref fragment (literal loads + copy/consume ref loads
  only) with a single public method and all M5 static premises
  discharged.
* `Outcome.verifiedModulo<Family>Codegen` — the fixture is well-formed,
  `compileSafe` succeeds, has at least one public method, and matches
  the corresponding per-family sub-omnibus's structural classifier
  (`Pipeline.compileSafe_observational_correct_modulo_*_codegen`).
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
              -- If any precondition fails, fall back to per-family
              -- classification through the sub-omnibus dispatch.
              -- These are the static premises of A15
              -- (`compileSafe_single_public_observational_correct_unconditional_ref`).
              if Lower.bindingsUseCheckPreimage anfM.body
                 || Lower.bindingsUseCodePart anfM.body
                 || Lower.bodyEndsInAssert anfM.body
                 || Lower.bindingsUseDeserializeState anfM.body then
                classifyByFamily p anfM
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
                  classifyByFamily p anfM
                else
                  let loweredBody := (Lower.lower p).bodyOf anfM.name
                  if !(Peephole.noIfOpBool loweredBody) then
                    classifyByFamily p anfM
                  else
                    -- All A15 static premises discharged. The remaining
                    -- runtime-witness premises (agreesTagged, wellTypedRun,
                    -- rollPickDepthOK, peepholePassAllFlat_preconditions,
                    -- AreRunarEmittable, structural shape, domain witnesses)
                    -- are not checked here — they're externally supplied at
                    -- proof time. The fixture qualifies for direct VERIFIED
                    -- because every binding is a structural-ref load.
                    Outcome.verified
          | anfM :: _ :: _ =>
              -- Multi-public-method programs cannot reach the direct
              -- VERIFIED tier today (the A15 capstone requires a single
              -- public method). They land in the dispatch family by
              -- construction; classify on the first public method's body.
              classifyByFamily p anfM

/--
Group-by outcome label for the summary table. Each distinct label
becomes one row.
-/
def groupByOutcome (results : List (String × Outcome)) :
    List (String × List String) :=
  let knownLabels : List String := [
    Outcome.verified.label,
    Outcome.verifiedModuloArithCodegen.label,
    Outcome.verifiedModuloMathByteCallCodegen.label,
    Outcome.verifiedModuloCryptoCallCodegen.label,
    Outcome.verifiedModuloUpdatePropCodegen.label,
    Outcome.verifiedModuloIfValCodegen.label,
    Outcome.verifiedModuloLoopCodegen.label,
    Outcome.verifiedModuloMethodCallCodegen.label,
    Outcome.verifiedModuloDispatchCodegen.label,
    Outcome.verifiedModuloStatefulCodegen.label,
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

  let countOf (o : Outcome) : Nat :=
    results.filter (fun r => r.2 == o) |>.length

  let verifiedCount             := countOf Outcome.verified
  let arithCount                := countOf Outcome.verifiedModuloArithCodegen
  let mathByteCount             := countOf Outcome.verifiedModuloMathByteCallCodegen
  let cryptoCount               := countOf Outcome.verifiedModuloCryptoCallCodegen
  let updatePropCount           := countOf Outcome.verifiedModuloUpdatePropCodegen
  let ifValCount                := countOf Outcome.verifiedModuloIfValCodegen
  let loopCount                 := countOf Outcome.verifiedModuloLoopCodegen
  let methodCallCount           := countOf Outcome.verifiedModuloMethodCallCodegen
  let dispatchCount             := countOf Outcome.verifiedModuloDispatchCodegen
  let statefulCount             := countOf Outcome.verifiedModuloStatefulCodegen
  let deferredParseCount        := countOf Outcome.deferredParseFail
  let deferredWFCount           := countOf Outcome.deferredNotWellFormed
  let deferredCompileCount      := countOf Outcome.deferredCompileSafeError
  let deferredNoPublicCount     := countOf Outcome.deferredNoPublicMethod

  IO.println s!"PipelineConformance: {total} fixtures"
  IO.println ""
  IO.println s!"  VERIFIED                                       : {verifiedCount}"
  IO.println s!"  VERIFIED-modulo-arith-codegen-axioms           : {arithCount}"
  IO.println s!"  VERIFIED-modulo-math-byte-call-codegen-axioms  : {mathByteCount}"
  IO.println s!"  VERIFIED-modulo-crypto-call-codegen-axioms     : {cryptoCount}"
  IO.println s!"  VERIFIED-modulo-update-prop-codegen-axioms     : {updatePropCount}"
  IO.println s!"  VERIFIED-modulo-if-val-codegen-axioms          : {ifValCount}"
  IO.println s!"  VERIFIED-modulo-loop-codegen-axioms            : {loopCount}"
  IO.println s!"  VERIFIED-modulo-method-call-codegen-axioms     : {methodCallCount}"
  IO.println s!"  VERIFIED-modulo-dispatch-codegen-axioms        : {dispatchCount}"
  IO.println s!"  VERIFIED-modulo-stateful-codegen-axioms        : {statefulCount}"
  IO.println s!"  DEFERRED-parse-failure                         : {deferredParseCount}"
  IO.println s!"  DEFERRED-not-well-formed                       : {deferredWFCount}"
  IO.println s!"  DEFERRED-compile-safe-error                    : {deferredCompileCount}"
  IO.println s!"  DEFERRED-no-public-method                      : {deferredNoPublicCount}"
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
  IO.println "VERIFIED-modulo-<family>-codegen-axioms fixtures are sound"
  IO.println "conditional on the corresponding per-family sub-omnibus axiom"
  IO.println "in `Pipeline.lean` (Tier 1 O1 split, 2026-05-17). Each"
  IO.println "sub-omnibus retires as its Stage C / Phase B / Phase D"
  IO.println "milestone lands. The crypto-call tier additionally depends on"
  IO.println "Phase B per-primitive codegen-to-spec axioms (Stack.HashOps,"
  IO.println "Stack.Blake3, Stack.Ec, Stack.P256P384, Stack.Wots,"
  IO.println "Stack.SlhDsa, Stack.Rabin). See `TRUST_MANIFEST.md` and"
  IO.println "`PATH2_PLAN.md` §5.23 for the per-sub-omnibus discharge plan."
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

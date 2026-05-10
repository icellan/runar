import RunarVerification.Pipeline
import RunarVerification.Stack.Agrees
import RunarVerification.Script.Parse

/-!
# Pipeline soundness for the `SimpleANF` subset (Tier 3 of the remediation plan)

This module is the **honest discharged successor** to the four
scaffolding theorems in `Pipeline.lean` (`compile_observational_correct_skeleton`,
`lower_observational_correct_skeleton`,
`peephole_observational_correct_modulo_runMethod_eq`,
`emit_round_trip_skeleton`).

Where the scaffolding theorems take their load-bearing claim as a
hypothesis (`hLowSimulates`, `hPeepEq`, `hRunMethodEq`) and discharge
by `exact` / `successAgrees_refl`, this module's theorems quantify
over normal program-domain constraints (`WF.ANF p`, `SimpleANF p`,
`m ∈ p.methods`) and consume the existing Stage A/B/C/D substrate
in `Stack.Agrees` to deliver `observationallyEqual` between ANF
evaluation and Stack VM execution.

## Status

This is the **first pass** of Tier 3. The substrate already
provides:

* `Stack.Agrees.stageD_simpleANF_full_capstone` (line 4336) —
  proves `runOps (lowerBindings sm body) initialStack = .ok stkFinal`
  ∧ `props/outputs` agreement, given a `ChainRel simpleStepRel ...`
  + `agreesTagged` hypothesis. **This is a real (non-tautological)
  theorem.**
* `Stack.Agrees.agreesTagged_empty_implies_outputs_eq` (line 4699)
  — projects the empty-tsm `agreesTagged` invariant to
  `props/outputs` equality.

Bridging from `lowerBindings` (binding-list level, used in
`Stack.Agrees`) to `runMethod (peepholeProgram (Lower.lower p))`
(method-level pipeline output, used in `Pipeline.lean`) requires:

1. **`Lower.lower_findMethod_lowerMethod`** — for `m ∈ p.methods`
   with `m.isPublic = true`,
   `(Lower.lower p).findMethod m.name = some (lowerMethod p.methods p.properties m)`.
2. **`peepholeProgram_findMethod`** — peephole preserves method
   names; `(peepholeProgram p).findMethod m.name = peepholePassAll ∘ findMethod p m.name`.
3. **`lowerMethod_to_lowerBindings`** — lowerMethod's ops list is
   `lowerBindings sm m.body` modulo post-processing (terminal
   assert elision, NIP cleanup).

Each bridging lemma is multi-day work. This first-pass module
states the target theorem and proves the trivial empty-method case
to establish the proof scaffold and the integration with the 2.2
`observationallyEqual` infrastructure.
-/

namespace RunarVerification.Pipeline.SimpleSoundness

open RunarVerification.ANF
open RunarVerification.Stack
open RunarVerification.Pipeline (compile peepholeProgram)
open RunarVerification.Pipeline.Soundness (Observation Observable observationallyEqual
  observationallyEqual_refl observationallyEqual_trans)

/-! ## Target theorem signatures (Tier 3 items 3.3 + 3.4)

These are the headline theorems the remediation plan promised.
The full proofs require the bridging stack (1-3) above. -/

/- **`compile_observational_correct_simple` (Tier 3 item 3.3)** —
**LANDED** as the headline theorem near the bottom of this module.
Composes `compile_observational_correct_simple_structured` (the
honest hypothesis-form structured composition) with the
`stageC_chain_singleton_*` substrate per-fixture corollaries
(`compile_observational_correct_simple_loadConst_int`,
`_loadConst_bool`, `_loadConst_bytes`, `_loadConst_thisRef`,
`_two_loadConst_int`, etc.) to deliver pipeline-level
`observationallyEqual` between ANF eval and Stack VM execution.

The headline form quantifies over the standard program-domain
constraints (`WF.ANF p`, `SimpleANF p`, `m ∈ p.methods`,
`m.isPublic`, name-uniqueness) plus an existential
`hAnfEvalSucceeds` bundling the Stage A/B/C/D operational
witnesses, plus an honest `hMethodOpsEq` hypothesis (the bridge
from `lowerBindingsP` — used by `lowerMethod` — to `lowerBindings`
— used by Stage C — for the no-post-processing case is mechanical
but not yet landed).

Each per-fixture corollary specialises the headline to a concrete
SimpleANF body shape, internally discharging the existential via
the existing `stageC_chain_singleton_*` substrate. -/

/-! ## Tier 3 bridge lemmas: lifting Stage A/B/C/D to `observationallyEqual`

Two lemmas that close the final step from `Stack.Agrees`'s
props/outputs equality to `observationallyEqual`. Once Stage B
per-construct discharge lands for the SimpleANF subset, these
plus the bridging stack from `lowerBindings` to `runMethod`
deliver the target theorem. -/

/-- The empty-tsm `agreesTagged` invariant lifts to
`observationallyEqual` between the ANF and Stack VM eval results.

Composes `agreesTagged_empty_implies_outputs_eq` (Stack/Agrees.lean:4699)
with the `Observable` projection (Pipeline.lean Soundness namespace). -/
theorem agreesTagged_empty_implies_observationallyEqual
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (h : Stack.Agrees.agreesTagged [] anfSt stkSt) :
    observationallyEqual
      (.ok anfSt : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkSt : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have hOuts := Stack.Agrees.agreesTagged_empty_implies_outputs_eq anfSt stkSt h
  unfold observationallyEqual
  show ({ errorCategory := none, outputs := anfSt.outputs, propsMap := anfSt.props } : Observation)
       = { errorCategory := none, outputs := stkSt.outputs, propsMap := stkSt.props }
  rw [hOuts.1, hOuts.2]

/-- Specialization of `Stack.Agrees.stageD_simpleANF_full_capstone`
to conclude `observationallyEqual` between ANF eval and Stack VM
execution at the binding-list level.

Given the Stage A/B/C/D substrate's `runOps` success + ChainRel +
agreesTagged hypotheses, lifts the props/outputs equality from the
capstone to the typed-projection `observationallyEqual` relation
the 2.2 infrastructure provides. -/
theorem stageD_observationallyEqual_at_bindings_level
    (body : List ANFBinding) (sm : Stack.Lower.StackMap)
    (tsm tsm' : Stack.Agrees.TaggedStackMap)
    (initialAnf anfFinal : ANF.Eval.State)
    (initialStack stkFinal : Stack.Eval.StackState)
    (hRun : Stack.Eval.runOps (Stack.Lower.lowerBindings sm body).1 initialStack = .ok stkFinal)
    (hChain : Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body tsm
                initialAnf initialStack tsm' anfFinal stkFinal)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack) :
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have hCap := Stack.Agrees.stageD_simpleANF_full_capstone
                 body sm tsm tsm' initialAnf anfFinal initialStack stkFinal
                 hRun hChain hAgrees
  unfold observationallyEqual
  show ({ errorCategory := none, outputs := anfFinal.outputs, propsMap := anfFinal.props } : Observation)
       = { errorCategory := none, outputs := stkFinal.outputs, propsMap := stkFinal.props }
  rw [hCap.2.1, hCap.2.2]

/-! ## Bridging lemma 1: `lowerMethod` preserves method name

Trivial structural fact about `lowerMethod`: the resulting `StackMethod`
has the same `name` as the input `ANFMethod`. Used by the next
bridging lemma to push `findMethod`-by-name through the lowering. -/

theorem lowerMethod_preserves_name
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod) :
    (Stack.Lower.lowerMethod progMethods props m).name = m.name := by
  -- `lowerMethod` ends with `{ name := m.name, ops := ops, maxStackDepth := 0 }`.
  rfl

/-! ## Bridging lemma 2: generic `List.find?` with uniquely-matching element

A standard fact about `List.find?`: if exactly one element of a list
satisfies the predicate (and that element is in the list), `find?`
returns it. Used by the next bridging lemma to push `findMethod`
through the `lower` filter+map. -/

theorem List.find?_eq_some_of_unique_match {α : Type}
    (p : α → Bool) (x : α) (xs : List α)
    (hMem : x ∈ xs) (hMatch : p x = true)
    (hUnique : ∀ y ∈ xs, p y = true → y = x) :
    xs.find? p = some x := by
  induction xs with
  | nil => exact absurd hMem (List.not_mem_nil)
  | cons head tail ih =>
      by_cases hp : p head = true
      · -- head matches; uniqueness forces head = x
        have hHeadMem : head ∈ head :: tail := List.Mem.head _
        have hHeadEqX : head = x := hUnique head hHeadMem hp
        rw [List.find?_cons]
        rw [hp]
        exact congrArg some hHeadEqX
      · -- head doesn't match; recurse on tail
        rw [List.find?_cons]
        rw [Bool.not_eq_true] at hp
        rw [hp]
        -- x ∈ tail (since x ≠ head, because p x = true ≠ p head)
        have hXNotHead : x ≠ head := fun h => by
          rw [← h] at hp; rw [hMatch] at hp; exact Bool.noConfusion hp
        have hXInTail : x ∈ tail := by
          cases List.mem_cons.mp hMem with
          | inl h => exact (hXNotHead h).elim
          | inr h => exact h
        apply ih hXInTail
        intros y hy hpy
        exact hUnique y (List.mem_cons_of_mem _ hy) hpy

/-! ## Bridging lemma 3: `Lower.lower`'s `findMethod` for public members

For any `m ∈ p.methods` with `m.isPublic = true`, plus uniqueness of
public-method names, `Lower.lower p`'s `findMethod m.name` returns
the lowered `m`. -/

theorem lower_findMethod_of_member
    (p : ANFProgram) (m : ANFMethod)
    (hMember : m ∈ p.methods) (hPublic : m.isPublic = true)
    (hUnique :
        ∀ m' ∈ p.methods,
          m'.isPublic = true → m'.name = m.name → m' = m) :
    (Stack.Lower.lower p).findMethod m.name =
      some (Stack.Lower.lowerMethod p.methods p.properties m) := by
  unfold Stack.Lower.lower Stack.StackProgram.findMethod
  -- Goal now: ((p.methods.filter ...).map lowerMethod).find? ... = some (lowerMethod m)
  apply List.find?_eq_some_of_unique_match
  · -- membership: lowerMethod m is in the lowered list
    apply List.mem_map.mpr
    refine ⟨m, ?_, rfl⟩
    exact List.mem_filter.mpr ⟨hMember, by simp [hPublic]⟩
  · -- match: predicate (·.name == m.name) holds at lowerMethod m
    have : (Stack.Lower.lowerMethod p.methods p.properties m).name = m.name :=
      lowerMethod_preserves_name p.methods p.properties m
    show ((Stack.Lower.lowerMethod p.methods p.properties m).name == m.name) = true
    rw [this]
    exact beq_self_eq_true _
  · -- uniqueness over the lowered list
    intros y hy hy_match
    obtain ⟨m', hm'_filter, hm'_eq⟩ := List.mem_map.mp hy
    have hMemPub := List.mem_filter.mp hm'_filter
    have hMemP : m' ∈ p.methods := hMemPub.1
    have hPub' : m'.isPublic = true := by
      have := hMemPub.2; simp at this; exact this
    have hNameEq : m'.name = m.name := by
      -- hy_match : (y.name == m.name) = true ; hm'_eq : lowerMethod m' = y
      -- rewrite y to lowerMethod m', then use lowerMethod_preserves_name
      have h1 : ((Stack.Lower.lowerMethod p.methods p.properties m').name == m.name) = true := by
        rw [hm'_eq]; exact hy_match
      rw [lowerMethod_preserves_name] at h1
      exact beq_iff_eq.mp h1
    have hM'EqM : m' = m := hUnique m' hMemP hPub' hNameEq
    rw [← hm'_eq, hM'EqM]

/-! ## Bridging lemma 4: `peepholeProgram` preserves method-name lookup

`peepholeProgram` rebuilds each method with a transformed `ops` list,
keeping `name` unchanged. So `findMethod name` on the peephole-program
returns `some (m with ops := transformed)` whenever the input had
`some m`. -/

/-- The peephole transformation applied to a single method. Mirrors
the `fun m => { m with ops := ... }` map in `peepholeProgram`. -/
def peepholeMethod (m : Stack.StackMethod) : Stack.StackMethod :=
  let newOps := Stack.Peephole.peepholeRollPickFold
                  (Stack.Peephole.peepholeChainFold
                    (Stack.Peephole.peepholePostFold
                      (Stack.Peephole.peepholePassAll m.ops)))
  { m with ops := newOps }

theorem peepholeMethod_preserves_name (m : Stack.StackMethod) :
    (peepholeMethod m).name = m.name := rfl

theorem peepholeProgram_findMethod (p : Stack.StackProgram) (name : String) :
    (peepholeProgram p).findMethod name =
      (p.findMethod name).map peepholeMethod := by
  unfold peepholeProgram Stack.StackProgram.findMethod
  -- Goal: (p.methods.map (fun m => { m with ops := ... })).find? (·.name == name)
  --     = (p.methods.find? (·.name == name)).map peepholeMethod
  -- Note: the `fun m => { m with ops := ... }` IS exactly `peepholeMethod`.
  show (p.methods.map peepholeMethod).find? (·.name == name)
       = (p.methods.find? (·.name == name)).map peepholeMethod
  rw [List.find?_map]
  -- Predicate composition: (·.name == name) ∘ peepholeMethod simplifies because
  -- peepholeMethod preserves name.
  have hPredEq :
      ((fun x : Stack.StackMethod => x.name == name) ∘ peepholeMethod)
      = (fun x : Stack.StackMethod => x.name == name) := by
    funext m
    show ((peepholeMethod m).name == name) = (m.name == name)
    rw [peepholeMethod_preserves_name]
  rw [hPredEq]

/-! ## Composition: pipeline-level `runMethod` reduces to bindings-level `runOps`

Composing bridging lemmas 3 + 4: `runMethod` on the full pipeline
output reduces to `runOps` on the peephole-applied lowered method's
ops. This is the bridge from the pipeline-level form (used in
`compile_observational_correct_skeleton`) to the bindings-level form
(used in the Stack.Agrees Stage D substrate). -/

theorem runMethod_pipeline_eq
    (p : ANFProgram) (m : ANFMethod)
    (hMember : m ∈ p.methods) (hPublic : m.isPublic = true)
    (hUnique :
        ∀ m' ∈ p.methods,
          m'.isPublic = true → m'.name = m.name → m' = m)
    (initialStack : Stack.Eval.StackState) :
    Stack.Eval.runMethod (peepholeProgram (Stack.Lower.lower p)) m.name initialStack
    = Stack.Eval.runOps
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        initialStack := by
  -- runMethod p m s = runOps (p.bodyOf m.name) s
  unfold Stack.Eval.runMethod Stack.StackProgram.bodyOf
  -- Goal: runOps (match findMethod m.name with ... ) initialStack = runOps (peepholeMethod _ _).ops _
  -- Use peepholeProgram_findMethod to push the peephole through findMethod.
  rw [peepholeProgram_findMethod]
  -- Now: match (Lower.lower p).findMethod m.name with ... |>.map peepholeMethod
  -- Use lower_findMethod_of_member to conclude (Lower.lower p).findMethod = some (lowerMethod ...).
  rw [lower_findMethod_of_member p m hMember hPublic hUnique]
  -- Now: match (some (lowerMethod ...)).map peepholeMethod with ... = runOps (peepholeMethod ...).ops
  rfl

/-! ## Tier 3 composition: `compile_observational_correct_simple_structured`

The honest hypothesis-form of `compile_observational_correct_simple`,
restructured around the genuine remaining subgoals (Stage B
ChainRel discharge + peephole post-pass soundness) instead of the
useless `hLowSimulates`/`hPeepEq` from the scaffolding form.

Compared to `compile_observational_correct_skeleton` in `Pipeline.lean`:

| Hypothesis | Skeleton | Structured (this lemma) |
|------------|----------|-------------------------|
| Lowering simulation | `hLowSimulates` (= the entire goal) | `hChain` + `hAgrees` (Stage A/B/C/D obligations) |
| Peephole equivalence | `hPeepEq` (= the entire goal) | `hPeepholeRunOpsEq` (single `runOps` equality, Tier 3 item 3.2) |

This is **strictly more honest** than the scaffolding: discharging
`hChain` + `hAgrees` requires actual Stage B per-construct work
(not a tautology); discharging `hPeepholeRunOpsEq` requires actual
peephole post-pass soundness proofs. The skeleton's hypotheses
were the goal itself; this lemma's hypotheses are real obligations.
-/

theorem compile_observational_correct_simple_structured
    (p : ANFProgram) (m : ANFMethod)
    (hMember : m ∈ p.methods) (hPublic : m.isPublic = true)
    (hUnique :
        ∀ m' ∈ p.methods,
          m'.isPublic = true → m'.name = m.name → m' = m)
    (sm : Stack.Lower.StackMap)
    (tsm tsm' : Stack.Agrees.TaggedStackMap)
    (initialAnf anfFinal : ANF.Eval.State)
    (initialStack stkFinal : Stack.Eval.StackState)
    (hRunPre :
        Stack.Eval.runOps (Stack.Lower.lowerBindings sm m.body).1 initialStack
        = .ok stkFinal)
    (hChain :
        Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel m.body tsm
          initialAnf initialStack tsm' anfFinal stkFinal)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings sm m.body).1)
    (hAnfEvalEq :
        RunarVerification.ANF.Eval.evalBindings initialAnf m.body = .ok anfFinal) :
    observationallyEqual
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  -- Step 1: pipeline-level runMethod reduces to bindings-level runOps via
  -- runMethod_pipeline_eq (composition of bridging lemmas 3 + 4).
  rw [runMethod_pipeline_eq p m hMember hPublic hUnique initialStack]
  -- Step 2: peephole-applied ops coincide with raw lowerBindings ops
  -- (hMethodOpsEq — discharged by Tier 3 item 3.2 + bridging lemma 5).
  rw [hMethodOpsEq]
  -- Step 3: ANF evaluation reduces to .ok anfFinal (hAnfEvalEq —
  -- discharged by callers via Stage B per-construct execution).
  rw [hAnfEvalEq, hRunPre]
  -- Step 4: lift the props/outputs equality from Stage D capstone to
  -- observationallyEqual.
  exact stageD_observationallyEqual_at_bindings_level
    m.body sm tsm tsm' initialAnf anfFinal initialStack stkFinal
    hRunPre hChain hAgrees

/-! ## Bridging lemma 5 — `lowerMethod_ops_trivial_case`

For methods with no preimage/codePart references, no terminal-assert
elision firing, and no NIP cleanup, `lowerMethod`'s post-processing
collapses to identity: the output `ops` field equals
`(lowerBindingsP ... userMap m.body).1` directly. -/

theorem lowerMethod_ops_trivial_case
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoAssertElide : ¬ (m.isPublic = true ∧
                         Stack.Lower.bodyEndsInAssert m.body = true))
    (hNoDeserialize : ¬ (m.isPublic = true ∧
                         Stack.Lower.bindingsUseDeserializeState m.body = true)) :
    (Stack.Lower.lowerMethod progMethods props m).ops =
      (Stack.Lower.lowerBindingsP progMethods props
        Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses m.body) []
        (m.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts m.body)
        ((m.params.map (fun p => p.name)).reverse)
        m.body).1 := by
  -- Force booleans to known values so the post-processing gates collapse.
  have hAssertElideFalse :
      (m.isPublic && Stack.Lower.bodyEndsInAssert m.body) = false := by
    cases hPub : m.isPublic with
    | false => rfl
    | true =>
        have hEnds : Stack.Lower.bodyEndsInAssert m.body = false := by
          cases hCases : Stack.Lower.bodyEndsInAssert m.body with
          | false => rfl
          | true  => exact absurd ⟨hPub, hCases⟩ hNoAssertElide
        rw [hEnds]; rfl
  have hDeserGateFalse :
      (m.isPublic && Stack.Lower.bindingsUseDeserializeState m.body) = false := by
    cases hPub : m.isPublic with
    | false => rfl
    | true =>
        have hDes : Stack.Lower.bindingsUseDeserializeState m.body = false := by
          cases hCases : Stack.Lower.bindingsUseDeserializeState m.body with
          | false => rfl
          | true  => exact absurd ⟨hPub, hCases⟩ hNoDeserialize
        rw [hDes]; rfl
  unfold Stack.Lower.lowerMethod
  simp only [hNoPreimage, Bool.false_eq_true, ↓reduceIte]
  -- Now `initialMap = userMap`. Both elide and NIP gates carry the
  -- `m.isPublic && ...` prefix, which is handled by hAssertElideFalse /
  -- hDeserGateFalse.
  simp only [hAssertElideFalse, hDeserGateFalse, Bool.false_and,
             Bool.false_eq_true, ↓reduceIte]
  -- Final shape: `(rawOps ++ List.replicate 0 .nip) = rawOps`.
  simp [List.replicate]

/-! ## First end-to-end Stage C list-level chain (singleton SimpleANF body)

Composes the per-binding `stageC_simpleStep_loadConst_int` (operational
discharge from `Stack.Agrees`) with `chainRel_cons` + `chainRel_nil`
+ `runOps_lowerBindings_singleton` to deliver a fully-discharged
ChainRel + runOps witness for a one-binding body.

This is the first concrete operational+predicate Stage C discharge
for a SimpleANF binding list. Combined with
`stageD_observationallyEqual_at_bindings_level`, it produces
`observationallyEqual` between ANF eval and Stack VM execution for
the body `[loadConst .int i]` — the smallest non-trivial SimpleANF
program. -/

theorem stageC_chain_singleton_loadConst_int
    (bn : String) (i : Int)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm)) :
    let body := [(ANFBinding.mk bn (.loadConst (.int i)) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint i)
    let anfFinal := anfSt.addBinding bn (.vBigint i)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  -- Per-binding operational + relational discharge from Stack.Agrees.
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_int
                  bn i tsm anfSt stkSt hFresh
  refine ⟨?_, ?_⟩
  · -- Run the lowered singleton body
    apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · -- Build ChainRel via cons + nil
    apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

/-- Composing the singleton-chain with Stage D capstone: the ANF eval
of `[loadConst .int i]` is `observationallyEqual` to the Stack VM
execution of the lowered body. **First end-to-end operational
soundness for a real (if minimal) SimpleANF program.** -/
theorem observationallyEqual_singleton_loadConst_int
    (bn : String) (i : Int)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt) :
    let stkFinal := stkSt.push (.vBigint i)
    let anfFinal := anfSt.addBinding bn (.vBigint i)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := stageC_chain_singleton_loadConst_int bn i tsm anfSt stkSt hFresh
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst (.int i)) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn (.vBigint i))
    stkSt (stkSt.push (.vBigint i))
    hRun hChain hAgrees

/-! ## Stage C list-level chains for additional `loadConst` variants

Same pattern as the `_int` case — combine the per-binding stageC
operational discharge with `chainRel_cons` + `chainRel_nil` +
`runOps_lowerBindings_singleton`. -/

theorem stageC_chain_singleton_loadConst_bool
    (bn : String) (flag : Bool)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm)) :
    let body := [(ANFBinding.mk bn (.loadConst (.bool flag)) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBool flag)
    let anfFinal := anfSt.addBinding bn (.vBool flag)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_bool
                  bn flag tsm anfSt stkSt hFresh
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem stageC_chain_singleton_loadConst_bytes
    (bn : String) (ba : ByteArray)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm)) :
    let body := [(ANFBinding.mk bn (.loadConst (.bytes ba)) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBytes ba)
    let anfFinal := anfSt.addBinding bn (.vBytes ba)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_bytes
                  bn ba tsm anfSt stkSt hFresh
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

/-! ## `observationallyEqual` corollaries — singleton bodies of each
loadConst variant. These are the smallest fully-discharged operational
soundness theorems for SimpleANF programs. -/

theorem observationallyEqual_singleton_loadConst_bool
    (bn : String) (flag : Bool)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt) :
    let stkFinal := stkSt.push (.vBool flag)
    let anfFinal := anfSt.addBinding bn (.vBool flag)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := stageC_chain_singleton_loadConst_bool bn flag tsm anfSt stkSt hFresh
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst (.bool flag)) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn (.vBool flag))
    stkSt (stkSt.push (.vBool flag))
    hRun hChain hAgrees

theorem observationallyEqual_singleton_loadConst_bytes
    (bn : String) (ba : ByteArray)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt) :
    let stkFinal := stkSt.push (.vBytes ba)
    let anfFinal := anfSt.addBinding bn (.vBytes ba)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := stageC_chain_singleton_loadConst_bytes bn ba tsm anfSt stkSt hFresh
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst (.bytes ba)) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn (.vBytes ba))
    stkSt (stkSt.push (.vBytes ba))
    hRun hChain hAgrees

/-! ## Two-binding `observationallyEqual` — `[loadConst .int i1, loadConst .int i2]`

Lifts `Stack.Agrees.stageC_two_loadConst_int` (existing Phase 7.6.c
multi-binding ChainRel demonstration) to `observationallyEqual`.
This is the first 2-binding fully-discharged operational soundness
for a SimpleANF program in the codebase. -/

theorem observationallyEqual_two_loadConst_int
    (bn1 bn2 : String) (i1 i2 : Int)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt) :
    let stkFinal := (stkSt.push (.vBigint i1)).push (.vBigint i2)
    let anfFinal :=
      (anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_two_loadConst_int
                            bn1 bn2 i1 i2 tsm anfSt stkSt hFresh1 hFresh2
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
     (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn2, Stack.Agrees.SlotKind.binding) ::
         (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt ((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2))
    stkSt ((stkSt.push (.vBigint i1)).push (.vBigint i2))
    hRun hChain hAgrees

/-! ## Mixed-constructor observationally-equal: `[loadConst .int i, unaryOp "-" t0]`

Lifts `Stack.Agrees.stageC_mixed_loadConst_unaryNegate` (existing
Phase 7.6.e mixed-constructor demonstration) to
`observationallyEqual`. The first 2-binding mixed-constructor
fully-discharged operational soundness for a SimpleANF program. -/

theorem observationallyEqual_mixed_loadConst_unaryNegate
    (bn1 bn2 : String) (i : Int) (rt : Option String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm))
          bn1 = [.dup]) :
    let stkFinal := (stkSt.push (.vBigint i)).push (.vBigint (-i))
    let anfFinal :=
      (anfSt.addBinding bn1 (.vBigint i)).addBinding bn2 (.vBigint (-i))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_mixed_loadConst_unaryNegate
    bn1 bn2 i rt tsm anfSt stkSt hAgrees hFresh1 hFresh2 hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i)) none : ANFBinding),
     (ANFBinding.mk bn2 (.unaryOp "-" bn1 rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn2, Stack.Agrees.SlotKind.binding) ::
     (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt
    ((anfSt.addBinding bn1 (.vBigint i)).addBinding bn2 (.vBigint (-i)))
    stkSt
    ((stkSt.push (.vBigint i)).push (.vBigint (-i)))
    hRun hChain hAgrees

/-! ## Tier 3.1 — Three-binding `[loadConst i1; loadConst i2; binOp "+" t0 t1]`

Lifts `Stack.Agrees.stageC_three_loadConst_binOp_ADD` (Tier 3.1 Stage B
3-binding chain) to `observationallyEqual`. The first 3-binding
fully-discharged SimpleANF body that exercises both `loadConst` and
`binOp` constructors. -/

theorem observationallyEqual_three_loadConst_binOp_ADD
    (bn1 bn2 bn3 : String) (i1 i2 : Int) (rt : Option String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh3 : Stack.Agrees.freshIn bn3
        (Stack.Agrees.untagSm
          ((bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn1
          = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (bn1 :: Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn2
          = [.over]) :
    let stkFinal := ((stkSt.push (.vBigint i1)).push (.vBigint i2)).push
                       (.vBigint (i1 + i2))
    let anfFinal := ((anfSt.addBinding bn1 (.vBigint i1)).addBinding
                       bn2 (.vBigint i2)).addBinding bn3 (.vBigint (i1 + i2))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_three_loadConst_binOp_ADD
    bn1 bn2 bn3 i1 i2 rt tsm anfSt stkSt hAgrees
    hFresh1 hFresh2 hFresh3 hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
     (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding),
     (ANFBinding.mk bn3 (.binOp "+" bn1 bn2 rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn3, Stack.Agrees.SlotKind.binding) ::
     (bn2, Stack.Agrees.SlotKind.binding) ::
     (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt
    (((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)).addBinding
       bn3 (.vBigint (i1 + i2)))
    stkSt
    (((stkSt.push (.vBigint i1)).push (.vBigint i2)).push (.vBigint (i1 + i2)))
    hRun hChain hAgrees

/-! ## Tier 3.1 extension — Three-binding `observationallyEqual` for SUB / MUL / LESSTHAN

Mirrors `observationallyEqual_three_loadConst_binOp_ADD` for the
remaining d1d0 binOps that have a per-step lemma. -/

theorem observationallyEqual_three_loadConst_binOp_SUB
    (bn1 bn2 bn3 : String) (i1 i2 : Int) (rt : Option String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh3 : Stack.Agrees.freshIn bn3
        (Stack.Agrees.untagSm
          ((bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn1
          = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (bn1 :: Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn2
          = [.over]) :
    let stkFinal := ((stkSt.push (.vBigint i1)).push (.vBigint i2)).push
                       (.vBigint (i1 - i2))
    let anfFinal := ((anfSt.addBinding bn1 (.vBigint i1)).addBinding
                       bn2 (.vBigint i2)).addBinding bn3 (.vBigint (i1 - i2))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_three_loadConst_binOp_SUB
    bn1 bn2 bn3 i1 i2 rt tsm anfSt stkSt hAgrees
    hFresh1 hFresh2 hFresh3 hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
     (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding),
     (ANFBinding.mk bn3 (.binOp "-" bn1 bn2 rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn3, Stack.Agrees.SlotKind.binding) ::
     (bn2, Stack.Agrees.SlotKind.binding) ::
     (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt
    (((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)).addBinding
       bn3 (.vBigint (i1 - i2)))
    stkSt
    (((stkSt.push (.vBigint i1)).push (.vBigint i2)).push (.vBigint (i1 - i2)))
    hRun hChain hAgrees

theorem observationallyEqual_three_loadConst_binOp_MUL
    (bn1 bn2 bn3 : String) (i1 i2 : Int) (rt : Option String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh3 : Stack.Agrees.freshIn bn3
        (Stack.Agrees.untagSm
          ((bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn1
          = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (bn1 :: Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn2
          = [.over]) :
    let stkFinal := ((stkSt.push (.vBigint i1)).push (.vBigint i2)).push
                       (.vBigint (i1 * i2))
    let anfFinal := ((anfSt.addBinding bn1 (.vBigint i1)).addBinding
                       bn2 (.vBigint i2)).addBinding bn3 (.vBigint (i1 * i2))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_three_loadConst_binOp_MUL
    bn1 bn2 bn3 i1 i2 rt tsm anfSt stkSt hAgrees
    hFresh1 hFresh2 hFresh3 hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
     (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding),
     (ANFBinding.mk bn3 (.binOp "*" bn1 bn2 rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn3, Stack.Agrees.SlotKind.binding) ::
     (bn2, Stack.Agrees.SlotKind.binding) ::
     (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt
    (((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)).addBinding
       bn3 (.vBigint (i1 * i2)))
    stkSt
    (((stkSt.push (.vBigint i1)).push (.vBigint i2)).push (.vBigint (i1 * i2)))
    hRun hChain hAgrees

theorem observationallyEqual_three_loadConst_binOp_LESSTHAN
    (bn1 bn2 bn3 : String) (i1 i2 : Int) (rt : Option String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh3 : Stack.Agrees.freshIn bn3
        (Stack.Agrees.untagSm
          ((bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn1
          = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (bn1 :: Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn2
          = [.over]) :
    let stkFinal := ((stkSt.push (.vBigint i1)).push (.vBigint i2)).push
                       (.vBool (decide (i1 < i2)))
    let anfFinal := ((anfSt.addBinding bn1 (.vBigint i1)).addBinding
                       bn2 (.vBigint i2)).addBinding bn3 (.vBool (decide (i1 < i2)))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_three_loadConst_binOp_LESSTHAN
    bn1 bn2 bn3 i1 i2 rt tsm anfSt stkSt hAgrees
    hFresh1 hFresh2 hFresh3 hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
     (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding),
     (ANFBinding.mk bn3 (.binOp "<" bn1 bn2 rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn3, Stack.Agrees.SlotKind.binding) ::
     (bn2, Stack.Agrees.SlotKind.binding) ::
     (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt
    (((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)).addBinding
       bn3 (.vBool (decide (i1 < i2))))
    stkSt
    (((stkSt.push (.vBigint i1)).push (.vBigint i2)).push (.vBool (decide (i1 < i2))))
    hRun hChain hAgrees

/-! ## Tier 3.1 extension — Five-binding chain composing two binOps

Lifts `Stack.Agrees.stageC_five_loadConst_binOp_addThenMul` (a 5-binding
chain `[loadConst i1, loadConst i2, binOp "+" t0 t1, loadConst i3,
binOp "*" t2 t3]`) to `observationallyEqual`. Demonstrates that
per-binding stageC lemmas compose recursively across mixed operators
(both ADD and MUL d1d0) in a single body. -/

theorem observationallyEqual_four_loadConst_binOp_chain
    (bn1 bn2 bn3 bn4 bn5 : String) (i1 i2 i3 : Int) (rt rt' : Option String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh3 : Stack.Agrees.freshIn bn3
        (Stack.Agrees.untagSm
          ((bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh4 : Stack.Agrees.freshIn bn4
        (Stack.Agrees.untagSm
          ((bn3, Stack.Agrees.SlotKind.binding) ::
           (bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hFresh5 : Stack.Agrees.freshIn bn5
        (Stack.Agrees.untagSm
          ((bn4, Stack.Agrees.SlotKind.binding) ::
           (bn3, Stack.Agrees.SlotKind.binding) ::
           (bn2, Stack.Agrees.SlotKind.binding) ::
           (bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hLoadRefL_add :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn1
          = [.over])
    (hLoadRefR_add :
        Stack.Lower.loadRef
          (bn1 :: Stack.Agrees.untagSm
            ((bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn2
          = [.over])
    (hLoadRefL_mul :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((bn4, Stack.Agrees.SlotKind.binding) ::
             (bn3, Stack.Agrees.SlotKind.binding) ::
             (bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn3
          = [.over])
    (hLoadRefR_mul :
        Stack.Lower.loadRef
          (bn3 :: Stack.Agrees.untagSm
            ((bn4, Stack.Agrees.SlotKind.binding) ::
             (bn3, Stack.Agrees.SlotKind.binding) ::
             (bn2, Stack.Agrees.SlotKind.binding) ::
             (bn1, Stack.Agrees.SlotKind.binding) :: tsm)) bn4
          = [.over]) :
    let v3 := i1 + i2
    let v5 := v3 * i3
    let stkFinal := ((((stkSt.push (.vBigint i1)).push (.vBigint i2)).push
                        (.vBigint v3)).push (.vBigint i3)).push (.vBigint v5)
    let anfFinal :=
      ((((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)).addBinding
          bn3 (.vBigint v3)).addBinding bn4 (.vBigint i3)).addBinding bn5 (.vBigint v5)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_five_loadConst_binOp_addThenMul
    bn1 bn2 bn3 bn4 bn5 i1 i2 i3 rt rt' tsm anfSt stkSt hAgrees
    hFresh1 hFresh2 hFresh3 hFresh4 hFresh5
    hLoadRefL_add hLoadRefR_add hLoadRefL_mul hLoadRefR_mul
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
     (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding),
     (ANFBinding.mk bn3 (.binOp "+" bn1 bn2 rt) none : ANFBinding),
     (ANFBinding.mk bn4 (.loadConst (.int i3)) none : ANFBinding),
     (ANFBinding.mk bn5 (.binOp "*" bn3 bn4 rt') none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn5, Stack.Agrees.SlotKind.binding) ::
     (bn4, Stack.Agrees.SlotKind.binding) ::
     (bn3, Stack.Agrees.SlotKind.binding) ::
     (bn2, Stack.Agrees.SlotKind.binding) ::
     (bn1, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt
    (((((anfSt.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)).addBinding
        bn3 (.vBigint (i1 + i2))).addBinding bn4 (.vBigint i3)).addBinding bn5
        (.vBigint ((i1 + i2) * i3)))
    stkSt
    (((((stkSt.push (.vBigint i1)).push (.vBigint i2)).push (.vBigint (i1 + i2))).push
        (.vBigint i3)).push (.vBigint ((i1 + i2) * i3)))
    hRun hChain hAgrees

/-! ## `loadConst .thisRef` singleton-chain + `observationallyEqual`

The 4th `loadConst` variant. Note: thisRef emits no stack ops
(reduces to `runOps []`), and `simpleStepRel` for thisRef leaves
`tsm` unchanged. -/

theorem stageC_chain_singleton_loadConst_thisRef
    (bn : String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm)) :
    let body := [(ANFBinding.mk bn (.loadConst .thisRef) none : ANFBinding)]
    let anfFinal := anfSt.addBinding bn .vThis
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkSt
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm anfFinal stkSt := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_thisRef
                  bn tsm anfSt stkSt hFresh
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadConst_thisRef
    (bn : String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt) :
    let anfFinal := anfSt.addBinding bn .vThis
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkSt : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ := stageC_chain_singleton_loadConst_thisRef bn tsm anfSt stkSt hFresh
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst .thisRef) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm tsm
    anfSt (anfSt.addBinding bn .vThis)
    stkSt stkSt
    hRun hChain hAgrees

/-! ## Tier 3.1 — `.loop 0 [] iter` (vacuous loop) singleton-chain +
`observationallyEqual`

The smallest case of `.loop`: `count = 0` with empty body. Per
`runLoop 0 = .ok s`, the ANF evaluator binds the synthetic
`.vBool true` without touching state. The lowering
`unrollIter [] 0 = []` emits no opcodes, so the Stack VM stack is
unchanged — same shape as `.loadConst .thisRef` and `.assert`. -/

theorem stageC_chain_singleton_loop_zero_emptyBody
    (bn iter : String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm)) :
    let body := [(ANFBinding.mk bn (.loop 0 [] iter) none : ANFBinding)]
    let anfFinal := anfSt.addBinding bn (.vBool true)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkSt
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm anfFinal stkSt := by
  have hStep := Stack.Agrees.stageC_simpleStep_loop_zero_emptyBody
                  bn iter tsm anfSt stkSt hFresh
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loop_zero_emptyBody
    (bn iter : String)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt) :
    let anfFinal := anfSt.addBinding bn (.vBool true)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkSt : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loop_zero_emptyBody bn iter tsm anfSt stkSt hFresh
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loop 0 [] iter) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm tsm
    anfSt (anfSt.addBinding bn (.vBool true))
    stkSt stkSt
    hRun hChain hAgrees

/-! ## `loadParam` / `loadProp` / `loadConst .refAlias` at depth 0

Lifts the depth-0 per-binding stageC discharges (which require the
referenced name to be at the top of the stack-map) to singleton
chains and `observationallyEqual`. -/

theorem stageC_chain_singleton_loadParam_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let body := [(ANFBinding.mk bn (.loadParam n) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm := ((n, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadParam_d0
                  bn n k tsm_rest anfSt stkSt v hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadParam_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadParam_d0 bn n k tsm_rest anfSt stkSt v
      hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadParam n) none : ANFBinding)]
    (Stack.Agrees.untagSm ((n, k) :: tsm_rest))
    ((n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

/-! ## `loadProp` and `loadConst .refAlias` at depth 0 — same shape as loadParam

Same pattern as `loadParam_d0`: the per-binding stageC discharge from
Stack.Agrees gives runOps + simpleStepRel; we lift to chain-of-1 +
observationallyEqual via the standard composition. -/

theorem stageC_chain_singleton_loadProp_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let body := [(ANFBinding.mk bn (.loadProp n) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm := ((n, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadProp_d0
                  bn n k tsm_rest anfSt stkSt v hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadProp_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadProp_d0 bn n k tsm_rest anfSt stkSt v
      hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadProp n) none : ANFBinding)]
    (Stack.Agrees.untagSm ((n, k) :: tsm_rest))
    ((n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

theorem stageC_chain_singleton_loadConst_refAlias_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let body :=
      [(ANFBinding.mk bn (.loadConst (.refAlias n)) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm := ((n, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_refAlias_d0
                  bn n k tsm_rest anfSt stkSt v hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadConst_refAlias_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_refAlias_d0 bn n k tsm_rest anfSt stkSt v
      hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst (.refAlias n)) none : ANFBinding)]
    (Stack.Agrees.untagSm ((n, k) :: tsm_rest))
    ((n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

/-! ## Depth-1 lifts

When the referenced operand is at depth 1 of the stack-map,
`loadRef` emits `[.over]`. Stage C operational discharge comes
from `Stack.Agrees.stageC_simpleStep_*_d1`; we lift to a singleton
ChainRel + runOps witness, then to `observationallyEqual` via
`stageD_observationallyEqual_at_bindings_level`. -/

theorem stageC_chain_singleton_loadParam_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let body := [(ANFBinding.mk bn (.loadParam n) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm := ((topName, k_top) :: (n, k) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadParam_d1
                  bn topName n k_top k tsm_rest anfSt stkSt v
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadParam_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadParam_d1 bn topName n k_top k tsm_rest
      anfSt stkSt v hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadParam n) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
    ((topName, k_top) :: (n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

theorem stageC_chain_singleton_loadProp_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let body := [(ANFBinding.mk bn (.loadProp n) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm := ((topName, k_top) :: (n, k) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadProp_d1
                  bn topName n k_top k tsm_rest anfSt stkSt v
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadProp_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadProp_d1 bn topName n k_top k tsm_rest
      anfSt stkSt v hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadProp n) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
    ((topName, k_top) :: (n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

theorem stageC_chain_singleton_loadConst_refAlias_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let body :=
      [(ANFBinding.mk bn (.loadConst (.refAlias n)) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm := ((topName, k_top) :: (n, k) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_refAlias_d1
                  bn topName n k_top k tsm_rest anfSt stkSt v
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadConst_refAlias_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_refAlias_d1 bn topName n k_top k tsm_rest
      anfSt stkSt v hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst (.refAlias n)) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
    ((topName, k_top) :: (n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

/-! ## Depth-≥2 lifts

When the operand sits at arbitrary depth `d ≥ 2`, `loadRef` emits
`[.pickStruct d]`. The Stage C per-binding discharge takes `nthOpt
d tsm = some (n, k)` (the operand-at-depth witness) instead of the
shape-restricted hypothesis used in the d0/d1 cases. -/

theorem stageC_chain_singleton_loadParam_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let body := [(ANFBinding.mk bn (.loadParam n) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadParam_dge2
                  bn n k d tsm anfSt stkSt v
                  hAgrees hAtDepth hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadParam_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadParam_dge2 bn n k d tsm anfSt stkSt v
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadParam n) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

theorem stageC_chain_singleton_loadProp_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let body := [(ANFBinding.mk bn (.loadProp n) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadProp_dge2
                  bn n k d tsm anfSt stkSt v
                  hAgrees hAtDepth hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadProp_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadProp_dge2 bn n k d tsm anfSt stkSt v
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadProp n) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

theorem stageC_chain_singleton_loadConst_refAlias_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let body :=
      [(ANFBinding.mk bn (.loadConst (.refAlias n)) none : ANFBinding)]
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_loadConst_refAlias_dge2
                  bn n k d tsm anfSt stkSt v
                  hAgrees hAtDepth hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_loadConst_refAlias_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState) (v : ANF.Eval.Value)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let stkFinal := stkSt.push v
    let anfFinal := anfSt.addBinding bn v
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_refAlias_dge2 bn n k d tsm anfSt stkSt v
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.loadConst (.refAlias n)) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn v)
    stkSt (stkSt.push v)
    hRun hChain hAgrees

/-! ## `unaryOp` NEGATE / NOT lifts at d0 / d1 / dge2

`unaryOp "-" n rt` lowers to `loadRef sm n ++ [.opcode "OP_NEGATE"]`,
producing `vBigint (-i)` on the stack from operand `vBigint i`.
`unaryOp "!"` is the analogous case for `vBool` operand using
`OP_NOT`. Each follows the standard chain_singleton pattern: the
per-binding stageC discharge from `Stack.Agrees` already chains
load + opcode and yields the post-state directly. -/

theorem stageC_chain_singleton_unaryOp_NEGATE_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBigint i))
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let body := [(ANFBinding.mk bn (.unaryOp "-" n rt) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (-i))
    let anfFinal := anfSt.addBinding bn (.vBigint (-i))
    let tsm := ((n, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_unaryOp_NEGATE_d0
                  bn n k tsm_rest anfSt stkSt i rt
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_unaryOp_NEGATE_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBigint i))
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let stkFinal := stkSt.push (.vBigint (-i))
    let anfFinal := anfSt.addBinding bn (.vBigint (-i))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_unaryOp_NEGATE_d0 bn n k tsm_rest
      anfSt stkSt i rt hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.unaryOp "-" n rt) none : ANFBinding)]
    (Stack.Agrees.untagSm ((n, k) :: tsm_rest))
    ((n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBigint (-i)))
    stkSt (stkSt.push (.vBigint (-i)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_unaryOp_NOT_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (b : Bool) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool b))
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let body := [(ANFBinding.mk bn (.unaryOp "!" n rt) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (!b))
    let anfFinal := anfSt.addBinding bn (.vBool (!b))
    let tsm := ((n, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_unaryOp_NOT_d0
                  bn n k tsm_rest anfSt stkSt b rt
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_unaryOp_NOT_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (b : Bool) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool b))
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let stkFinal := stkSt.push (.vBool (!b))
    let anfFinal := anfSt.addBinding bn (.vBool (!b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_unaryOp_NOT_d0 bn n k tsm_rest
      anfSt stkSt b rt hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.unaryOp "!" n rt) none : ANFBinding)]
    (Stack.Agrees.untagSm ((n, k) :: tsm_rest))
    ((n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (!b)))
    stkSt (stkSt.push (.vBool (!b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_unaryOp_NEGATE_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBigint i))
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let body := [(ANFBinding.mk bn (.unaryOp "-" n rt) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (-i))
    let anfFinal := anfSt.addBinding bn (.vBigint (-i))
    let tsm := ((topName, k_top) :: (n, k) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_unaryOp_NEGATE_d1
                  bn topName n k_top k tsm_rest anfSt stkSt i rt
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_unaryOp_NEGATE_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBigint i))
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let stkFinal := stkSt.push (.vBigint (-i))
    let anfFinal := anfSt.addBinding bn (.vBigint (-i))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_unaryOp_NEGATE_d1 bn topName n k_top k tsm_rest
      anfSt stkSt i rt hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.unaryOp "-" n rt) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
    ((topName, k_top) :: (n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBigint (-i)))
    stkSt (stkSt.push (.vBigint (-i)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_unaryOp_NOT_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (b : Bool) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool b))
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let body := [(ANFBinding.mk bn (.unaryOp "!" n rt) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (!b))
    let anfFinal := anfSt.addBinding bn (.vBool (!b))
    let tsm := ((topName, k_top) :: (n, k) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_unaryOp_NOT_d1
                  bn topName n k_top k tsm_rest anfSt stkSt b rt
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_unaryOp_NOT_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (b : Bool) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool b))
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let stkFinal := stkSt.push (.vBool (!b))
    let anfFinal := anfSt.addBinding bn (.vBool (!b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_unaryOp_NOT_d1 bn topName n k_top k tsm_rest
      anfSt stkSt b rt hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.unaryOp "!" n rt) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
    ((topName, k_top) :: (n, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (!b)))
    stkSt (stkSt.push (.vBool (!b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_unaryOp_NEGATE_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBigint i))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let body := [(ANFBinding.mk bn (.unaryOp "-" n rt) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (-i))
    let anfFinal := anfSt.addBinding bn (.vBigint (-i))
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_unaryOp_NEGATE_dge2
                  bn n k d tsm anfSt stkSt i rt
                  hAgrees hAtDepth hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_unaryOp_NEGATE_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBigint i))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let stkFinal := stkSt.push (.vBigint (-i))
    let anfFinal := anfSt.addBinding bn (.vBigint (-i))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_unaryOp_NEGATE_dge2 bn n k d tsm
      anfSt stkSt i rt hAgrees hAtDepth hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.unaryOp "-" n rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn (.vBigint (-i)))
    stkSt (stkSt.push (.vBigint (-i)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_unaryOp_NOT_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (b : Bool) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool b))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let body := [(ANFBinding.mk bn (.unaryOp "!" n rt) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (!b))
    let anfFinal := anfSt.addBinding bn (.vBool (!b))
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_unaryOp_NOT_dge2
                  bn n k d tsm anfSt stkSt b rt
                  hAgrees hAtDepth hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_unaryOp_NOT_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (b : Bool) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool b))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let stkFinal := stkSt.push (.vBool (!b))
    let anfFinal := anfSt.addBinding bn (.vBool (!b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_unaryOp_NOT_dge2 bn n k d tsm
      anfSt stkSt b rt hAgrees hAtDepth hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.unaryOp "!" n rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn (.vBool (!b)))
    stkSt (stkSt.push (.vBool (!b)))
    hRun hChain hAgrees

/-! ## `assert n` lifts at d0 / d1 / dge2

`assert n` lowers to `loadRef sm n ++ [.opcode "OP_VERIFY"]`, which
**does not push** a value (verify-and-discard semantics for the
input `vBool true`). Distinct from load/unaryOp lifts:

* `tsm'` equals `tsm` (no new stack-map binding — assert returns
  the input `sm`, not `sm.push bn`).
* `stkFinal` equals `stkSt` (stack unchanged after verify-and-discard).
* `anfFinal` is `anfSt.addBinding bn (.vBool true)` (ANF binding
  preserves the assertion's witness).

The chain relation is `ChainRel simpleStepRel body tsm anfSt stkSt
tsm anfFinal stkSt` — same `tsm` and `stkSt` on both ends. -/

theorem stageC_chain_singleton_assert_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let body := [(ANFBinding.mk bn (.assert n) none : ANFBinding)]
    let anfFinal := anfSt.addBinding bn (.vBool true)
    let tsm := ((n, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkSt
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm anfFinal stkSt := by
  have hStep := Stack.Agrees.stageC_simpleStep_assert_d0
                  bn n k tsm_rest anfSt stkSt
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_assert_d0
    (bn n : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh : Stack.Agrees.freshIn bn (n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((n, k) :: tsm_rest)) n
        = [.dup]) :
    let anfFinal := anfSt.addBinding bn (.vBool true)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkSt : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_assert_d0 bn n k tsm_rest anfSt stkSt
      hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.assert n) none : ANFBinding)]
    (Stack.Agrees.untagSm ((n, k) :: tsm_rest))
    ((n, k) :: tsm_rest) ((n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool true))
    stkSt stkSt
    hRun hChain hAgrees

theorem stageC_chain_singleton_assert_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let body := [(ANFBinding.mk bn (.assert n) none : ANFBinding)]
    let anfFinal := anfSt.addBinding bn (.vBool true)
    let tsm := ((topName, k_top) :: (n, k) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkSt
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm anfFinal stkSt := by
  have hStep := Stack.Agrees.stageC_simpleStep_assert_d1
                  bn topName n k_top k tsm_rest anfSt stkSt
                  hAgrees hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_assert_d1
    (bn topName n : String) (k_top k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh :
        Stack.Agrees.freshIn bn
          (topName :: n :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n
        = [.over]) :
    let anfFinal := anfSt.addBinding bn (.vBool true)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkSt : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_assert_d1 bn topName n k_top k tsm_rest
      anfSt stkSt hAgrees hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.assert n) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
    ((topName, k_top) :: (n, k) :: tsm_rest)
    ((topName, k_top) :: (n, k) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool true))
    stkSt stkSt
    hRun hChain hAgrees

theorem stageC_chain_singleton_assert_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let body := [(ANFBinding.mk bn (.assert n) none : ANFBinding)]
    let anfFinal := anfSt.addBinding bn (.vBool true)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkSt
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm anfFinal stkSt := by
  have hStep := Stack.Agrees.stageC_simpleStep_assert_dge2
                  bn n k d tsm anfSt stkSt
                  hAgrees hAtDepth hLookup hFresh hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_assert_dge2
    (bn n : String) (k : Stack.Agrees.SlotKind) (d : Nat)
    (tsm : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepth : Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) n = [.pickStruct d]) :
    let anfFinal := anfSt.addBinding bn (.vBool true)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkSt : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_assert_dge2 bn n k d tsm anfSt stkSt
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.assert n) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm tsm
    anfSt (anfSt.addBinding bn (.vBool true))
    stkSt stkSt
    hRun hChain hAgrees

/-! ## Tier 3.1 Stage B (per-construct ifVal) — chain singleton lifts

Lifts the per-binding `Stack.Agrees.stageC_simpleStep_ifVal_intInt_d0_*`
discharges to singleton-body `ChainRel simpleStepRel` + `runOps`
claims, then to `observationallyEqual` corollaries. Pattern matches
the analogous `unaryOp` / `assert` lifts above. The shape covered
here is the simplest `ifVal`: cond at depth 0 (boolean), and both
branches are `[singleton with .loadConst (.int _)]`. Two sibling
lifts for `cond = true` / `cond = false`. -/

theorem stageC_chain_singleton_ifVal_intInt_d0_true
    (bn cond thnBn elsBn : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i_thn i_els : Int) (thnAnn elsAnn : Option SourceLoc)
    (hAgrees : Stack.Agrees.agreesTagged ((cond, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (cond, k) = some (.vBool true))
    (hFresh : Stack.Agrees.freshIn bn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hThnFresh : Stack.Agrees.freshIn thnBn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((cond, k) :: tsm_rest)) cond
        = [.dup]) :
    let body := [(ANFBinding.mk bn
                    (.ifVal cond
                       [.mk thnBn (.loadConst (.int i_thn)) thnAnn]
                       [.mk elsBn (.loadConst (.int i_els)) elsAnn]) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint i_thn)
    let anfFinal := (anfSt.addBinding thnBn (.vBigint i_thn)).addBinding bn (.vBigint i_thn)
    let tsm := ((cond, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_ifVal_intInt_d0_true
                  bn cond thnBn elsBn k tsm_rest anfSt stkSt i_thn i_els
                  thnAnn elsAnn hAgrees hLookup hFresh hThnFresh
                  hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_ifVal_intInt_d0_true
    (bn cond thnBn elsBn : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i_thn i_els : Int) (thnAnn elsAnn : Option SourceLoc)
    (hAgrees : Stack.Agrees.agreesTagged ((cond, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (cond, k) = some (.vBool true))
    (hFresh : Stack.Agrees.freshIn bn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hThnFresh : Stack.Agrees.freshIn thnBn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((cond, k) :: tsm_rest)) cond
        = [.dup]) :
    let stkFinal := stkSt.push (.vBigint i_thn)
    let anfFinal := (anfSt.addBinding thnBn (.vBigint i_thn)).addBinding bn (.vBigint i_thn)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_ifVal_intInt_d0_true bn cond thnBn elsBn k tsm_rest
      anfSt stkSt i_thn i_els thnAnn elsAnn hAgrees hLookup hFresh
      hThnFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn
        (.ifVal cond
           [.mk thnBn (.loadConst (.int i_thn)) thnAnn]
           [.mk elsBn (.loadConst (.int i_els)) elsAnn]) none : ANFBinding)]
    (Stack.Agrees.untagSm ((cond, k) :: tsm_rest))
    ((cond, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (cond, k) :: tsm_rest)
    anfSt
    ((anfSt.addBinding thnBn (.vBigint i_thn)).addBinding bn (.vBigint i_thn))
    stkSt (stkSt.push (.vBigint i_thn))
    hRun hChain hAgrees

theorem stageC_chain_singleton_ifVal_intInt_d0_false
    (bn cond thnBn elsBn : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i_thn i_els : Int) (thnAnn elsAnn : Option SourceLoc)
    (hAgrees : Stack.Agrees.agreesTagged ((cond, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (cond, k) = some (.vBool false))
    (hFresh : Stack.Agrees.freshIn bn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hElsFresh : Stack.Agrees.freshIn elsBn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((cond, k) :: tsm_rest)) cond
        = [.dup]) :
    let body := [(ANFBinding.mk bn
                    (.ifVal cond
                       [.mk thnBn (.loadConst (.int i_thn)) thnAnn]
                       [.mk elsBn (.loadConst (.int i_els)) elsAnn]) none : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint i_els)
    let anfFinal := (anfSt.addBinding elsBn (.vBigint i_els)).addBinding bn (.vBigint i_els)
    let tsm := ((cond, k) :: tsm_rest : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_ifVal_intInt_d0_false
                  bn cond thnBn elsBn k tsm_rest anfSt stkSt i_thn i_els
                  thnAnn elsAnn hAgrees hLookup hFresh hElsFresh
                  hLoadRefShape
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_ifVal_intInt_d0_false
    (bn cond thnBn elsBn : String) (k : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (i_thn i_els : Int) (thnAnn elsAnn : Option SourceLoc)
    (hAgrees : Stack.Agrees.agreesTagged ((cond, k) :: tsm_rest) anfSt stkSt)
    (hLookup : Stack.Agrees.lookupAnfByKind anfSt (cond, k) = some (.vBool false))
    (hFresh : Stack.Agrees.freshIn bn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hElsFresh : Stack.Agrees.freshIn elsBn (cond :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefShape :
        Stack.Lower.loadRef (Stack.Agrees.untagSm ((cond, k) :: tsm_rest)) cond
        = [.dup]) :
    let stkFinal := stkSt.push (.vBigint i_els)
    let anfFinal := (anfSt.addBinding elsBn (.vBigint i_els)).addBinding bn (.vBigint i_els)
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_ifVal_intInt_d0_false bn cond thnBn elsBn k tsm_rest
      anfSt stkSt i_thn i_els thnAnn elsAnn hAgrees hLookup hFresh
      hElsFresh hLoadRefShape
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn
        (.ifVal cond
           [.mk thnBn (.loadConst (.int i_thn)) thnAnn]
           [.mk elsBn (.loadConst (.int i_els)) elsAnn]) none : ANFBinding)]
    (Stack.Agrees.untagSm ((cond, k) :: tsm_rest))
    ((cond, k) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (cond, k) :: tsm_rest)
    anfSt
    ((anfSt.addBinding elsBn (.vBigint i_els)).addBinding bn (.vBigint i_els))
    stkSt (stkSt.push (.vBigint i_els))
    hRun hChain hAgrees

/-! ## Tier 3.1 Stage B (per-construct binOp / call) — chain singleton lifts

Lifts the per-binding `Stack.Agrees.stageC_simpleStep_binOp_*_d1d0` and
`stageC_simpleStep_call_cat_d1d0` discharges to singleton-body
`ChainRel simpleStepRel` + `runOps` claims, then to
`observationallyEqual` corollaries. Pattern matches the analogous
`unaryOp` / `assert` lifts above: each per-binding witness is
wrapped via `runOps_lowerBindings_singleton` + `chainRel_cons` /
`chainRel_nil`, then bridged through
`stageD_observationallyEqual_at_bindings_level` for the obs-eq form.

The depth-(1, 0) case is the canonical binOp / 2-arg-call shape:
left operand at depth 1, right operand at depth 0 of `tsm`. Lower
emits `[.over, .over, .opcode <opc>]`. Each lift takes the same
`hLoadRefL` / `hLoadRefR` shape hypotheses required by the
underlying per-step lemma. -/

theorem stageC_chain_singleton_binOp_ADD_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "+" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_ADD_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_ADD_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_ADD_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "+" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBigint (a + b)))
    stkSt (stkSt.push (.vBigint (a + b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_SUB_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "-" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (a - b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a - b))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_SUB_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_SUB_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBigint (a - b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a - b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_SUB_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "-" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBigint (a - b)))
    stkSt (stkSt.push (.vBigint (a - b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_MUL_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "*" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (a * b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a * b))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_MUL_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_MUL_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBigint (a * b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a * b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_MUL_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "*" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBigint (a * b)))
    stkSt (stkSt.push (.vBigint (a * b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_NUMEQUAL_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "===" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (decide (a = b)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a = b)))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_NUMEQUAL_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hRtNotBytes hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_NUMEQUAL_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBool (decide (a = b)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a = b)))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_NUMEQUAL_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt hRtNotBytes
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "===" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (decide (a = b))))
    stkSt (stkSt.push (.vBool (decide (a = b))))
    hRun hChain hAgrees

/-! ## Tier 3.1 extension — d1d0 chain_singleton + observationallyEqual
for LESSTHAN/GREATERTHAN/BOOLAND/BOOLOR.

Same pattern as the ADD/SUB/MUL/NUMEQUAL singleton lifts. Each takes
the per-step lemma `stageC_simpleStep_binOp_<OP>_d1d0` and packages
it through `runOps_lowerBindings_singleton` + `chainRel_cons` (chain
side) and `stageD_observationallyEqual_at_bindings_level` (observation
side). -/

theorem stageC_chain_singleton_binOp_LESSTHAN_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "<" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (decide (a < b)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a < b)))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_LESSTHAN_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_LESSTHAN_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBool (decide (a < b)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a < b)))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_LESSTHAN_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "<" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (decide (a < b))))
    stkSt (stkSt.push (.vBool (decide (a < b))))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_GREATERTHAN_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp ">" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (decide (a > b)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a > b)))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_GREATERTHAN_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_GREATERTHAN_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBool (decide (a > b)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a > b)))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_GREATERTHAN_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp ">" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (decide (a > b))))
    stkSt (stkSt.push (.vBool (decide (a > b))))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_BOOLAND_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "&&" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_BOOLAND_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_BOOLAND_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_BOOLAND_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "&&" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (decide (a ≠ 0 ∧ b ≠ 0))))
    stkSt (stkSt.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0))))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_BOOLOR_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "||" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_BOOLOR_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b rt
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_BOOLOR_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))
    let anfFinal := anfSt.addBinding bn (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_BOOLOR_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b rt
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "||" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBool (decide (a ≠ 0 ∨ b ≠ 0))))
    stkSt (stkSt.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0))))
    hRun hChain hAgrees

/-! ## Tier 3.1 extension — Higher-depth ADD chain_singleton + observationallyEqual
for d2d0 / d2d1 / dge2_dge2.

Lifts the per-step `stageC_simpleStep_binOp_ADD_*` lemmas through
`runOps_lowerBindings_singleton` + `chainRel_cons` (chain side) and
`stageD_observationallyEqual_at_bindings_level` (observation side). -/

theorem stageC_chain_singleton_binOp_ADD_d2d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_after_top : Stack.Agrees.TaggedStackMap) (d_l : Nat)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: tsm_after_top) anfSt stkSt)
    (hAtDepth :
        Stack.Agrees.nthOpt d_l ((topName, k_top) :: tsm_after_top)
          = some (botName, k_bot))
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: Stack.Agrees.untagSm tsm_after_top))
    (hDl : d_l ≥ 2)
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: tsm_after_top)) botName
        = [.pickStruct d_l])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm ((topName, k_top) :: tsm_after_top)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.binOp "+" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    let tsm := ((topName, k_top) :: tsm_after_top
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_ADD_d2d0
                  bn topName botName k_top k_bot tsm_after_top d_l
                  anfSt stkSt a b rt
                  hAgrees hAtDepth hLookupL hLookupR hFresh hDl hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_ADD_d2d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_after_top : Stack.Agrees.TaggedStackMap) (d_l : Nat)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: tsm_after_top) anfSt stkSt)
    (hAtDepth :
        Stack.Agrees.nthOpt d_l ((topName, k_top) :: tsm_after_top)
          = some (botName, k_bot))
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: Stack.Agrees.untagSm tsm_after_top))
    (hDl : d_l ≥ 2)
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm ((topName, k_top) :: tsm_after_top)) botName
        = [.pickStruct d_l])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm ((topName, k_top) :: tsm_after_top)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_ADD_d2d0 bn topName botName k_top k_bot
      tsm_after_top d_l anfSt stkSt a b rt
      hAgrees hAtDepth hLookupL hLookupR hFresh hDl hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "+" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm ((topName, k_top) :: tsm_after_top))
    ((topName, k_top) :: tsm_after_top)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) :: tsm_after_top)
    anfSt (anfSt.addBinding bn (.vBigint (a + b)))
    stkSt (stkSt.push (.vBigint (a + b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_ADD_d2d1
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_mid : Stack.Agrees.TaggedStackMap) (d_l : Nat)
    (someTopV : String × Stack.Agrees.SlotKind)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                (someTopV :: (topName, k_top) :: tsm_mid) anfSt stkSt)
    (hAtDepth :
        Stack.Agrees.nthOpt d_l (someTopV :: (topName, k_top) :: tsm_mid)
          = some (botName, k_bot))
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (someTopV.fst :: topName :: Stack.Agrees.untagSm tsm_mid))
    (hDl : d_l ≥ 2)
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm (someTopV :: (topName, k_top) :: tsm_mid)) botName
        = [.pickStruct d_l])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              (someTopV :: (topName, k_top) :: tsm_mid)) topName
        = [.pickStruct 2]) :
    let body := [(ANFBinding.mk bn (.binOp "+" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    let tsm := (someTopV :: (topName, k_top) :: tsm_mid
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_ADD_d2d1
                  bn topName botName k_top k_bot tsm_mid d_l someTopV
                  anfSt stkSt a b rt
                  hAgrees hAtDepth hLookupL hLookupR hFresh hDl hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_ADD_d2d1
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_mid : Stack.Agrees.TaggedStackMap) (d_l : Nat)
    (someTopV : String × Stack.Agrees.SlotKind)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged
                (someTopV :: (topName, k_top) :: tsm_mid) anfSt stkSt)
    (hAtDepth :
        Stack.Agrees.nthOpt d_l (someTopV :: (topName, k_top) :: tsm_mid)
          = some (botName, k_bot))
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn
                (someTopV.fst :: topName :: Stack.Agrees.untagSm tsm_mid))
    (hDl : d_l ≥ 2)
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm (someTopV :: (topName, k_top) :: tsm_mid)) botName
        = [.pickStruct d_l])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              (someTopV :: (topName, k_top) :: tsm_mid)) topName
        = [.pickStruct 2]) :
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_ADD_d2d1 bn topName botName k_top k_bot
      tsm_mid d_l someTopV anfSt stkSt a b rt
      hAgrees hAtDepth hLookupL hLookupR hFresh hDl hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "+" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm (someTopV :: (topName, k_top) :: tsm_mid))
    (someTopV :: (topName, k_top) :: tsm_mid)
    ((bn, Stack.Agrees.SlotKind.binding) :: someTopV :: (topName, k_top) :: tsm_mid)
    anfSt (anfSt.addBinding bn (.vBigint (a + b)))
    stkSt (stkSt.push (.vBigint (a + b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_binOp_ADD_dge2_dge2
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm : Stack.Agrees.TaggedStackMap) (d_l d_r : Nat)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepthL : Stack.Agrees.nthOpt d_l tsm = some (botName, k_bot))
    (hAtDepthR : Stack.Agrees.nthOpt d_r tsm = some (topName, k_top))
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hDl : d_l ≥ 2) (hDr : d_r ≥ 2)
    (hLoadRefL :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) botName
        = [.pickStruct d_l])
    (hLoadRefR :
        Stack.Lower.loadRef (botName :: Stack.Agrees.untagSm tsm) topName
        = [.pickStruct (d_r + 1)]) :
    let body := [(ANFBinding.mk bn (.binOp "+" botName topName rt) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_binOp_ADD_dge2_dge2
                  bn topName botName k_top k_bot tsm d_l d_r
                  anfSt stkSt a b rt
                  hAgrees hAtDepthL hAtDepthR hLookupL hLookupR hFresh hDl hDr
                  hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_binOp_ADD_dge2_dge2
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm : Stack.Agrees.TaggedStackMap) (d_l d_r : Nat)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : Int) (rt : Option String)
    (hAgrees : Stack.Agrees.agreesTagged tsm anfSt stkSt)
    (hAtDepthL : Stack.Agrees.nthOpt d_l tsm = some (botName, k_bot))
    (hAtDepthR : Stack.Agrees.nthOpt d_r tsm = some (topName, k_top))
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBigint a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBigint b))
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hDl : d_l ≥ 2) (hDr : d_r ≥ 2)
    (hLoadRefL :
        Stack.Lower.loadRef (Stack.Agrees.untagSm tsm) botName
        = [.pickStruct d_l])
    (hLoadRefR :
        Stack.Lower.loadRef (botName :: Stack.Agrees.untagSm tsm) topName
        = [.pickStruct (d_r + 1)]) :
    let stkFinal := stkSt.push (.vBigint (a + b))
    let anfFinal := anfSt.addBinding bn (.vBigint (a + b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_binOp_ADD_dge2_dge2 bn topName botName k_top k_bot
      tsm d_l d_r anfSt stkSt a b rt
      hAgrees hAtDepthL hAtDepthR hLookupL hLookupR hFresh hDl hDr
      hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.binOp "+" botName topName rt) none : ANFBinding)]
    (Stack.Agrees.untagSm tsm)
    tsm
    ((bn, Stack.Agrees.SlotKind.binding) :: tsm)
    anfSt (anfSt.addBinding bn (.vBigint (a + b)))
    stkSt (stkSt.push (.vBigint (a + b)))
    hRun hChain hAgrees

theorem stageC_chain_singleton_call_cat_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : ByteArray)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBytes a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBytes b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let body := [(ANFBinding.mk bn (.call "cat" [botName, topName]) none
                  : ANFBinding)]
    let stkFinal := stkSt.push (.vBytes (a ++ b))
    let anfFinal := anfSt.addBinding bn (.vBytes (a ++ b))
    let tsm := ((topName, k_top) :: (botName, k_bot) :: tsm_rest
                : Stack.Agrees.TaggedStackMap)
    let tsm' := ((bn, Stack.Agrees.SlotKind.binding) :: tsm
                 : Stack.Agrees.TaggedStackMap)
    Stack.Eval.runOps
      (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) body).1 stkSt
      = .ok stkFinal
    ∧ Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel body
        tsm anfSt stkSt tsm' anfFinal stkFinal := by
  have hStep := Stack.Agrees.stageC_simpleStep_call_cat_d1d0
                  bn topName botName k_top k_bot tsm_rest anfSt stkSt a b
                  hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  refine ⟨?_, ?_⟩
  · apply Stack.Agrees.runOps_lowerBindings_singleton
    exact hStep.1
  · apply Stack.Agrees.chainRel_cons _ _ _ _ _ _ _ _ _ _ _ hStep.2
    exact Stack.Agrees.chainRel_nil _ _ _

theorem observationallyEqual_singleton_call_cat_d1d0
    (bn topName botName : String) (k_top k_bot : Stack.Agrees.SlotKind)
    (tsm_rest : Stack.Agrees.TaggedStackMap)
    (anfSt : ANF.Eval.State) (stkSt : Stack.Eval.StackState)
    (a b : ByteArray)
    (hAgrees : Stack.Agrees.agreesTagged
                ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt)
    (hLookupL : Stack.Agrees.lookupAnfByKind anfSt (botName, k_bot)
                  = some (.vBytes a))
    (hLookupR : Stack.Agrees.lookupAnfByKind anfSt (topName, k_top)
                  = some (.vBytes b))
    (hFresh : Stack.Agrees.freshIn bn
                (topName :: botName :: Stack.Agrees.untagSm tsm_rest))
    (hLoadRefL :
        Stack.Lower.loadRef
          (Stack.Agrees.untagSm
            ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRefR :
        Stack.Lower.loadRef
          (botName ::
            Stack.Agrees.untagSm
              ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.over]) :
    let stkFinal := stkSt.push (.vBytes (a ++ b))
    let anfFinal := anfSt.addBinding bn (.vBytes (a ++ b))
    observationallyEqual
      (.ok anfFinal : ANF.Eval.EvalResult ANF.Eval.State)
      (.ok stkFinal : ANF.Eval.EvalResult Stack.Eval.StackState) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_call_cat_d1d0 bn topName botName k_top k_bot
      tsm_rest anfSt stkSt a b
      hAgrees hLookupL hLookupR hFresh hLoadRefL hLoadRefR
  exact stageD_observationallyEqual_at_bindings_level
    [(ANFBinding.mk bn (.call "cat" [botName, topName]) none : ANFBinding)]
    (Stack.Agrees.untagSm
      ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
    ((bn, Stack.Agrees.SlotKind.binding) :: (topName, k_top) ::
       (botName, k_bot) :: tsm_rest)
    anfSt (anfSt.addBinding bn (.vBytes (a ++ b)))
    stkSt (stkSt.push (.vBytes (a ++ b)))
    hRun hChain hAgrees

/-! ## Tier 3 item 3.2 — Peephole post-pass composition (skeleton)

`peepholeProgram` chains 4 sub-passes:
  `peepholePassAll → peepholePostFold → peepholeChainFold → peepholeRollPickFold`

To deliver the discharged version of `peephole_observational_correct_modulo_runMethod_eq`,
each sub-pass needs an operational-soundness lemma: `runOps (P ops) s
= runOps ops s`. Composition then yields `runOps (peepholeProgram p)
m s = runOps p m s`, which discharges `hRunMethodEq`.

`peepholePassFullPlus_sound` (in `Stack/Peephole.lean:8708`) covers
12 of 19 rules in `peepholePassAll`; `peepholePassAllFlat_sound`
(line 9608) extends to 17 of 19 with two external preconditions.
The 4 post-passes are NOT covered.

This section establishes the proof framework with the **empty-list
base case** for each sub-pass — the trivial case that goes through
without any rewrite-rule reasoning. Subsequent work extends each
to non-empty inputs by induction on the op list.

Estimated remaining effort per audit: 2-3 person-weeks.
-/

theorem peepholePostFold_empty :
    Stack.Peephole.peepholePostFold [] = [] := rfl

/-- For the structural `peepholePostFold` (no fixpoint), the empty
case reduces to `[]` by definitional unfolding, so `runOps` agrees
on both sides trivially. The corresponding lemmas for
`peepholeChainFold` and `peepholeRollPickFold` require unfolding
the fixpoint iteration (`chainFoldFixpointFlat 64`, `rollPickFixpointFlat 64`)
which doesn't reduce by `rfl` — they need a separate lemma that
`fixpointFlat n [] = []` for all `n`. Deferred. -/
theorem peepholePostFold_runOps_empty (s : Stack.Eval.StackState) :
    Stack.Eval.runOps (Stack.Peephole.peepholePostFold []) s
      = Stack.Eval.runOps [] s := by
  rw [peepholePostFold_empty]

/-! ### Tier 3.2.d — Top-level peephole composition

Composes the sub-pass operational soundness lemmas:
* `peepholePassAllFlat_sound` (Stack/Peephole.lean:9608) — needs
  `noIfOp` + `wellTypedRun` + 2 external WT preconditions
* `peepholePostFold_runOps_eq` (✅ Stack/Peephole.lean) — unconditional
* `peepholeChainFold_runOps_eq` — pending (atom-level closed; list-level
  needs stack-shape invariant)
* `peepholeRollPickFold_runOps_eq` — blocked (IR/byte semantic gap)

The two pending sub-passes are taken as hypotheses; the proven sub-pass
(postFold) is discharged inline. -/

/-- Per-method `runOps`-equality for the full peephole pipeline,
modulo chain-fold and roll/pick-fold operational equivalence. -/
theorem peephole_method_runOps_eq_modulo_chain_rollpick
    (ops : List Stack.StackOp) (s : Stack.Eval.StackState)
    (hPassAll : Stack.Eval.runOps (Stack.Peephole.peepholePassAll ops) s
              = Stack.Eval.runOps ops s)
    (hChain : ∀ ops' s',
        Stack.Eval.runOps (Stack.Peephole.peepholeChainFold ops') s'
        = Stack.Eval.runOps ops' s')
    (hRollPick : ∀ ops' s',
        Stack.Eval.runOps (Stack.Peephole.peepholeRollPickFold ops') s'
        = Stack.Eval.runOps ops' s') :
    Stack.Eval.runOps
      (Stack.Peephole.peepholeRollPickFold
        (Stack.Peephole.peepholeChainFold
          (Stack.Peephole.peepholePostFold
            (Stack.Peephole.peepholePassAll ops)))) s
    = Stack.Eval.runOps ops s := by
  rw [hRollPick, hChain, Stack.Peephole.peepholePostFold_runOps_eq, hPassAll]

/-- Top-level program-level form: for any program `p` and method
`m`, `runMethod (peepholeProgram p) m s = runMethod p m s` modulo the
sub-pass operational equivalences as hypotheses. This is the
discharged version of `peephole_observational_correct_modulo_runMethod_eq`'s
`hRunMethodEq` premise.

For methods not present in `p`, the equality holds trivially since
both sides reduce to `runOps [] s`. For methods present, we use
`peephole_method_runOps_eq_modulo_chain_rollpick` per-method. -/
theorem peepholeProgram_runMethod_eq_modulo_subpasses
    (p : Stack.StackProgram) (m : String) (s : Stack.Eval.StackState)
    (hPassAll : ∀ ops s',
        Stack.Eval.runOps (Stack.Peephole.peepholePassAll ops) s'
        = Stack.Eval.runOps ops s')
    (hChain : ∀ ops s',
        Stack.Eval.runOps (Stack.Peephole.peepholeChainFold ops) s'
        = Stack.Eval.runOps ops s')
    (hRollPick : ∀ ops s',
        Stack.Eval.runOps (Stack.Peephole.peepholeRollPickFold ops) s'
        = Stack.Eval.runOps ops s') :
    Stack.Eval.runMethod (peepholeProgram p) m s
    = Stack.Eval.runMethod p m s := by
  unfold Stack.Eval.runMethod Stack.StackProgram.bodyOf
  rw [peepholeProgram_findMethod]
  cases hFind : p.findMethod m with
  | none => rfl
  | some sm =>
      simp only [Option.map_some]
      show Stack.Eval.runOps
            (Stack.Peephole.peepholeRollPickFold
              (Stack.Peephole.peepholeChainFold
                (Stack.Peephole.peepholePostFold
                  (Stack.Peephole.peepholePassAll sm.ops)))) s
          = Stack.Eval.runOps sm.ops s
      exact peephole_method_runOps_eq_modulo_chain_rollpick
              sm.ops s (hPassAll sm.ops s) hChain hRollPick

/-! ### Tier 2.5 — closed opcode type (landed, partial)

`Stack/Lower.lean:67-87` defines `LoweringError` (6 ctors covering
the placeholder-byte fallback sites). `Stack/Syntax.lean` now also
hosts the closed `RunarOp` inductive (~55 ctors enumerating exactly
the Bitcoin Script opcodes Rúnar emits) and a smart constructor
`StackOp.runarOp : RunarOp → StackOp` that routes through the legacy
string-keyed `.opcode` arm. Round-trip via `RunarOp.toName /
RunarOp.ofName?` is decidable and proven (`toName_ofName`).

`Stack/Lower.lean` adds `lowerSafe : ANFProgram → Except
LoweringError StackProgram` — returns `.ok (lower p)` for SimpleANF
inputs and `.error` otherwise. The success/error domain is a
biconditional with `SimpleANF` (`simpleANF_iff_lowerSafe_ok`).

`Pipeline.lean` adds `compileSafe : ANFProgram → Except
LoweringError ByteArray` — the structured peer of `compile`. SimpleANF
inputs go through byte-equal output; non-SimpleANF inputs return
`.error` with a structured `LoweringError` instead of compiling
silently to invalid `OP_RUNAR_*_TODO` placeholder bytes
(`compileSafe_ok_eq_compile`, `compileSafe_error_of_not_simpleANF`,
`simpleANF_iff_compileSafe_ok`).

Deferred for a follow-up session (each is mechanical but voluminous):
* Refactor every legacy `StackOp.opcode "OP_..."` literal in
  `Stack/Lower.lean` (and `Stack/Peephole.lean`, the crypto codegen
  modules) to `StackOp.runarOp .ADD` etc. — no semantics change, just
  structured names. ~80 dependent lemmas need byte-equivalence
  rewriting.
* Refine `lowerSafe`'s error to per-construct `LoweringError`
  ctors (the 6 already enumerated, plus new ones for each
  `OP_RUNAR_*_TODO` site) so the diagnostic identifies which
  unsupported binding fired.
-/

/-- The current `Lower.lower` is total (always returns a `StackProgram`).
This is the trivial reflection of that fact — useful as a guard. -/
theorem lower_total (p : ANFProgram) :
    ∃ sp : Stack.StackProgram, Stack.Lower.lower p = sp :=
  ⟨Stack.Lower.lower p, rfl⟩

/-- The Tier-2.5 bridging theorem (formerly placeholder-named
`simpleANF_implies_no_lowering_error`): the `lowerSafe` of a SimpleANF
program succeeds. Now provable concretely against the landed
`Stack.Lower.lowerSafe`. -/
theorem simpleANF_implies_lowerSafe_ok (p : ANFProgram)
    (hSimple : Stack.Lower.SimpleANF p) :
    Stack.Lower.lowerSafe p = .ok (Stack.Lower.lower p) :=
  Stack.Lower.lowerSafe_ok_of_simpleANF p hSimple

/-- For SimpleANF programs, `compileSafe` returns the same bytes as
the legacy total `compile`. -/
theorem simpleANF_implies_compileSafe_ok (p : ANFProgram)
    (hSimple : Stack.Lower.SimpleANF p) :
    compileSafe p = .ok (compile p) :=
  compileSafe_ok_eq_compile p hSimple

/-! ## Tier 3 item 3.4 — byte-level theorem `compile_runs_correctly_simple`

The headline byte-level pipeline theorem: for SimpleANF programs whose
post-pipeline form is a single public method, `parseScript (compile p)`
recovers the post-peephole op list (via Tier 2.3
`parseScript_emit_round_trip`) and the parsed op list, executed against
the initial stack state, is `observationallyEqual` to the ANF evaluator
on `m.body`.

This is **Path A** (single-public-method). The full multi-method
dispatch-chain round-trip (Path B) requires extending
`parseScript_emit_round_trip` to recognise the
`OP_DUP <i> OP_NUMEQUAL OP_IF OP_DROP <body> OP_ELSE …` chain, and is
deferred. Path A composes the existing pieces:

1. `compile p = Emit.emitFast (peepholeProgram (Lower.lower p))` — defn.
2. `Emit.emit q = Emit.emitFast q` for any `StackProgram q` — Tier 2.4
   (`Script.EmitCorrect.emit_eq_emitFast`).
3. For a single-public-method post-pipeline program with the method
   name `≠ "constructor"`, `Emit.emit q = Emit.emitOps m'.ops` where
   `m'` is the sole public method (from `Emit.emit`'s `[m]` arm).
4. `Parse.parseScript (Emit.emitOps m'.ops) = .ok m'.ops` under
   `AreRunarEmittable m'.ops` — Tier 2.3
   (`Script.Parse.parseScript_emit_round_trip`).
5. `Stack.Eval.runOps m'.ops initialStack
   = Stack.Eval.runMethod (peepholeProgram (Lower.lower p)) m.name initialStack`
   — `findMethod` on a singleton with matching name returns `some m'`.
6. `compile_observational_correct_simple_structured` discharges the
   `observationallyEqual (evalBindings ...) (runMethod ...)` claim.
-/

/-! ### Bridging lemma: `Lower.lower` under a single-public-method
hypothesis -/

/-- If `p`'s public-method projection is exactly `[m]`, then the
lowered program's `methods` field is the singleton list containing
the lowered `m`. Direct refl-like reduction: `Lower.lower` is
`(p.methods.filter (·.isPublic)).map (lowerMethod ...)`, and `map`
on a singleton list reduces to a singleton. -/
theorem lower_methods_of_single_public
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m]) :
    (Stack.Lower.lower p).methods =
      [Stack.Lower.lowerMethod p.methods p.properties m] := by
  unfold Stack.Lower.lower
  simp only [hSinglePublic, List.map_cons, List.map_nil]

/-- Companion: `peepholeProgram (Lower.lower p)`'s `methods` field is
the singleton list `[peepholeMethod (lowerMethod ... m)]`. -/
theorem peephole_lower_methods_of_single_public
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m]) :
    (peepholeProgram (Stack.Lower.lower p)).methods =
      [peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)] := by
  unfold peepholeProgram
  simp only [lower_methods_of_single_public p m hSinglePublic,
             List.map_cons, List.map_nil]
  -- Goal: [⟨...with new ops⟩] = [peepholeMethod (lowerMethod ...)]
  -- The `peepholeProgram` map's lambda IS exactly `peepholeMethod`'s body.
  rfl

/-! ### Bridging lemma: `Emit.publicMethodsOf` of the post-pipeline
program reduces to the singleton lowered+peephole'd method -/

/-- For a single-public-method ANF program whose method name is not
`"constructor"`, the post-pipeline `publicMethodsOf` is the singleton
`[peepholeMethod (lowerMethod ... m)]`. -/
theorem publicMethodsOf_peephole_lower_of_single_public
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m])
    (hNotConstructor : m.name ≠ "constructor") :
    Script.Emit.publicMethodsOf (peepholeProgram (Stack.Lower.lower p)) =
      [peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)] := by
  unfold Script.Emit.publicMethodsOf
  rw [peephole_lower_methods_of_single_public p m hSinglePublic]
  -- Goal: [peepholeMethod ...].filter isPublicStackMethod = [peepholeMethod ...]
  show ([peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)]
          : List Stack.StackMethod).filter Script.Emit.isPublicStackMethod
        = [peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)]
  -- The peephole-method's name is m.name (preserved by both lowerMethod and peepholeMethod).
  have hName :
      (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).name = m.name := by
    rw [peepholeMethod_preserves_name, lowerMethod_preserves_name]
  have hIsPublic :
      Script.Emit.isPublicStackMethod
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)) = true := by
    unfold Script.Emit.isPublicStackMethod
    rw [hName]
    -- `m.name != "constructor"` from hNotConstructor.
    show (m.name != "constructor") = true
    exact bne_iff_ne.mpr hNotConstructor
  simp [List.filter, hIsPublic]

/-! ### Bridging lemma: `compile p = emitOps m'.ops` for the singleton
public-method case -/

/-- For a single-public-method ANF program (with name ≠ "constructor"),
`Pipeline.compile p` equals `Emit.emitOps` on the post-peephole lowered
method's ops list. Composes:
* `Pipeline.compile p = Emit.emitFast _` (definition),
* `Emit.emit q = Emit.emitFast q` (Tier 2.4
  `Script.EmitCorrect.emit_eq_emitFast`),
* `Emit.emit q = Emit.emitMethod m' = Emit.emitOps m'.ops` for the
  singleton `publicMethodsOf` case.
-/
theorem compile_eq_emitOps_of_single_public
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m])
    (hNotConstructor : m.name ≠ "constructor") :
    Pipeline.compile p =
      Script.Emit.emitOps
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops := by
  -- Step 1: compile = emitFast.
  unfold Pipeline.compile
  -- Step 2: emit q = emitFast q.
  rw [← Script.Emit.emit_eq_emitFast]
  -- Step 3: emit q for a single-public-method q.
  unfold Script.Emit.emit
  rw [publicMethodsOf_peephole_lower_of_single_public p m hSinglePublic hNotConstructor]
  -- Goal: emitMethod (peepholeMethod (lowerMethod ...)) = emitOps (peepholeMethod ...).ops.
  rfl

/-! ### Bridging lemma: `findMethod` on the post-pipeline program
under a single-public-method hypothesis -/

/-- For a single-public-method ANF program (with name ≠ "constructor"),
`(peepholeProgram (Lower.lower p)).findMethod m.name` returns
`some (peepholeMethod (lowerMethod ... m))`. -/
theorem peephole_lower_findMethod_of_single_public
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m]) :
    (peepholeProgram (Stack.Lower.lower p)).findMethod m.name =
      some (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)) := by
  unfold Stack.StackProgram.findMethod
  rw [peephole_lower_methods_of_single_public p m hSinglePublic]
  -- [peepholeMethod (lowerMethod ... m)].find? (·.name == m.name) = some _
  -- Need: (peepholeMethod (lowerMethod ... m)).name == m.name = true.
  have hName :
      (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).name = m.name := by
    rw [peepholeMethod_preserves_name, lowerMethod_preserves_name]
  show (List.find?
          (fun x => x.name == m.name)
          [peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)])
        = some (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m))
  rw [List.find?_cons]
  rw [hName]
  rw [beq_self_eq_true]

/-! ### Bridging lemma: `runMethod` reduces to `runOps` for the
singleton-public-method case -/

theorem runMethod_eq_runOps_of_single_public
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m])
    (initialStack : Stack.Eval.StackState) :
    Stack.Eval.runMethod (peepholeProgram (Stack.Lower.lower p)) m.name initialStack
    = Stack.Eval.runOps
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        initialStack := by
  unfold Stack.Eval.runMethod Stack.StackProgram.bodyOf
  rw [peephole_lower_findMethod_of_single_public p m hSinglePublic]

/-! ### `compile_runs_correctly_simple` — the byte-level theorem (Path A)

Combines:
* `compile_eq_emitOps_of_single_public` — `compile p` reduces to
  `emitOps m'.ops` under the singleton-public-method hypothesis.
* `Script.Parse.parseScript_emit_round_trip` — recovers `m'.ops` from
  the bytes, under `AreRunarEmittable m'.ops`.
* `runMethod_eq_runOps_of_single_public` — `runMethod` reduces to
  `runOps m'.ops`.
* `compile_observational_correct_simple_structured` — provides
  `observationallyEqual` between ANF eval and the post-pipeline
  `runMethod`.

The conclusion is the existential

```
∃ ops, parseScript (compile p) = .ok ops ∧
       observationallyEqual (evalBindings initialAnf m.body) (runOps ops initialStack)
```

with `ops = (peepholeMethod (lowerMethod ... m)).ops`.

The hypothesis stack mirrors `compile_observational_correct_simple_structured`'s
honest-form: ChainRel + agreesTagged + runOps-pre + lowerMethod-ops-eq +
ANF-eval-eq are the genuine remaining obligations (each discharged by
the per-construct singleton soundness corollaries above), augmented
with:
* `hSinglePublic`: the program has exactly one public method `m`.
* `hNotConstructor`: `m.name ≠ "constructor"` (so the public method
  survives `Emit.publicMethodsOf`'s constructor filter).
* `hRunarEmittable`: the post-peephole op list is `RunarEmittable`,
  required by `Tier 2.3 parseScript_emit_round_trip`. -/
theorem compile_runs_correctly_simple
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m])
    (hNotConstructor : m.name ≠ "constructor")
    (hRunarEmittable :
        Script.Parse.AreRunarEmittable
          (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops)
    (sm : Stack.Lower.StackMap)
    (tsm tsm' : Stack.Agrees.TaggedStackMap)
    (initialAnf anfFinal : ANF.Eval.State)
    (initialStack stkFinal : Stack.Eval.StackState)
    (hRunPre :
        Stack.Eval.runOps (Stack.Lower.lowerBindings sm m.body).1 initialStack
        = .ok stkFinal)
    (hChain :
        Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel m.body tsm
          initialAnf initialStack tsm' anfFinal stkFinal)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings sm m.body).1)
    (hAnfEvalEq :
        RunarVerification.ANF.Eval.evalBindings initialAnf m.body = .ok anfFinal) :
    ∃ ops,
      Script.Parse.parseScript (Pipeline.compile p) = .ok ops ∧
      observationallyEqual
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
        (Stack.Eval.runOps ops initialStack) := by
  -- Bind `ops := (peepholeMethod (lowerMethod ... m)).ops`.
  refine ⟨(peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops,
          ?_, ?_⟩
  · -- parseScript (compile p) = .ok ops.
    rw [compile_eq_emitOps_of_single_public p m hSinglePublic hNotConstructor]
    exact Script.Parse.parseScript_emit_round_trip _ hRunarEmittable
  · -- observationallyEqual (evalBindings ...) (runOps ops initialStack).
    -- Step 1: derive `m ∈ p.methods` and the public/uniqueness side-conditions
    -- from `hSinglePublic`.
    have hMember : m ∈ p.methods := by
      have hFiltMem : m ∈ p.methods.filter (·.isPublic) := by
        rw [hSinglePublic]; exact List.mem_singleton.mpr rfl
      exact (List.mem_filter.mp hFiltMem).1
    have hPublic : m.isPublic = true := by
      have hFiltMem : m ∈ p.methods.filter (·.isPublic) := by
        rw [hSinglePublic]; exact List.mem_singleton.mpr rfl
      have := (List.mem_filter.mp hFiltMem).2
      simp at this
      exact this
    -- Uniqueness over the public-method projection: any other public method
    -- in p.methods with the same name must be exactly m, since the public-
    -- method list is the singleton [m].
    have hUnique :
        ∀ m' ∈ p.methods,
          m'.isPublic = true → m'.name = m.name → m' = m := by
      intros m' hMem' hPub' _hName'
      have hM'Filt : m' ∈ p.methods.filter (·.isPublic) :=
        List.mem_filter.mpr ⟨hMem', by simp [hPub']⟩
      rw [hSinglePublic] at hM'Filt
      exact List.mem_singleton.mp hM'Filt
    -- Step 2: compose `compile_observational_correct_simple_structured`
    -- (gives observationallyEqual against `runMethod`).
    have hOEq :=
      compile_observational_correct_simple_structured
        p m hMember hPublic hUnique sm tsm tsm'
        initialAnf anfFinal initialStack stkFinal
        hRunPre hChain hAgrees hMethodOpsEq hAnfEvalEq
    -- Step 3: reduce `runMethod` to `runOps ops` via the singleton bridge.
    rw [runMethod_eq_runOps_of_single_public p m hSinglePublic initialStack] at hOEq
    exact hOEq

/-! ### Concrete fixture corollary: `compile_runs_correctly_simple_singleton_int`

Exercises `compile_runs_correctly_simple` for the smallest non-trivial
SimpleANF program: a contract with one public method whose body is the
singleton `[loadConst .int i]`. -/

/-- Build an `ANFProgram` whose only public method `m` is named
`methodName` (with no params, no properties, body `[loadConst .int i]`).
The single binding name is `bn`. The contract is named `cn`. The
constructor method `"constructor"` (private) is included so that the
filter `(·.isPublic) = [m]` is preserved. -/
def someProgram (cn methodName bn : String) (i : Int) : ANFProgram :=
  let body : List ANFBinding :=
    [(ANFBinding.mk bn (.loadConst (.int i)) none : ANFBinding)]
  let m : ANFMethod :=
    { name := methodName, params := [], body := body, isPublic := true }
  { contractName := cn
    properties := []
    methods := [m] }

/-- The fixture corollary. The TS-reference compile path through this
program produces a single-`OP_PUSH(i)` script (or one of the short-form
push opcodes for small `i`); the byte-level theorem says that script
parses back to `[push i]` and the parsed op list, run against the
initial stack, agrees observationally with ANF evaluation of
`[loadConst .int i]`. -/
theorem compile_runs_correctly_simple_singleton_int
    (cn methodName bn : String) (i : Int)
    (hMethodNotConstructor : methodName ≠ "constructor")
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged [] initialAnf initialStack)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm []))
    (hRunarEmittable :
        Script.Parse.AreRunarEmittable
          (peepholeMethod
            (Stack.Lower.lowerMethod
              (someProgram cn methodName bn i).methods
              (someProgram cn methodName bn i).properties
              { name := methodName, params := [],
                body := [⟨bn, .loadConst (.int i), none⟩],
                isPublic := true })).ops)
    (hMethodOpsEq :
        (peepholeMethod
          (Stack.Lower.lowerMethod
            (someProgram cn methodName bn i).methods
            (someProgram cn methodName bn i).properties
            { name := methodName, params := [],
              body := [⟨bn, .loadConst (.int i), none⟩],
              isPublic := true })).ops
        = (Stack.Lower.lowerBindings []
            [⟨bn, .loadConst (.int i), none⟩]).1) :
    let m : ANFMethod :=
      { name := methodName, params := [],
        body := [⟨bn, .loadConst (.int i), none⟩], isPublic := true }
    ∃ ops,
      Script.Parse.parseScript (Pipeline.compile (someProgram cn methodName bn i))
        = .ok ops ∧
      observationallyEqual
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
        (Stack.Eval.runOps ops initialStack) := by
  -- Set up the program structure.
  let m : ANFMethod :=
    { name := methodName, params := [],
      body := [⟨bn, .loadConst (.int i), none⟩], isPublic := true }
  -- Filter projection: only one public method.
  have hSinglePublic :
      (someProgram cn methodName bn i).methods.filter (·.isPublic) = [m] := by
    show (List.filter (·.isPublic) [m]) = [m]
    -- The single method m has isPublic = true, so the filter is identity.
    rfl
  -- Discharge the structured-form's pre-existing hypotheses via the
  -- singleton-loadConst-int chain (Stack.Agrees.stageC_simpleStep_loadConst_int +
  -- chainRel_cons + chainRel_nil + runOps_lowerBindings_singleton).
  have ⟨hRunPre, hChain⟩ :=
    stageC_chain_singleton_loadConst_int bn i [] initialAnf initialStack hFresh
  -- ANF eval of `[loadConst .int i]` against initialAnf reduces to
  -- `.ok (initialAnf.addBinding bn (.vBigint i))` by definitional
  -- unfolding of evalBindings (singleton list of `loadConst .int`).
  have hAnfEvalEq :
      RunarVerification.ANF.Eval.evalBindings initialAnf m.body
      = .ok (initialAnf.addBinding bn (.vBigint i)) := by
    show RunarVerification.ANF.Eval.evalBindings initialAnf
          [⟨bn, .loadConst (.int i), none⟩]
        = .ok (initialAnf.addBinding bn (.vBigint i))
    -- evalBindings on `[mk bn (loadConst (int i)) _]` reduces via the
    -- mk-arm: do let (val, s') ← evalValue ...; evalBindings (s'.add ...) [].
    -- Then evalBindings on `[]` is `.ok s'`.
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    show RunarVerification.ANF.Eval.evalBindings
            (initialAnf.addBinding bn (.vBigint i)) [] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    rfl
  -- Compose the byte-level theorem.
  exact compile_runs_correctly_simple
    (someProgram cn methodName bn i) m hSinglePublic hMethodNotConstructor
    hRunarEmittable
    [] [] ((bn, Stack.Agrees.SlotKind.binding) :: [])
    initialAnf (initialAnf.addBinding bn (.vBigint i))
    initialStack (initialStack.push (.vBigint i))
    hRunPre hChain hAgrees hMethodOpsEq hAnfEvalEq

/-! ## Tier 3.3 — `compile_observational_correct_simple` (headline)

The headline theorem the remediation plan promised. Lifts
`compile_observational_correct_simple_structured` (which takes
the operational witnesses `hRunPre`, `hChain`, `hAgrees`,
`hAnfEvalEq` directly) to a form that:

* Quantifies over the standard program-domain constraints
  (`WF.ANF`, `SimpleANF`, `m ∈ p.methods`, `m.isPublic`, name-uniqueness).
* Carries the `hNoPostProc` predicate (matching the gates of
  `lowerMethod_ops_trivial_case`) so the post-processing path
  is documented at the headline.
* Bundles the operational witnesses into an existential
  `hAnfEvalSucceeds` so the caller may provide them per-fixture
  via the existing `stageC_chain_singleton_*` corollaries.

`hMethodOpsEq` remains an honest hypothesis (the bridge from
`lowerBindingsP` — used by `lowerMethod` post-processing — to
`lowerBindings` — used by Stage C / `runOps` — for the
no-post-processing case is mechanical but not yet landed; tracked
as a follow-up).

This is the **honest hypothesis-form** successor of
`compile_observational_correct_skeleton`: where the skeleton's
load-bearing claims (`hLowSimulates`, `hPeepEq`) were the entire
goal restated, this theorem's hypotheses are real
operational/structural obligations grounded in the Stage A/B/C/D
substrate. -/

theorem compile_observational_correct_simple
    (p : ANFProgram) (_hWF : WF.ANF p) (_hSimple : Stack.Lower.SimpleANF p)
    (_hNoPostProc : ∀ m ∈ p.methods,
        Stack.Lower.bindingsUseCheckPreimage m.body = false ∧
        ¬ (m.isPublic = true ∧ Stack.Lower.bodyEndsInAssert m.body = true) ∧
        ¬ (m.isPublic = true ∧
           Stack.Lower.bindingsUseDeserializeState m.body = true))
    (m : ANFMethod) (hMember : m ∈ p.methods)
    (hPublic : m.isPublic = true)
    (hUnique : ∀ m' ∈ p.methods,
        m'.isPublic = true → m'.name = m.name → m' = m)
    (sm : Stack.Lower.StackMap)
    (tsm : Stack.Agrees.TaggedStackMap)
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hSmEq : sm = Stack.Agrees.untagSm tsm)
    (hAnfEvalSucceeds :
        ∃ tsmFinal anfFinal stkFinal,
          ANF.Eval.evalBindings initialAnf m.body = .ok anfFinal ∧
          Stack.Eval.runOps (Stack.Lower.lowerBindings sm m.body).1 initialStack
            = .ok stkFinal ∧
          Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel m.body
            tsm initialAnf initialStack tsmFinal anfFinal stkFinal)
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings sm m.body).1) :
    observationallyEqual
      (ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  obtain ⟨tsmFinal, anfFinal, stkFinal,
          hAnfEvalEq, hRunPre, hChain⟩ := hAnfEvalSucceeds
  subst hSmEq
  exact compile_observational_correct_simple_structured
    p m hMember hPublic hUnique
    (Stack.Agrees.untagSm tsm) tsm tsmFinal
    initialAnf anfFinal initialStack stkFinal
    hRunPre hChain hAgrees hMethodOpsEq hAnfEvalEq

/-! ## Per-fixture corollaries of `compile_observational_correct_simple`

Each corollary specialises the headline theorem to a concrete
SimpleANF body shape, internally discharging `hAnfEvalSucceeds`
via the existing `stageC_chain_singleton_*` substrate. Because
the bridge from `lowerBindingsP` (used by `lowerMethod` post-
processing) to `lowerBindings` (used by Stage C / `runOps`) is
not yet landed, every corollary takes `hMethodOpsEq` as a
remaining hypothesis — a strict subset of the obligations in
`compile_observational_correct_skeleton_strong`. -/

/-- 1-binding `[loadConst .int i]` body. Pipeline-level
`observationallyEqual` reduces to the existing per-binding
Stage A/B/C/D witness. -/
theorem compile_observational_correct_simple_loadConst_int
    (p : ANFProgram) (hWF : WF.ANF p) (hSimple : Stack.Lower.SimpleANF p)
    (hNoPostProc : ∀ m ∈ p.methods,
        Stack.Lower.bindingsUseCheckPreimage m.body = false ∧
        ¬ (m.isPublic = true ∧ Stack.Lower.bodyEndsInAssert m.body = true) ∧
        ¬ (m.isPublic = true ∧
           Stack.Lower.bindingsUseDeserializeState m.body = true))
    (m : ANFMethod) (hMember : m ∈ p.methods)
    (hPublic : m.isPublic = true)
    (hUnique : ∀ m' ∈ p.methods,
        m'.isPublic = true → m'.name = m.name → m' = m)
    (bn : String) (i : Int)
    (hBody : m.body = [(ANFBinding.mk bn (.loadConst (.int i)) none : ANFBinding)])
    (tsm : Stack.Agrees.TaggedStackMap)
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) m.body).1) :
    observationallyEqual
      (ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  -- Discharge `hAnfEvalSucceeds` via the singleton-loadConst-int chain.
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_int bn i tsm initialAnf initialStack hFresh
  -- ANF.Eval.evalBindings on a singleton loadConst .int reduces to addBinding.
  have hAnfEvalEq :
      ANF.Eval.evalBindings initialAnf m.body
      = .ok (initialAnf.addBinding bn (.vBigint i)) := by
    rw [hBody]
    show RunarVerification.ANF.Eval.evalBindings initialAnf
          [⟨bn, .loadConst (.int i), none⟩]
        = .ok (initialAnf.addBinding bn (.vBigint i))
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    show RunarVerification.ANF.Eval.evalBindings
            (initialAnf.addBinding bn (.vBigint i)) [] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    rfl
  apply compile_observational_correct_simple
    p hWF hSimple hNoPostProc m hMember hPublic hUnique
    (Stack.Agrees.untagSm tsm) tsm initialAnf initialStack hAgrees rfl
  · refine ⟨((bn, Stack.Agrees.SlotKind.binding) :: tsm),
            initialAnf.addBinding bn (.vBigint i),
            initialStack.push (.vBigint i),
            hAnfEvalEq, ?_, ?_⟩
    · rw [hBody]; exact hRun
    · rw [hBody]; exact hChain
  · rw [hBody]; rw [hBody] at hMethodOpsEq; exact hMethodOpsEq

/-- 1-binding `[loadConst .bool flag]` body. -/
theorem compile_observational_correct_simple_loadConst_bool
    (p : ANFProgram) (hWF : WF.ANF p) (hSimple : Stack.Lower.SimpleANF p)
    (hNoPostProc : ∀ m ∈ p.methods,
        Stack.Lower.bindingsUseCheckPreimage m.body = false ∧
        ¬ (m.isPublic = true ∧ Stack.Lower.bodyEndsInAssert m.body = true) ∧
        ¬ (m.isPublic = true ∧
           Stack.Lower.bindingsUseDeserializeState m.body = true))
    (m : ANFMethod) (hMember : m ∈ p.methods)
    (hPublic : m.isPublic = true)
    (hUnique : ∀ m' ∈ p.methods,
        m'.isPublic = true → m'.name = m.name → m' = m)
    (bn : String) (flag : Bool)
    (hBody : m.body = [(ANFBinding.mk bn (.loadConst (.bool flag)) none : ANFBinding)])
    (tsm : Stack.Agrees.TaggedStackMap)
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) m.body).1) :
    observationallyEqual
      (ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_bool bn flag tsm initialAnf initialStack hFresh
  have hAnfEvalEq :
      ANF.Eval.evalBindings initialAnf m.body
      = .ok (initialAnf.addBinding bn (.vBool flag)) := by
    rw [hBody]
    show RunarVerification.ANF.Eval.evalBindings initialAnf
          [⟨bn, .loadConst (.bool flag), none⟩]
        = .ok (initialAnf.addBinding bn (.vBool flag))
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    show RunarVerification.ANF.Eval.evalBindings
            (initialAnf.addBinding bn (.vBool flag)) [] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    rfl
  apply compile_observational_correct_simple
    p hWF hSimple hNoPostProc m hMember hPublic hUnique
    (Stack.Agrees.untagSm tsm) tsm initialAnf initialStack hAgrees rfl
  · refine ⟨((bn, Stack.Agrees.SlotKind.binding) :: tsm),
            initialAnf.addBinding bn (.vBool flag),
            initialStack.push (.vBool flag),
            hAnfEvalEq, ?_, ?_⟩
    · rw [hBody]; exact hRun
    · rw [hBody]; exact hChain
  · rw [hBody]; rw [hBody] at hMethodOpsEq; exact hMethodOpsEq

/-- 1-binding `[loadConst .bytes ba]` body. -/
theorem compile_observational_correct_simple_loadConst_bytes
    (p : ANFProgram) (hWF : WF.ANF p) (hSimple : Stack.Lower.SimpleANF p)
    (hNoPostProc : ∀ m ∈ p.methods,
        Stack.Lower.bindingsUseCheckPreimage m.body = false ∧
        ¬ (m.isPublic = true ∧ Stack.Lower.bodyEndsInAssert m.body = true) ∧
        ¬ (m.isPublic = true ∧
           Stack.Lower.bindingsUseDeserializeState m.body = true))
    (m : ANFMethod) (hMember : m ∈ p.methods)
    (hPublic : m.isPublic = true)
    (hUnique : ∀ m' ∈ p.methods,
        m'.isPublic = true → m'.name = m.name → m' = m)
    (bn : String) (ba : ByteArray)
    (hBody : m.body = [(ANFBinding.mk bn (.loadConst (.bytes ba)) none : ANFBinding)])
    (tsm : Stack.Agrees.TaggedStackMap)
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) m.body).1) :
    observationallyEqual
      (ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_bytes bn ba tsm initialAnf initialStack hFresh
  have hAnfEvalEq :
      ANF.Eval.evalBindings initialAnf m.body
      = .ok (initialAnf.addBinding bn (.vBytes ba)) := by
    rw [hBody]
    show RunarVerification.ANF.Eval.evalBindings initialAnf
          [⟨bn, .loadConst (.bytes ba), none⟩]
        = .ok (initialAnf.addBinding bn (.vBytes ba))
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    show RunarVerification.ANF.Eval.evalBindings
            (initialAnf.addBinding bn (.vBytes ba)) [] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    rfl
  apply compile_observational_correct_simple
    p hWF hSimple hNoPostProc m hMember hPublic hUnique
    (Stack.Agrees.untagSm tsm) tsm initialAnf initialStack hAgrees rfl
  · refine ⟨((bn, Stack.Agrees.SlotKind.binding) :: tsm),
            initialAnf.addBinding bn (.vBytes ba),
            initialStack.push (.vBytes ba),
            hAnfEvalEq, ?_, ?_⟩
    · rw [hBody]; exact hRun
    · rw [hBody]; exact hChain
  · rw [hBody]; rw [hBody] at hMethodOpsEq; exact hMethodOpsEq

/-- 1-binding `[loadConst .thisRef]` body. The `loadConst .thisRef`
case is special: it emits no stack ops (lowering is a no-op) and
the simpleStepRel for `thisRef` leaves the tagged stack-map
unchanged. -/
theorem compile_observational_correct_simple_loadConst_thisRef
    (p : ANFProgram) (hWF : WF.ANF p) (hSimple : Stack.Lower.SimpleANF p)
    (hNoPostProc : ∀ m ∈ p.methods,
        Stack.Lower.bindingsUseCheckPreimage m.body = false ∧
        ¬ (m.isPublic = true ∧ Stack.Lower.bodyEndsInAssert m.body = true) ∧
        ¬ (m.isPublic = true ∧
           Stack.Lower.bindingsUseDeserializeState m.body = true))
    (m : ANFMethod) (hMember : m ∈ p.methods)
    (hPublic : m.isPublic = true)
    (hUnique : ∀ m' ∈ p.methods,
        m'.isPublic = true → m'.name = m.name → m' = m)
    (bn : String)
    (hBody : m.body = [(ANFBinding.mk bn (.loadConst .thisRef) none : ANFBinding)])
    (tsm : Stack.Agrees.TaggedStackMap)
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hFresh : Stack.Agrees.freshIn bn (Stack.Agrees.untagSm tsm))
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) m.body).1) :
    observationallyEqual
      (ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  have ⟨hRun, hChain⟩ :=
    stageC_chain_singleton_loadConst_thisRef bn tsm initialAnf initialStack hFresh
  have hAnfEvalEq :
      ANF.Eval.evalBindings initialAnf m.body
      = .ok (initialAnf.addBinding bn .vThis) := by
    rw [hBody]
    show RunarVerification.ANF.Eval.evalBindings initialAnf
          [⟨bn, .loadConst .thisRef, none⟩]
        = .ok (initialAnf.addBinding bn .vThis)
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    show RunarVerification.ANF.Eval.evalBindings
            (initialAnf.addBinding bn .vThis) [] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    rfl
  apply compile_observational_correct_simple
    p hWF hSimple hNoPostProc m hMember hPublic hUnique
    (Stack.Agrees.untagSm tsm) tsm initialAnf initialStack hAgrees rfl
  · -- thisRef leaves tsm unchanged and stkSt unchanged.
    refine ⟨tsm, initialAnf.addBinding bn .vThis, initialStack,
            hAnfEvalEq, ?_, ?_⟩
    · rw [hBody]; exact hRun
    · rw [hBody]; exact hChain
  · rw [hBody]; rw [hBody] at hMethodOpsEq; exact hMethodOpsEq

/-- 2-binding `[loadConst .int i1, loadConst .int i2]` body. Composes
two `stageC_simpleStep_loadConst_int` discharges via the existing
`stageC_two_loadConst_int` substrate. **First 2-binding fully-
discharged pipeline-level corollary of `compile_observational_correct_simple`.** -/
theorem compile_observational_correct_simple_two_loadConst_int
    (p : ANFProgram) (hWF : WF.ANF p) (hSimple : Stack.Lower.SimpleANF p)
    (hNoPostProc : ∀ m ∈ p.methods,
        Stack.Lower.bindingsUseCheckPreimage m.body = false ∧
        ¬ (m.isPublic = true ∧ Stack.Lower.bodyEndsInAssert m.body = true) ∧
        ¬ (m.isPublic = true ∧
           Stack.Lower.bindingsUseDeserializeState m.body = true))
    (m : ANFMethod) (hMember : m ∈ p.methods)
    (hPublic : m.isPublic = true)
    (hUnique : ∀ m' ∈ p.methods,
        m'.isPublic = true → m'.name = m.name → m' = m)
    (bn1 bn2 : String) (i1 i2 : Int)
    (hBody : m.body =
        [(ANFBinding.mk bn1 (.loadConst (.int i1)) none : ANFBinding),
         (ANFBinding.mk bn2 (.loadConst (.int i2)) none : ANFBinding)])
    (tsm : Stack.Agrees.TaggedStackMap)
    (initialAnf : ANF.Eval.State) (initialStack : Stack.Eval.StackState)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hFresh1 : Stack.Agrees.freshIn bn1 (Stack.Agrees.untagSm tsm))
    (hFresh2 : Stack.Agrees.freshIn bn2
        (Stack.Agrees.untagSm ((bn1, Stack.Agrees.SlotKind.binding) :: tsm)))
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings (Stack.Agrees.untagSm tsm) m.body).1) :
    observationallyEqual
      (ANF.Eval.evalBindings initialAnf m.body)
      (Stack.Eval.runMethod
        (peepholeProgram (Stack.Lower.lower p)) m.name initialStack) := by
  have ⟨hRun, hChain⟩ := Stack.Agrees.stageC_two_loadConst_int
                            bn1 bn2 i1 i2 tsm initialAnf initialStack hFresh1 hFresh2
  -- Two-step ANF eval: bn1 := i1, then bn2 := i2.
  have hAnfEvalEq :
      ANF.Eval.evalBindings initialAnf m.body
      = .ok ((initialAnf.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2)) := by
    rw [hBody]
    show RunarVerification.ANF.Eval.evalBindings initialAnf
          [⟨bn1, .loadConst (.int i1), none⟩, ⟨bn2, .loadConst (.int i2), none⟩]
        = .ok ((initialAnf.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2))
    -- Step 1: peel the bn1 binding.
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    -- Step 2: peel the bn2 binding.
    show RunarVerification.ANF.Eval.evalBindings
            (initialAnf.addBinding bn1 (.vBigint i1))
            [⟨bn2, .loadConst (.int i2), none⟩] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    simp only [RunarVerification.ANF.Eval.evalValue, bind, Except.bind]
    show RunarVerification.ANF.Eval.evalBindings
            ((initialAnf.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2))
            [] = _
    unfold RunarVerification.ANF.Eval.evalBindings
    rfl
  apply compile_observational_correct_simple
    p hWF hSimple hNoPostProc m hMember hPublic hUnique
    (Stack.Agrees.untagSm tsm) tsm initialAnf initialStack hAgrees rfl
  · refine ⟨((bn2, Stack.Agrees.SlotKind.binding) ::
              (bn1, Stack.Agrees.SlotKind.binding) :: tsm),
            (initialAnf.addBinding bn1 (.vBigint i1)).addBinding bn2 (.vBigint i2),
            (initialStack.push (.vBigint i1)).push (.vBigint i2),
            hAnfEvalEq, ?_, ?_⟩
    · rw [hBody]; exact hRun
    · rw [hBody]; exact hChain
  · rw [hBody]; rw [hBody] at hMethodOpsEq; exact hMethodOpsEq

/-! ## Tier 3.4 Path B foundation — multi-method dispatch

Path A above (`compile_runs_correctly_simple`) covers programs whose
public-method projection is a singleton `[m]`. Path B targets programs
with `n ≥ 2` public methods, where `Pipeline.compile p` emits the
TS-reference dispatch chain
`OP_DUP <0> OP_NUMEQUAL OP_IF OP_DROP <body_0> OP_ELSE … <n-1>
OP_NUMEQUALVERIFY <body_{n-1}> OP_ENDIF * (n-1)`. The unlocking script
pushes a selector index `i ∈ [0, n-1]` on the stack top, and the
locking script's chain dispatches to body `i`.

`Stack.Eval.runMethodByIndex` (defined in `Stack/Eval.lean`) is the
semantic mirror of the byte-level dispatch: given the public-methods
list and an index, it runs the indexed method's op stream. The
operational equivalence

```
runOps (Emit.emitDispatch ms) (initialStack with selector_idx on top)
  = runMethodByIndex ms idx initialStack
```

is the headline Path B obligation. Proving it requires reasoning about
the `OP_IF`/`OP_ELSE`/`OP_ENDIF` control flow recovered by
`parseScript` as `.ifOp thn els` structured operations, then showing
that the structured dispatch evaluates to the matching body — this is
mechanical but lengthy (the `OP_DUP <i> OP_NUMEQUAL` head produces a
boolean from the stack-top index, and the structured-form `runOps`
inlines the if-branch dispatch). The full multi-method bridging is
tracked as a follow-up alongside `parseDispatchN_emit_round_trip` (Tier
3.4 Path B Phase 1), which already discharges the byte-recognition
half.

This section delivers the **singleton-list base case** of the bridging
lemma — when `ms = [m]`, `runMethodByIndex [m] 0 = runOps m.ops` (by
`runMethodByIndex_singleton_zero` in `Stack.Eval`), and
`Emit.emitDispatch [m] = Emit.emitOps m.ops` is *not* the path used by
`Pipeline.compile` (the single-method path bypasses the dispatch chain
via `Emit.emit`'s `[m]` arm). The base case is therefore documentary:
it pins down the semantic shape for the multi-method induction's foot
even though `Pipeline.compile` does not emit a dispatch chain for a
single public method.
-/

/-! ### Singleton-`runMethodByIndex` reduction at idx = 0

Trivial wrapper around `Stack.Eval.runMethodByIndex_singleton_zero`,
lifted to the post-pipeline public-methods list shape. Documents the
Path B foot-of-induction: when the public-methods projection is the
singleton `[m']`, dispatch-by-index reduces to running the sole body. -/
theorem runMethodByIndex_singleton_post_pipeline
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m])
    (hNotConstructor : m.name ≠ "constructor")
    (initialStack : Stack.Eval.StackState) :
    Stack.Eval.runMethodByIndex
        (Script.Emit.publicMethodsOf (peepholeProgram (Stack.Lower.lower p))) 0
        initialStack
      = Stack.Eval.runOps
          (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
          initialStack := by
  rw [publicMethodsOf_peephole_lower_of_single_public p m hSinglePublic hNotConstructor]
  exact Stack.Eval.runMethodByIndex_singleton_zero _ initialStack

/-! ### Multi-method byte-level theorem (foundation form)

The full multi-method Path B theorem (`compile_runs_correctly_simple_multi`
in the task spec) carries the dispatch-chain semantic equivalence,
which depends on the deferred `runOps_emitDispatch_eq_runMethodByIndex`
bridging lemma (operational `OP_IF`/`OP_ELSE` interpretation). What we
can deliver today is the structural foundation: for the singleton
public-methods case, the byte-level conclusion of Path A specialises
to the `runMethodByIndex` form trivially.

This corollary is the *foundation* for the multi-method theorem — its
conclusion is structurally identical to Path A's
`compile_runs_correctly_simple`, but routes the result through
`runMethodByIndex` (the Path B semantics) instead of `runMethod` (the
Path A by-name semantics). When the dispatch-chain bridging lemma
lands, the same `∃ ops, parseScript ... ∧ observationallyEqual ...`
conclusion will hold for `n ≥ 2` public methods, with `runMethodByIndex
ms idx` selecting which body's evaluation is observationally compared.
-/
theorem compile_runs_correctly_simple_multi_singleton_case
    (p : ANFProgram) (m : ANFMethod)
    (hSinglePublic : p.methods.filter (·.isPublic) = [m])
    (hNotConstructor : m.name ≠ "constructor")
    (hRunarEmittable :
        Script.Parse.AreRunarEmittable
          (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops)
    (sm : Stack.Lower.StackMap)
    (tsm tsm' : Stack.Agrees.TaggedStackMap)
    (initialAnf anfFinal : ANF.Eval.State)
    (initialStack stkFinal : Stack.Eval.StackState)
    (hRunPre :
        Stack.Eval.runOps (Stack.Lower.lowerBindings sm m.body).1 initialStack
        = .ok stkFinal)
    (hChain :
        Stack.Agrees.ChainRel Stack.Agrees.simpleStepRel m.body tsm
          initialAnf initialStack tsm' anfFinal stkFinal)
    (hAgrees : Stack.Agrees.agreesTagged tsm initialAnf initialStack)
    (hMethodOpsEq :
        (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops
        = (Stack.Lower.lowerBindings sm m.body).1)
    (hAnfEvalEq :
        RunarVerification.ANF.Eval.evalBindings initialAnf m.body = .ok anfFinal) :
    ∃ ops,
      Script.Parse.parseScript (Pipeline.compile p) = .ok ops ∧
      observationallyEqual
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
        (Stack.Eval.runMethodByIndex
          (Script.Emit.publicMethodsOf (peepholeProgram (Stack.Lower.lower p))) 0
          initialStack) := by
  -- Compose Path A's `compile_runs_correctly_simple` with the singleton
  -- `runMethodByIndex` bridge.
  obtain ⟨ops, hParse, hOEq⟩ :=
    compile_runs_correctly_simple p m hSinglePublic hNotConstructor
      hRunarEmittable sm tsm tsm' initialAnf anfFinal initialStack stkFinal
      hRunPre hChain hAgrees hMethodOpsEq hAnfEvalEq
  refine ⟨ops, hParse, ?_⟩
  -- `compile_runs_correctly_simple` gives `runOps ops initialStack`,
  -- with `ops = (peepholeMethod (lowerMethod ... m)).ops`. The
  -- singleton-`runMethodByIndex` bridge converts this to the Path B form.
  -- First derive that the chosen `ops` is exactly the peephole-lowered ops list.
  have hOpsEq : ops = (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops := by
    -- The witness from `compile_runs_correctly_simple` is exactly this op list
    -- (its existential is `refine ⟨(peepholeMethod ...).ops, ?_, ?_⟩`). To recover
    -- this fact, re-derive `parseScript (compile p) = .ok (peepholeMethod ...).ops`
    -- and use the parse-result injectivity.
    have hParse' : Script.Parse.parseScript (Pipeline.compile p)
        = .ok (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops := by
      rw [compile_eq_emitOps_of_single_public p m hSinglePublic hNotConstructor]
      exact Script.Parse.parseScript_emit_round_trip _ hRunarEmittable
    -- `parseScript` returns `.ok` injectively: the two `.ok` witnesses agree.
    have hEqOk : (Except.ok ops
            : Except Script.Parse.ParseError (List Stack.StackOp))
        = Except.ok
            (peepholeMethod (Stack.Lower.lowerMethod p.methods p.properties m)).ops := by
      rw [← hParse, hParse']
    exact Except.ok.inj hEqOk
  rw [hOpsEq] at hOEq
  rw [runMethodByIndex_singleton_post_pipeline p m hSinglePublic hNotConstructor initialStack]
  exact hOEq

/-! ### Path B follow-up obligations

The full `n ≥ 2` Path B theorem needs the following pieces, all of
which are mechanical extensions of the existing substrate:

1. **`runOps_emitDispatchChain_eq_runMethodByIndex`** — the dispatch
   chain's structured-form (`.ifOp thn els` after `parseScript`'s
   balanced-bracket parser recovers OP_IF/OP_ELSE/OP_ENDIF) evaluates
   `runOps` to the body of the matching index. Strategy: induction on
   `ms`, peel the `OP_DUP <i> OP_NUMEQUAL OP_IF OP_DROP <body_i>
   OP_ELSE …` head, case-split on whether the selector matches `i`.
   The base case is the singleton `[m]` (via
   `runMethodByIndex_singleton_zero` above); the step case threads
   `OP_DUP <i> OP_NUMEQUAL`'s evaluation through `runOps`'s `.ifOp`
   arm. The pre-condition `initialStack.stack.head? = some (.vBigint
   (Int.ofNat idx))` ensures the selector is present on the stack top.

2. **`Pipeline.compile p`-to-`emitDispatchChain` reduction** — for an
   `n ≥ 2` public-methods program, `Pipeline.compile p =
   emitDispatchChain 0 ms ++ emitEndifs (n-1)` where `ms =
   publicMethodsOf (peepholeProgram (Lower.lower p))`. Direct unfolding
   of `Emit.emit`'s `ms` arm.

3. **`compile_observational_correct_simple_structured` lift** — the
   existing observational-equivalence theorem is keyed on the named
   `runMethod` (find-by-name on the post-pipeline `methods` list). For
   the multi-method case, the same observational equivalence holds
   for `runMethodByIndex` with `idx` matching `m`'s position in
   `publicMethodsOf`. Requires showing `publicMethodsOf`'s `nthOpt
   idx` returns `peepholeMethod (lowerMethod ... m)` when `m` is the
   `idx`-th public method of `p.methods`.

The `compile_runs_correctly_simple_multi_singleton_case` corollary
above is the structural foundation: when these three pieces land, the
multi-method theorem composes them with Path A's existing machinery
in the same shape demonstrated for the singleton case here. -/

/-! ## Tier 3.4 Path B — structured `.ifOp` operational lemmas

The byte-level `OP_IF` / `OP_ELSE` / `OP_ENDIF` opcodes are recovered
by `Script.Parse.parseScript` as the **structured** `StackOp.ifOp thn
els` constructor — a single matched-bracket node carrying both
branches and an explicit (optional) else. The Lean Stack VM (`runOps`
in `Stack/Eval.lean`) operates on this structured form directly,
inlining the `.ifOp` case in the recursion (`runOps.eq_2`).

This section discharges the structured operational lemmas needed by
the multi-method dispatch chain: a single `.ifOp` step rule plus the
2-method dispatch-chain match lemmas, then a bridge to
`runMethodByIndex`. Because the byte-level decoder is already proven
correct (`Script.Parse.parseScript_emit_round_trip`), reasoning at
the structured level is sufficient — the byte-level `OP_IF`/`OP_ELSE`/
`OP_ENDIF` semantics is recovered through `parseScript` and replayed
as `.ifOp thn els` in `runOps`.

The byte-level direct-semantics path (a hypothetical `runScript :
ByteArray → ScriptState → ScriptResult` evaluator) is **not**
materialised here: parser-correctness + structured `runOps` is the
cleaner of the two acceptable approaches identified in the Path B
task spec, and avoids duplicating the per-opcode dispatch from
`Stack.Eval.runOpcode`.
-/

/-! ### Single-step structured `.ifOp` reduction

These mirror the structured operational lemma the spec calls out
(`runOps_if_else_endif_match`) — except they target `.ifOp thn els`,
which is the form `parseScript` recovers from balanced `OP_IF` /
`OP_ELSE` / `OP_ENDIF` bytes. Both branches handled symmetrically:
true takes `thn`, false takes `els` (or skips when `els = none`). -/

/-- `runOps (.ifOp thn (some els) :: rest) s` when the top of the
stack is `.vBool true`: pops the condition and runs `thn` then `rest`. -/
theorem runOps_cons_ifOp_some_true
    (thn els rest : List Stack.StackOp) (s : Stack.Eval.StackState)
    (v : ANF.Eval.Value)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = v :: tail)
    (hBool : Stack.Eval.asBool? v = some true) :
    Stack.Eval.runOps (.ifOp thn (some els) :: rest) s
      = match Stack.Eval.runOps thn { s with stack := tail } with
        | .error e => .error e
        | .ok s'   => Stack.Eval.runOps rest s' := by
  rw [Stack.Eval.runOps.eq_2 s thn (some els) rest]
  -- s.pop? = some (v, {s with stack := tail})
  have hPop : s.pop? = some (v, { s with stack := tail }) := by
    unfold Stack.Eval.StackState.pop?; rw [hStack]
  rw [hPop]
  simp only []
  rw [hBool]
  rfl

/-- `runOps (.ifOp thn (some els) :: rest) s` when the top of the
stack is `.vBool false`: pops the condition and runs `els` then `rest`. -/
theorem runOps_cons_ifOp_some_false
    (thn els rest : List Stack.StackOp) (s : Stack.Eval.StackState)
    (v : ANF.Eval.Value)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = v :: tail)
    (hBool : Stack.Eval.asBool? v = some false) :
    Stack.Eval.runOps (.ifOp thn (some els) :: rest) s
      = match Stack.Eval.runOps els { s with stack := tail } with
        | .error e => .error e
        | .ok s'   => Stack.Eval.runOps rest s' := by
  rw [Stack.Eval.runOps.eq_2 s thn (some els) rest]
  have hPop : s.pop? = some (v, { s with stack := tail }) := by
    unfold Stack.Eval.StackState.pop?; rw [hStack]
  rw [hPop]
  simp only []
  rw [hBool]
  rfl

/-- `runOps (.ifOp thn none :: rest) s` when the top of the stack is
`.vBool false`: pops the condition and runs `rest` directly. The
empty-else case is the no-op branch. -/
theorem runOps_cons_ifOp_none_false
    (thn rest : List Stack.StackOp) (s : Stack.Eval.StackState)
    (v : ANF.Eval.Value)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = v :: tail)
    (hBool : Stack.Eval.asBool? v = some false) :
    Stack.Eval.runOps (.ifOp thn none :: rest) s
      = Stack.Eval.runOps rest { s with stack := tail } := by
  rw [Stack.Eval.runOps.eq_2 s thn none rest]
  have hPop : s.pop? = some (v, { s with stack := tail }) := by
    unfold Stack.Eval.StackState.pop?; rw [hStack]
  rw [hPop]
  simp only []
  rw [hBool]

/-- `runOps (.ifOp thn none :: rest) s` when the top of the stack is
`.vBool true`: pops the condition and runs `thn` then `rest`. -/
theorem runOps_cons_ifOp_none_true
    (thn rest : List Stack.StackOp) (s : Stack.Eval.StackState)
    (v : ANF.Eval.Value)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = v :: tail)
    (hBool : Stack.Eval.asBool? v = some true) :
    Stack.Eval.runOps (.ifOp thn none :: rest) s
      = match Stack.Eval.runOps thn { s with stack := tail } with
        | .error e => .error e
        | .ok s'   => Stack.Eval.runOps rest s' := by
  rw [Stack.Eval.runOps.eq_2 s thn none rest]
  have hPop : s.pop? = some (v, { s with stack := tail }) := by
    unfold Stack.Eval.StackState.pop?; rw [hStack]
  rw [hPop]
  simp only []
  rw [hBool]
  rfl

/-! ### Structured-level 2-method dispatch program

The byte-level dispatch chain emitted by `Emit.emitDispatch` for two
public methods `m0`, `m1` decodes via `parseScript`'s balanced-bracket
parser to the following structured `StackOp` list:

```
[ .dup, .push (.bigint 0), .opcode "OP_NUMEQUAL",
  .ifOp ([.drop] ++ m0.ops)
        (some ([.push (.bigint 1), .opcode "OP_NUMEQUALVERIFY"] ++ m1.ops))
]
```

We name this structured form `structuredDispatch2` so the operational
lemmas below can refer to it without re-stating the layout. Note this
mirrors the *post-parseScript* shape: the head `OP_DUP push(0)
OP_NUMEQUAL OP_IF OP_DROP body0 OP_ELSE` from `emitDispatchHeadNonLast`
becomes `.dup, .push 0, .opcode NUMEQUAL, .ifOp ([.drop ++ body0] ...
)`, and the parser merges the inner `OP_ELSE ... OP_ENDIF` into the
`some` else-branch carrying the last method's `push(1)
OP_NUMEQUALVERIFY body1` sequence.
-/

/-- Structured form of the 2-method dispatch chain (post-`parseScript`
shape). Mirrors the layout `Emit.emitDispatch [m0, m1]` produces after
the parser brackets `OP_IF`/`OP_ELSE`/`OP_ENDIF` into a `.ifOp` node. -/
def structuredDispatch2 (m0Ops m1Ops : List Stack.StackOp) : List Stack.StackOp :=
  [ .dup
  , .push (.bigint 0)
  , .opcode "OP_NUMEQUAL"
  , .ifOp ([.drop] ++ m0Ops)
          (some ([.push (.bigint 1), .opcode "OP_NUMEQUALVERIFY"] ++ m1Ops))
  ]

/-- Selector-zero match for the 2-method structured dispatch: when
the stack-top is `.vBigint 0`, the dispatch program runs the dispatch
head (DUP / push 0 / NUMEQUAL / IF) — taking the then-branch — then
the `.drop` at the head of `thn` removes the surviving selector copy
(preserved by OP_DUP). The dispatch then continues with `m0Ops`.

Trace (stack tops, leftmost = top):
* pre-DUP:    [0, ...tail]
* post-DUP:   [0, 0, ...tail]
* post-push:  [0, 0, 0, ...tail]
* post-NEQ:   [true, 0, ...tail]  (NUMEQUAL pops 2 pushes vBool)
* post-IF:    [0, ...tail]         (IF pops the bool, takes thn)
* post-DROP:  [...tail]             (DROP removes the surviving 0)
* runs m0Ops on the post-DROP state. -/
theorem runOps_structuredDispatch2_match_zero
    (m0Ops m1Ops : List Stack.StackOp) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint 0 :: tail) :
    Stack.Eval.runOps (structuredDispatch2 m0Ops m1Ops) s
      = Stack.Eval.runOps m0Ops { s with stack := tail } := by
  unfold structuredDispatch2
  -- Step 1: `.dup` duplicates the top, leaving stack [0, 0, ...tail].
  rw [Stack.Peephole.runOps_cons_dup_eq]
  rw [Stack.Eval.stepNonIf_dup]
  have hDup : Stack.Eval.applyDup s = .ok (s.push (.vBigint 0)) := by
    unfold Stack.Eval.applyDup; rw [hStack]
  rw [hDup]
  simp only []
  -- Step 2: `.push 0` pushes another `.vBigint 0`.
  rw [Stack.Peephole.runOps_cons_push_eq]
  rw [Stack.Eval.stepNonIf_push_bigint]
  simp only []
  -- Step 3: `OP_NUMEQUAL` compares the two top integers (both 0).
  rw [Stack.Peephole.runOps_cons_opcode_eq]
  rw [Stack.Eval.stepNonIf_opcode]
  -- Pre-NUMEQUAL stack: [0, 0, 0, ...tail]. The two consumed ints are
  -- the top two zeros; rest = .vBigint 0 :: tail.
  have hMidStk :
      ((s.push (.vBigint 0)).push (.vBigint 0)).stack
        = .vBigint 0 :: .vBigint 0 :: .vBigint 0 :: tail := by
    unfold Stack.Eval.StackState.push; rw [hStack]
  have hNE :
      Stack.Eval.runOpcode "OP_NUMEQUAL" ((s.push (.vBigint 0)).push (.vBigint 0))
        = .ok ({ ((s.push (.vBigint 0)).push (.vBigint 0)) with
                  stack := .vBigint 0 :: tail }.push
              (.vBool (decide ((0 : Int) = (0 : Int))))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt
      ((s.push (.vBigint 0)).push (.vBigint 0)) 0 0 (.vBigint 0 :: tail) hMidStk
  rw [hNE]
  simp only []
  -- Reshape: the post-NUMEQUAL state equals `{s with stack := .vBool true :: .vBigint 0 :: tail}`.
  -- The `decide ((0:Int) = (0:Int))` has reduced to `decide True` after the rewrite.
  have hReshape :
      (({ ((s.push (.vBigint 0)).push (.vBigint 0)) with
            stack := (.vBigint 0 : ANF.Eval.Value) :: tail }).push
            (.vBool (decide ((0 : Int) = (0 : Int)))))
      = { s with stack := .vBool true :: .vBigint 0 :: tail } := by
    unfold Stack.Eval.StackState.push
    cases s; simp
  -- The `rw [hNE]` reduced `decide (0=0)` to `decide True` (Lean's
  -- definitional reduction for the literal). State the equation in
  -- both forms so `rw` finds either.
  have hReshape' :
      (({ ((s.push (.vBigint 0)).push (.vBigint 0)) with
            stack := (.vBigint 0 : ANF.Eval.Value) :: tail }).push
            (.vBool (decide True)))
      = { s with stack := .vBool true :: .vBigint 0 :: tail } := by
    unfold Stack.Eval.StackState.push
    cases s; simp
  -- Try both reshape forms; only one will succeed but Lean accepts the chain.
  first
    | rw [hReshape]
    | rw [hReshape']
  -- Step 4: `.ifOp` with stack `.vBool true :: .vBigint 0 :: tail` takes the then-branch.
  have hIfStack :
      ({ s with stack := .vBool true :: .vBigint 0 :: tail } : Stack.Eval.StackState).stack
        = .vBool true :: (.vBigint 0 :: tail) := rfl
  have hIfBool :
      Stack.Eval.asBool? (.vBool true : ANF.Eval.Value) = some true := rfl
  rw [runOps_cons_ifOp_some_true
        (thn := ([Stack.StackOp.drop] ++ m0Ops : List Stack.StackOp))
        (els := ([Stack.StackOp.push (.bigint 1), Stack.StackOp.opcode "OP_NUMEQUALVERIFY"] ++ m1Ops
                  : List Stack.StackOp))
        (rest := ([] : List Stack.StackOp))
        (s := { s with stack := .vBool true :: .vBigint 0 :: tail })
        (v := (.vBool true : ANF.Eval.Value))
        (tail := (.vBigint 0 :: tail : List ANF.Eval.Value))
        hIfStack hIfBool]
  -- Step 5: thn = `.drop :: m0Ops` runs on `{s with stack := .vBigint 0 :: tail}`.
  rw [show ([Stack.StackOp.drop] ++ m0Ops : List Stack.StackOp) = Stack.StackOp.drop :: m0Ops from rfl]
  rw [Stack.Peephole.runOps_cons_drop_eq]
  rw [Stack.Eval.stepNonIf_drop]
  have hDropApply :
      Stack.Eval.applyDrop ({ s with stack := .vBigint 0 :: tail } : Stack.Eval.StackState)
        = .ok ({ s with stack := tail } : Stack.Eval.StackState) := by
    unfold Stack.Eval.applyDrop
    rfl
  rw [hDropApply]
  simp only []
  -- Collapse the outer empty-rest match: `runOps [] s' = .ok s'`.
  cases hPost : Stack.Eval.runOps m0Ops ({ s with stack := tail } : Stack.Eval.StackState) with
  | error e => rfl
  | ok s'   =>
      simp only []
      exact Stack.Eval.runOps_nil s'

/-- Selector-one match for the 2-method structured dispatch: when
the stack-top is `.vBigint 1`, the dispatch program runs the dispatch
head — the NUMEQUAL against 0 fails so the ifOp takes the else-branch
— then `push 1 OP_NUMEQUALVERIFY` consumes both the 1 push and the
surviving selector copy via assertion-equality. Finally `m1Ops` runs
on a state whose stack is `tail`.

Trace:
* pre-DUP:    [1, ...tail]
* post-DUP:   [1, 1, ...tail]
* post-push:  [0, 1, 1, ...tail]
* post-NEQ:   [false, 1, ...tail]  (NUMEQUAL 0 vs 1)
* post-IF:    [1, ...tail]         (IF pops bool, takes else-branch)
* post-push1: [1, 1, ...tail]
* post-NEQV:  [...tail]             (NUMEQUALVERIFY pops 2, asserts ==)
* runs m1Ops on the post-NEQV state. -/
theorem runOps_structuredDispatch2_match_one
    (m0Ops m1Ops : List Stack.StackOp) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint 1 :: tail) :
    Stack.Eval.runOps (structuredDispatch2 m0Ops m1Ops) s
      = Stack.Eval.runOps m1Ops { s with stack := tail } := by
  unfold structuredDispatch2
  rw [Stack.Peephole.runOps_cons_dup_eq]
  rw [Stack.Eval.stepNonIf_dup]
  have hDup : Stack.Eval.applyDup s = .ok (s.push (.vBigint 1)) := by
    unfold Stack.Eval.applyDup; rw [hStack]
  rw [hDup]
  simp only []
  rw [Stack.Peephole.runOps_cons_push_eq]
  rw [Stack.Eval.stepNonIf_push_bigint]
  simp only []
  rw [Stack.Peephole.runOps_cons_opcode_eq]
  rw [Stack.Eval.stepNonIf_opcode]
  -- Pre-NUMEQUAL: [0, 1, 1, ...tail].
  have hMidStk :
      ((s.push (.vBigint 1)).push (.vBigint 0)).stack
        = .vBigint 0 :: .vBigint 1 :: .vBigint 1 :: tail := by
    unfold Stack.Eval.StackState.push; rw [hStack]
  have hNE :
      Stack.Eval.runOpcode "OP_NUMEQUAL" ((s.push (.vBigint 1)).push (.vBigint 0))
        = .ok ({ ((s.push (.vBigint 1)).push (.vBigint 0)) with
                  stack := .vBigint 1 :: tail }.push
              (.vBool (decide ((1 : Int) = (0 : Int))))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt
      ((s.push (.vBigint 1)).push (.vBigint 0)) 1 0 (.vBigint 1 :: tail) hMidStk
  rw [hNE]
  simp only []
  have hReshape :
      ({ ((s.push (.vBigint 1)).push (.vBigint 0)) with
            stack := (.vBigint 1 : ANF.Eval.Value) :: tail }.push
            (.vBool (decide ((1 : Int) = (0 : Int)))))
      = { s with stack := .vBool false :: .vBigint 1 :: tail } := by
    unfold Stack.Eval.StackState.push
    cases s; simp
  -- The post-NUMEQUAL `decide` may have reduced to `decide False` already.
  have hReshape' :
      ({ ((s.push (.vBigint 1)).push (.vBigint 0)) with
            stack := (.vBigint 1 : ANF.Eval.Value) :: tail }.push
            (.vBool (decide False)))
      = { s with stack := .vBool false :: .vBigint 1 :: tail } := by
    unfold Stack.Eval.StackState.push
    cases s; simp
  first
    | rw [hReshape]
    | rw [hReshape']
  have hIfStack :
      ({ s with stack := .vBool false :: .vBigint 1 :: tail } : Stack.Eval.StackState).stack
        = .vBool false :: (.vBigint 1 :: tail) := rfl
  have hIfBool :
      Stack.Eval.asBool? (.vBool false : ANF.Eval.Value) = some false := rfl
  rw [runOps_cons_ifOp_some_false
        (thn := ([Stack.StackOp.drop] ++ m0Ops : List Stack.StackOp))
        (els := ([Stack.StackOp.push (.bigint 1), Stack.StackOp.opcode "OP_NUMEQUALVERIFY"] ++ m1Ops
                  : List Stack.StackOp))
        (rest := ([] : List Stack.StackOp))
        (s := { s with stack := .vBool false :: .vBigint 1 :: tail })
        (v := (.vBool false : ANF.Eval.Value))
        (tail := (.vBigint 1 :: tail : List ANF.Eval.Value))
        hIfStack hIfBool]
  -- Now the else-branch: `[push 1, OP_NUMEQUALVERIFY] ++ m1Ops` on
  -- `{s with stack := .vBigint 1 :: tail}`.
  rw [show ([.push (.bigint 1), .opcode "OP_NUMEQUALVERIFY"] ++ m1Ops : List Stack.StackOp)
        = .push (.bigint 1) :: .opcode "OP_NUMEQUALVERIFY" :: m1Ops from rfl]
  rw [Stack.Peephole.runOps_cons_push_eq]
  rw [Stack.Eval.stepNonIf_push_bigint]
  simp only []
  rw [Stack.Peephole.runOps_cons_opcode_eq]
  rw [Stack.Eval.stepNonIf_opcode]
  -- Pre-NUMEQUALVERIFY stack: [1, 1, ...tail].
  -- runOpcode OP_NUMEQUALVERIFY: popN 2 → ([1, 1], state'), asInt? on both → some 1 / some 1,
  -- decide (1 = 1) = true, returns .ok state' where state'.stack = tail.
  have hNEV :
      Stack.Eval.runOpcode "OP_NUMEQUALVERIFY"
        (({ s with stack := .vBigint 1 :: tail } : Stack.Eval.StackState).push (.vBigint 1))
        = .ok ({ s with stack := tail } : Stack.Eval.StackState) := by
    -- Unfold runOpcode "OP_NUMEQUALVERIFY"; popN consumes [.vBigint 1, .vBigint 1]
    -- on a stack `[1, 1, ...tail]`, leaving residual stack = tail.
    cases s with
    | mk stk alt out pr pi cs =>
      simp [Stack.Eval.runOpcode, Stack.Eval.popN, Stack.Eval.StackState.pop?,
            Stack.Eval.StackState.push, Stack.Eval.asInt?]
  rw [hNEV]
  simp only []
  -- Goal: runOps m1Ops { s with stack := tail } = the same (modulo the
  -- outer `match` collapse from runOps_cons_ifOp_some_false's residual
  -- `runOps [] s' = .ok s'`).
  cases hPost : Stack.Eval.runOps m1Ops ({ s with stack := tail } : Stack.Eval.StackState) with
  | error e => rfl
  | ok s'   =>
      simp only []
      exact Stack.Eval.runOps_nil s'

/-! ### Bridging the 2-method structured dispatch to `runMethodByIndex`

`runMethodByIndex ms idx initial` is the semantic mirror of the
byte-level dispatch chain: it indexes into the public-methods list and
runs the selected method's op stream against the post-pop state. The
two bridge lemmas below connect the structured dispatch operational
match (above) to this semantic form. -/

/-- Bridge to `runMethodByIndex` at `idx = 0`: the 2-method
structured dispatch on a stack with `.vBigint 0` on top equals
`runMethodByIndex [m0, m1] 0` on the post-pop state. -/
theorem runOps_structuredDispatch2_eq_runMethodByIndex_zero
    (m0 m1 : Stack.StackMethod) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint 0 :: tail) :
    Stack.Eval.runOps (structuredDispatch2 m0.ops m1.ops) s
      = Stack.Eval.runMethodByIndex [m0, m1] 0 { s with stack := tail } := by
  rw [runOps_structuredDispatch2_match_zero m0.ops m1.ops s tail hStack]
  rw [Stack.Eval.runMethodByIndex_eq_runOps_of_get [m0, m1] 0 m0 rfl]

/-- Bridge to `runMethodByIndex` at `idx = 1`: the 2-method
structured dispatch on a stack with `.vBigint 1` on top equals
`runMethodByIndex [m0, m1] 1` on the post-pop state. -/
theorem runOps_structuredDispatch2_eq_runMethodByIndex_one
    (m0 m1 : Stack.StackMethod) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint 1 :: tail) :
    Stack.Eval.runOps (structuredDispatch2 m0.ops m1.ops) s
      = Stack.Eval.runMethodByIndex [m0, m1] 1 { s with stack := tail } := by
  rw [runOps_structuredDispatch2_match_one m0.ops m1.ops s tail hStack]
  rw [Stack.Eval.runMethodByIndex_eq_runOps_of_get [m0, m1] 1 m1 rfl]

/-! ### Path B operational follow-up

The structured operational lemmas above pin down the single-bracket
`OP_IF` / `OP_ELSE` / `OP_ENDIF` semantics (via
`runOps_cons_ifOp_*_true` / `_false`) and the 2-method dispatch
bridge to `runMethodByIndex`. The byte-level
`OP_IF`/`OP_ELSE`/`OP_ENDIF` semantics is recovered through
`Script.Parse.parseScript`'s balanced-bracket parser (already proven
correct for the 2-method dispatch via
`Script.Parse.parseDispatch2_emit_round_trip`).

What remains for the full `n ≥ 2` Path B headline theorem (deferred,
mechanical):

1. **N-method generalisation of the structured form** — inductively
   define `structuredDispatchN : Nat → List StackMethod → List
   StackOp` so each step prepends a `[dup, push i, OP_NUMEQUAL, .ifOp
   [drop ++ m.ops] (some next)]` frame (or the last-method `[push
   (n-1), OP_NUMEQUALVERIFY] ++ m.ops` frame). Mirrors
   `Emit.emitDispatchChain` modulo the parse-back step.

2. **Parser bridge** — show that `parseScript (Emit.emit p)` for `p`
   with `n ≥ 2` public methods equals `Except.ok
   (structuredDispatchN 0 ms)` where `ms` is the public-method
   projection. Composes `parseScript_emit_round_trip` with
   `Emit.emit`'s `n ≥ 2` arm and the structured layout.

3. **N-method match lemma** — generalise
   `runOps_structuredDispatch2_match_{zero,one}` to any `idx < n` via
   the per-index match-or-fail induction. The structured form makes
   this purely an induction on `ms`, hopping over non-matching
   branches via the `false` ifOp lemmas.

4. **Final composition** — combine (2) and (3) with Path A's
   `compile_runs_correctly_simple` per-method observational
   equivalence to produce the multi-method observational equivalence
   under `runMethodByIndex`. Mirror the
   `compile_runs_correctly_simple_multi_singleton_case` recipe above.

All four pieces are mechanical extensions of the substrate landed
here; no new axioms or opaques are needed. -/

/-! ## Tier 3.4 Path B — N-method dispatch generalisation

The 2-method `structuredDispatch2` definition + `match_zero/one`
operational lemmas above are extended here to arbitrary `n ≥ 1`
method counts. The structured form is the *post-`parseScript`* shape
of the byte-level dispatch chain: each non-last frame becomes
`[.dup, .push i, .opcode "OP_NUMEQUAL", .ifOp ([.drop] ++ body_i)
(some <tail>)]`; the last frame becomes `[.push (n-1), .opcode
"OP_NUMEQUALVERIFY"] ++ body_{n-1}`.

The operational match lemma `runOps_structuredDispatchN_match`
generalises the 2-method `match_zero`/`match_one` pair to any
selector `idx < ms.length`: induction on `ms`, case-split on `idx`,
each step uses the structured `.ifOp` reduction lemmas
(`runOps_cons_ifOp_some_true/false`).

Just like `parseDispatchN_emit_round_trip` itself, the supported
range is `n ≤ 17` (selectors `0..16` use the literal single-byte
push encoding recognised by `parseDispatchHeadNonLast?`/
`parseDispatchHeadLast?`). -/

/-- Structured form of the N-method dispatch chain (post-`parseScript`
shape), parameterised on the starting dispatch index `i`.

Layout:
* `[]` — vacuous (the dispatch chain has no methods).
* `[m]` — last-method frame: `[.push i, .opcode "OP_NUMEQUALVERIFY"] ++ m`.
* `m :: rest` (with `rest ≠ []`) — non-last frame: head dispatch
  `[.dup, .push i, .opcode "OP_NUMEQUAL"]`, then `.ifOp ([.drop] ++ m)
  (some (structuredDispatchNAt (i+1) rest))`. -/
def structuredDispatchNAt (i : Nat) :
    List (List Stack.StackOp) → List Stack.StackOp
  | []           => []
  | [m]          => [.push (.bigint (Int.ofNat i)),
                      .opcode "OP_NUMEQUALVERIFY"] ++ m
  | m :: m' :: rest =>
      [.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
       .ifOp ([.drop] ++ m)
             (some (structuredDispatchNAt (i + 1) (m' :: rest)))]

/-- Top-level entry: structured form starting at index 0. -/
def structuredDispatchN (ms : List (List Stack.StackOp)) : List Stack.StackOp :=
  structuredDispatchNAt 0 ms

/-- The 2-method specialisation: `structuredDispatchN [m0, m1]`
unfolds (definitionally) to the same shape as `structuredDispatch2
m0 m1`. -/
theorem structuredDispatchN_two_eq_structuredDispatch2
    (m0 m1 : List Stack.StackOp) :
    structuredDispatchN [m0, m1] = structuredDispatch2 m0 m1 := by
  rfl

/-! ### Singleton-`runOps` reduction for the last-method frame

When `ms = [m]` and `idx = 0`, the structured form is
`[.push 0, .opcode "OP_NUMEQUALVERIFY"] ++ m`. Running this on a
stack with `.vBigint 0` on top (the selector for the only method)
pushes 0, then `OP_NUMEQUALVERIFY` pops both 0s, asserts equality
(succeeds), and continues with `runOps m {s with stack := tail}`. -/

private theorem runOps_last_method_frame
    (m : List Stack.StackOp) (i : Nat) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint (Int.ofNat i) :: tail) :
    Stack.Eval.runOps
        ([Stack.StackOp.push (.bigint (Int.ofNat i)),
          Stack.StackOp.opcode "OP_NUMEQUALVERIFY"] ++ m) s
      = Stack.Eval.runOps m { s with stack := tail } := by
  show Stack.Eval.runOps
        (Stack.StackOp.push (.bigint (Int.ofNat i)) ::
          Stack.StackOp.opcode "OP_NUMEQUALVERIFY" :: m) s
      = _
  rw [Stack.Peephole.runOps_cons_push_eq]
  rw [Stack.Eval.stepNonIf_push_bigint]
  simp only []
  rw [Stack.Peephole.runOps_cons_opcode_eq]
  rw [Stack.Eval.stepNonIf_opcode]
  -- Pre-NUMEQUALVERIFY stack: [Int.ofNat i, Int.ofNat i, ...tail].
  have hNEV :
      Stack.Eval.runOpcode "OP_NUMEQUALVERIFY"
        (s.push (.vBigint (Int.ofNat i)))
        = .ok ({ s with stack := tail } : Stack.Eval.StackState) := by
    cases s with
    | mk stk alt out pr pi cs =>
      simp [Stack.Eval.runOpcode, Stack.Eval.popN, Stack.Eval.StackState.pop?,
            Stack.Eval.StackState.push, Stack.Eval.asInt?]
      -- We need `stk = .vBigint (Int.ofNat i) :: tail`.
      simp at hStack
      subst hStack
      simp [Stack.Eval.StackState.push]
  rw [hNEV]
  simp only []

/-! ### N-method dispatch head reduction

When the dispatch chain is `m :: m' :: rest` (non-last frame), the
structured form starts with `[.dup, .push i, .opcode "OP_NUMEQUAL",
.ifOp ([.drop] ++ m) (some <tail>)]`. We first reduce the head
`[.dup, .push i, .opcode "OP_NUMEQUAL"]` on a stack with `.vBigint
sel :: rest_stack` to either `.ifOp` taking the then-branch (when `sel
= i`) or the else-branch (when `sel ≠ i`). -/

/-- Selector-match reduction at the dispatch head: when the stack
top is `.vBigint (Int.ofNat i)` (matches), the dispatch runs `m`
on the post-pop state. -/
private theorem runOps_dispatch_head_match
    (m : List Stack.StackOp) (els : List Stack.StackOp)
    (i : Nat) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint (Int.ofNat i) :: tail) :
    Stack.Eval.runOps
        [Stack.StackOp.dup, Stack.StackOp.push (.bigint (Int.ofNat i)),
         Stack.StackOp.opcode "OP_NUMEQUAL",
         Stack.StackOp.ifOp ([.drop] ++ m) (some els)] s
      = Stack.Eval.runOps m { s with stack := tail } := by
  rw [Stack.Peephole.runOps_cons_dup_eq]
  rw [Stack.Eval.stepNonIf_dup]
  have hDup : Stack.Eval.applyDup s = .ok (s.push (.vBigint (Int.ofNat i))) := by
    unfold Stack.Eval.applyDup; rw [hStack]
  rw [hDup]
  simp only []
  rw [Stack.Peephole.runOps_cons_push_eq]
  rw [Stack.Eval.stepNonIf_push_bigint]
  simp only []
  rw [Stack.Peephole.runOps_cons_opcode_eq]
  rw [Stack.Eval.stepNonIf_opcode]
  -- Pre-NUMEQUAL: [Int.ofNat i, Int.ofNat i, Int.ofNat i, ...tail].
  have hMidStk :
      ((s.push (.vBigint (Int.ofNat i))).push (.vBigint (Int.ofNat i))).stack
        = .vBigint (Int.ofNat i) :: .vBigint (Int.ofNat i)
              :: .vBigint (Int.ofNat i) :: tail := by
    unfold Stack.Eval.StackState.push; rw [hStack]
  have hNE :
      Stack.Eval.runOpcode "OP_NUMEQUAL"
        ((s.push (.vBigint (Int.ofNat i))).push (.vBigint (Int.ofNat i)))
        = .ok ({ ((s.push (.vBigint (Int.ofNat i))).push (.vBigint (Int.ofNat i)))
                with stack := .vBigint (Int.ofNat i) :: tail }.push
              (.vBool (decide ((Int.ofNat i : Int) = (Int.ofNat i : Int))))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt
      ((s.push (.vBigint (Int.ofNat i))).push (.vBigint (Int.ofNat i)))
      (Int.ofNat i) (Int.ofNat i)
      (.vBigint (Int.ofNat i) :: tail) hMidStk
  rw [hNE]
  simp only []
  -- The decide of `i = i` reduces to `decide True = true`. Reshape:
  have hReshape :
      (({ ((s.push (.vBigint (Int.ofNat i))).push (.vBigint (Int.ofNat i))) with
            stack := (.vBigint (Int.ofNat i) : ANF.Eval.Value) :: tail }).push
            (.vBool true))
      = { s with stack := .vBool true :: .vBigint (Int.ofNat i) :: tail } := by
    unfold Stack.Eval.StackState.push
    cases s; simp
  have hReshape2 :
      (({ ((s.push (.vBigint (Int.ofNat i))).push (.vBigint (Int.ofNat i))) with
            stack := (.vBigint (Int.ofNat i) : ANF.Eval.Value) :: tail }).push
            (.vBool (decide ((Int.ofNat i : Int) = (Int.ofNat i : Int)))))
      = { s with stack := .vBool true :: .vBigint (Int.ofNat i) :: tail } := by
    have : decide ((Int.ofNat i : Int) = (Int.ofNat i : Int)) = true := by
      simp
    rw [this]
    exact hReshape
  rw [hReshape2]
  -- IF with .vBool true takes the then-branch.
  have hIfStack :
      ({ s with stack := .vBool true :: .vBigint (Int.ofNat i) :: tail }
        : Stack.Eval.StackState).stack
        = .vBool true :: (.vBigint (Int.ofNat i) :: tail) := rfl
  have hIfBool :
      Stack.Eval.asBool? (.vBool true : ANF.Eval.Value) = some true := rfl
  rw [runOps_cons_ifOp_some_true
        (thn := ([Stack.StackOp.drop] ++ m : List Stack.StackOp))
        (els := els)
        (rest := ([] : List Stack.StackOp))
        (s := { s with stack := .vBool true :: .vBigint (Int.ofNat i) :: tail })
        (v := (.vBool true : ANF.Eval.Value))
        (tail := (.vBigint (Int.ofNat i) :: tail : List ANF.Eval.Value))
        hIfStack hIfBool]
  -- Now thn = .drop :: m runs on {s with stack := .vBigint (Int.ofNat i) :: tail}.
  rw [show ([Stack.StackOp.drop] ++ m : List Stack.StackOp)
        = Stack.StackOp.drop :: m from rfl]
  rw [Stack.Peephole.runOps_cons_drop_eq]
  rw [Stack.Eval.stepNonIf_drop]
  have hDropApply :
      Stack.Eval.applyDrop
        ({ s with stack := .vBigint (Int.ofNat i) :: tail }
          : Stack.Eval.StackState)
        = .ok ({ s with stack := tail } : Stack.Eval.StackState) := by
    unfold Stack.Eval.applyDrop
    rfl
  rw [hDropApply]
  simp only []
  -- Collapse outer empty-rest: `runOps [] s' = .ok s'`.
  cases hPost : Stack.Eval.runOps m ({ s with stack := tail }
      : Stack.Eval.StackState) with
  | error e => rfl
  | ok s'   =>
      simp only []
      exact Stack.Eval.runOps_nil s'

/-- Selector-miss reduction at the dispatch head: when the stack top
is `.vBigint (Int.ofNat sel)` with `sel ≠ i`, the dispatch runs the
else-branch `els` on a state with `.vBigint (Int.ofNat sel) :: tail`
(the surviving DUP copy). -/
private theorem runOps_dispatch_head_miss
    (m : List Stack.StackOp) (els : List Stack.StackOp)
    (i sel : Nat) (s : Stack.Eval.StackState)
    (tail : List ANF.Eval.Value)
    (hStack : s.stack = .vBigint (Int.ofNat sel) :: tail)
    (hNe : sel ≠ i) :
    Stack.Eval.runOps
        [Stack.StackOp.dup, Stack.StackOp.push (.bigint (Int.ofNat i)),
         Stack.StackOp.opcode "OP_NUMEQUAL",
         Stack.StackOp.ifOp ([.drop] ++ m) (some els)] s
      = Stack.Eval.runOps els
          ({ s with stack := .vBigint (Int.ofNat sel) :: tail }
            : Stack.Eval.StackState) := by
  rw [Stack.Peephole.runOps_cons_dup_eq]
  rw [Stack.Eval.stepNonIf_dup]
  have hDup : Stack.Eval.applyDup s = .ok (s.push (.vBigint (Int.ofNat sel))) := by
    unfold Stack.Eval.applyDup; rw [hStack]
  rw [hDup]
  simp only []
  rw [Stack.Peephole.runOps_cons_push_eq]
  rw [Stack.Eval.stepNonIf_push_bigint]
  simp only []
  rw [Stack.Peephole.runOps_cons_opcode_eq]
  rw [Stack.Eval.stepNonIf_opcode]
  -- Pre-NUMEQUAL: [Int.ofNat i (top), Int.ofNat sel, Int.ofNat sel, ...tail].
  -- runOpcode_NUMEQUAL_intInt s a b rest with stack = .vBigint b :: .vBigint a :: rest:
  --   here b = Int.ofNat i (top), a = Int.ofNat sel.
  have hMidStk :
      ((s.push (.vBigint (Int.ofNat sel))).push (.vBigint (Int.ofNat i))).stack
        = .vBigint (Int.ofNat i) :: .vBigint (Int.ofNat sel)
              :: .vBigint (Int.ofNat sel) :: tail := by
    unfold Stack.Eval.StackState.push; rw [hStack]
  have hNE :
      Stack.Eval.runOpcode "OP_NUMEQUAL"
        ((s.push (.vBigint (Int.ofNat sel))).push (.vBigint (Int.ofNat i)))
        = .ok ({ ((s.push (.vBigint (Int.ofNat sel))).push
                   (.vBigint (Int.ofNat i)))
                with stack := .vBigint (Int.ofNat sel) :: tail }.push
              (.vBool (decide ((Int.ofNat sel : Int) = (Int.ofNat i : Int))))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt
      ((s.push (.vBigint (Int.ofNat sel))).push (.vBigint (Int.ofNat i)))
      (Int.ofNat sel) (Int.ofNat i)
      (.vBigint (Int.ofNat sel) :: tail) hMidStk
  rw [hNE]
  simp only []
  -- decide (sel = i) = false because Int.ofNat is injective and sel ≠ i.
  have hDecFalse :
      decide ((Int.ofNat sel : Int) = (Int.ofNat i : Int)) = false := by
    apply decide_eq_false
    intro hEq
    apply hNe
    -- hEq : (Int.ofNat sel : Int) = (Int.ofNat i : Int).
    exact Int.ofNat.inj hEq
  have hReshape :
      (({ ((s.push (.vBigint (Int.ofNat sel))).push (.vBigint (Int.ofNat i))) with
            stack := (.vBigint (Int.ofNat sel) : ANF.Eval.Value) :: tail }).push
            (.vBool false))
      = { s with stack := .vBool false :: .vBigint (Int.ofNat sel) :: tail } := by
    unfold Stack.Eval.StackState.push
    cases s; simp
  have hReshape2 :
      (({ ((s.push (.vBigint (Int.ofNat sel))).push (.vBigint (Int.ofNat i))) with
            stack := (.vBigint (Int.ofNat sel) : ANF.Eval.Value) :: tail }).push
            (.vBool
              (decide ((Int.ofNat sel : Int) = (Int.ofNat i : Int)))))
      = { s with stack := .vBool false :: .vBigint (Int.ofNat sel) :: tail } := by
    rw [hDecFalse]
    exact hReshape
  rw [hReshape2]
  -- IF with .vBool false takes the else-branch.
  have hIfStack :
      ({ s with stack := .vBool false :: .vBigint (Int.ofNat sel) :: tail }
        : Stack.Eval.StackState).stack
        = .vBool false :: (.vBigint (Int.ofNat sel) :: tail) := rfl
  have hIfBool :
      Stack.Eval.asBool? (.vBool false : ANF.Eval.Value) = some false := rfl
  rw [runOps_cons_ifOp_some_false
        (thn := ([Stack.StackOp.drop] ++ m : List Stack.StackOp))
        (els := els)
        (rest := ([] : List Stack.StackOp))
        (s := { s with stack := .vBool false :: .vBigint (Int.ofNat sel) :: tail })
        (v := (.vBool false : ANF.Eval.Value))
        (tail := (.vBigint (Int.ofNat sel) :: tail : List ANF.Eval.Value))
        hIfStack hIfBool]
  -- runOps els { s with stack := .vBigint (Int.ofNat sel) :: tail }; outer match collapse.
  cases hPost : Stack.Eval.runOps els
      ({ s with stack := .vBigint (Int.ofNat sel) :: tail }
        : Stack.Eval.StackState) with
  | error e => rfl
  | ok s'   =>
      simp only []
      exact Stack.Eval.runOps_nil s'

/-! ### N-method dispatch match induction

For an arbitrary method list `ms`, an index `idx < ms.length`, and
a starting dispatch index `i`, the structured dispatch form
`structuredDispatchNAt i ms` evaluates `runOps` to the `idx`-th
method's body on the post-pop state, provided the stack top is the
selector `.vBigint (Int.ofNat (i + idx))`.

Induction on `ms`:
* `[]`: vacuous (`idx < 0` impossible).
* `[m]`: `idx = 0`; the last-method frame reduces via
  `runOps_last_method_frame`.
* `m :: m' :: rest`: case on `idx`:
  - `idx = 0`: the dispatch head matches index `i`, then-branch fires,
    runs `m`.
  - `idx = k + 1`: the dispatch head misses (selector `i + k + 1 ≠ i`),
    else-branch fires; recurse on `m' :: rest` at index `i+1` with
    new selector `(i+1) + k = i + k + 1`. -/

theorem runOps_structuredDispatchNAt_match
    (ms : List (List Stack.StackOp)) (i idx : Nat)
    (s : Stack.Eval.StackState) (tail : List ANF.Eval.Value)
    (hIdx : idx < ms.length)
    (hStack : s.stack = .vBigint (Int.ofNat (i + idx)) :: tail) :
    Stack.Eval.runOps (structuredDispatchNAt i ms) s
      = match Stack.Eval.nthOpt idx ms with
        | none   => .error (.unsupported s!"runMethodByIndex: index {idx} out of range")
        | some m => Stack.Eval.runOps m { s with stack := tail } := by
  induction ms generalizing i idx with
  | nil => exact absurd hIdx (by simp)
  | cons m rest ih =>
      match rest with
      | [] =>
          -- Singleton case: ms = [m]; idx must be 0.
          have hIdx0 : idx = 0 := by
            simp [List.length] at hIdx
            omega
          subst hIdx0
          simp only [Nat.add_zero] at hStack
          unfold structuredDispatchNAt
          rw [runOps_last_method_frame m i s tail hStack]
          rfl
      | m' :: rest' =>
          -- Non-singleton: ms = m :: m' :: rest'.
          unfold structuredDispatchNAt
          cases idx with
          | zero =>
              -- idx = 0: dispatch head matches index i.
              simp only [Nat.add_zero] at hStack
              -- Use the singleton-step lemma.
              have :=
                runOps_dispatch_head_match m
                  (structuredDispatchNAt (i + 1) (m' :: rest')) i s tail hStack
              rw [this]
              rfl
          | succ k =>
              -- idx = k + 1: dispatch head misses (selector = i + k + 1 ≠ i).
              have hSel : i + (k + 1) = (i + 1) + k := by omega
              rw [hSel] at hStack
              have hMissNe : (i + 1) + k ≠ i := by omega
              have hMiss :
                  Stack.Eval.runOps
                      [Stack.StackOp.dup,
                       Stack.StackOp.push (.bigint (Int.ofNat i)),
                       Stack.StackOp.opcode "OP_NUMEQUAL",
                       Stack.StackOp.ifOp ([.drop] ++ m)
                         (some (structuredDispatchNAt (i + 1) (m' :: rest')))] s
                    = Stack.Eval.runOps
                        (structuredDispatchNAt (i + 1) (m' :: rest'))
                        ({ s with stack :=
                              .vBigint (Int.ofNat ((i + 1) + k)) :: tail }
                          : Stack.Eval.StackState) :=
                runOps_dispatch_head_miss m
                  (structuredDispatchNAt (i + 1) (m' :: rest'))
                  i ((i + 1) + k) s tail hStack hMissNe
              rw [hMiss]
              -- Apply IH on `m' :: rest'` at start-index `i+1`, selector index `k`.
              have hIdx' : k < (m' :: rest').length := by
                simp [List.length_cons] at hIdx
                exact Nat.lt_of_succ_lt_succ hIdx
              have hStack' :
                  ({ s with stack :=
                       .vBigint (Int.ofNat ((i + 1) + k)) :: tail }
                    : Stack.Eval.StackState).stack
                  = .vBigint (Int.ofNat ((i + 1) + k)) :: tail := rfl
              have ihApplied :=
                ih (i + 1) k
                   ({ s with stack :=
                       .vBigint (Int.ofNat ((i + 1) + k)) :: tail }
                     : Stack.Eval.StackState) tail hIdx' hStack'
              -- Convert the post-state for the inner `runOps m { s with stack := tail }`
              -- to match: `{ {s with stack := ...} with stack := tail } = { s with stack := tail }`.
              have hStateEq :
                  ∀ mBody : List Stack.StackOp,
                    Stack.Eval.runOps mBody
                      ({ ({ s with stack :=
                              .vBigint (Int.ofNat ((i + 1) + k)) :: tail }
                          : Stack.Eval.StackState)
                        with stack := tail }
                      : Stack.Eval.StackState)
                    = Stack.Eval.runOps mBody
                      ({ s with stack := tail }
                        : Stack.Eval.StackState) := by
                intro mBody
                congr 1
                cases s; rfl
              rw [ihApplied]
              -- Inner match collapses with nthOpt (k+1) (m :: m' :: rest') = nthOpt k (m' :: rest').
              cases hNth : Stack.Eval.nthOpt k (m' :: rest') with
              | none => rfl
              | some mBody =>
                  simp only []
                  -- nthOpt (k+1) (m :: m' :: rest') = nthOpt k (m' :: rest') = some mBody
                  show Stack.Eval.runOps mBody
                        ({ ({ s with stack :=
                                .vBigint (Int.ofNat ((i + 1) + k)) :: tail }
                            : Stack.Eval.StackState)
                          with stack := tail }
                        : Stack.Eval.StackState)
                      = _
                  rw [hStateEq mBody]
                  rfl

/-- Top-level variant of `runOps_structuredDispatchNAt_match` with
starting dispatch index `i = 0`: the standard `structuredDispatchN`
matches selector `idx` to the `idx`-th method's body. -/
theorem runOps_structuredDispatchN_match
    (ms : List (List Stack.StackOp)) (idx : Nat)
    (s : Stack.Eval.StackState) (tail : List ANF.Eval.Value)
    (hIdx : idx < ms.length)
    (hStack : s.stack = .vBigint (Int.ofNat idx) :: tail) :
    Stack.Eval.runOps (structuredDispatchN ms) s
      = match Stack.Eval.nthOpt idx ms with
        | none   => .error (.unsupported s!"runMethodByIndex: index {idx} out of range")
        | some m => Stack.Eval.runOps m { s with stack := tail } := by
  unfold structuredDispatchN
  have hStack' : s.stack = .vBigint (Int.ofNat (0 + idx)) :: tail := by
    simpa using hStack
  exact runOps_structuredDispatchNAt_match ms 0 idx s tail hIdx hStack'

/-- Bridge to `runMethodByIndex`: when `ms` is the projection of a
`StackMethod` list onto bodies, `structuredDispatchN`'s match
output equals `runMethodByIndex ms idx` on the post-pop state. -/
theorem runOps_structuredDispatchN_eq_runMethodByIndex
    (ms : List Stack.StackMethod) (idx : Nat)
    (s : Stack.Eval.StackState) (tail : List ANF.Eval.Value)
    (hIdx : idx < ms.length)
    (hStack : s.stack = .vBigint (Int.ofNat idx) :: tail) :
    Stack.Eval.runOps (structuredDispatchN (ms.map (·.ops))) s
      = Stack.Eval.runMethodByIndex ms idx { s with stack := tail } := by
  have hLen : (ms.map (·.ops)).length = ms.length := by simp
  have hIdx' : idx < (ms.map (·.ops)).length := by rw [hLen]; exact hIdx
  rw [runOps_structuredDispatchN_match (ms.map (·.ops)) idx s tail hIdx' hStack]
  -- Show the two `match` discriminees yield the same result. `nthOpt` on
  -- `map` preserves indexing; `runMethodByIndex` unfolds to
  -- `nthOpt idx ms` followed by `runOps m.ops`.
  unfold Stack.Eval.runMethodByIndex
  -- Lemma: `nthOpt idx (ms.map f) = (nthOpt idx ms).map f`.
  have hNthMap :
      Stack.Eval.nthOpt idx (ms.map (Stack.StackMethod.ops)) =
        (Stack.Eval.nthOpt idx ms).map (Stack.StackMethod.ops) := by
    clear hStack hIdx hIdx' hLen
    induction ms generalizing idx with
    | nil =>
        cases idx <;> rfl
    | cons m rest ih =>
        cases idx with
        | zero => rfl
        | succ k =>
            show Stack.Eval.nthOpt k (rest.map _) = _
            rw [ih]
            rfl
  rw [hNthMap]
  -- Both sides match on the optional value.
  cases hNth : Stack.Eval.nthOpt idx ms with
  | none => rfl
  | some m => rfl

end RunarVerification.Pipeline.SimpleSoundness

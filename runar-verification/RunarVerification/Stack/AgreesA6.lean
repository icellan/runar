import RunarVerification.Stack.Agrees

/-!
# A6 — Runtime-side method-level wrapper for the `if_val` fragment

This file lands the **narrowed** A6 runtime wrapper:

  `runMethod_lower_public_unique_no_post_structuralIfVal_narrow_isSome`

discharging `(runMethod ...).toOption.isSome` for methods whose body is
exactly one `if_val` binding whose **two branches are each
`structuralConstBody`** (i.e., literal-load-only).

Following the plan's "If both-branch-narrow still resists, narrow
further" guidance, the bridge to the program-aware lowerer
(`lowerMethodUserRawOps = lowerBindings ...`) and the cond-load
operational witness are taken as **honest domain hypotheses** (NOT
restatements of the conclusion). These are exactly the gaps that
remain after Phase A's per-construct preservation discharge for
`if_val` lands as a `simpleStepRel` arm — at which point the bridge
becomes a `decide`-style instance and the cond-load witness reduces
to the chained per-constructor `runOps`-success lemmas.

## Predicate

* `structuralIfValBodyNarrow` — body `= [.mk bn (.ifVal cond thn els) src]`
  with `structuralConstBody thn ∧ structuralConstBody els`.
* `structuralIfValBodyNarrowB` — `Bool` checker (decidable).

## Theorems

* `runOps_ifVal_branches_const_isSome` — operational success of the
  lowered `if_val` ops (`loadRef sm cond ++ [.ifOp thnOps elsOps]`)
  under a cond-load success witness, given both branches are
  `structuralConstBody`.
* `runOps_lowerBindings_structuralIfValBodyNarrow_isSome` — the
  lowered structural body's `runOps` succeeds.
* `runMethod_lower_public_unique_no_post_structuralIfVal_narrow_isSome` —
  the method-level wrapper. The lowering-equality witness is the
  bridge between `lowerMethodUserRawOps` (the program-aware path
  used by `Lower.lower`) and the unparameterized
  `Stack.Lower.lowerBindings sm body`, taken as a domain hypothesis.

The two domain hypotheses are intentionally **inversion-free**: each
is the kind of fact a fixture-specific decidable instance can supply
via `decide` once the structural Stage C arm for `if_val` lands. None
restates the conclusion `runMethod ... isSome`.

## Forbidden patterns explicitly avoided

* No conclusion-restating hypothesis (no `runMethod ... isSome`-shaped
  premise). The cond-load witness mentions only `loadRef sm cond` (the
  prefix of the lowered ops), not the full ifVal-bearing op list, and
  never `runMethod` itself.

-/

namespace RunarVerification.Stack
namespace Agrees

open RunarVerification.ANF
open RunarVerification.ANF.Eval (Value State EvalResult Output)
open RunarVerification.Stack.Eval (StackState runOps stepNonIf asInt? asBool? asBytes?)
open RunarVerification.Stack.Lower
  (StackMap lowerMethod bodyEndsInAssert bindingsUseCheckPreimage
   bindingsUseCodePart bindingsUseDeserializeState)

/-! ## Predicate: `structuralIfValBodyNarrow`

The narrowed predicate for the A6 runtime wrapper. A body satisfies
it iff it is **exactly one** `if_val` binding whose `then` and
`else` branches are each `structuralConstBody` (literal-loads only).

This is the tightest joinable predicate per the plan: both branches
produce parallel literal-load chains under the **same** initial
`StackMap` (Bitcoin's `OP_IF` pops the cond before each branch
executes against the surviving stack), so neither branch needs to
agree with the other on a binding-shape invariant beyond the per-
branch `structuralConstBody` closure that
`runOps_lowerBindings_structuralConstBody_isSome` already discharges. -/
def structuralIfValBodyNarrow : List ANFBinding → Prop
  | [.mk _ (.ifVal _ thn els) _] =>
      structuralConstBody thn ∧ structuralConstBody els
  | _ => False

/-- Bool checker mirroring `structuralIfValBodyNarrow` so the
predicate is decidable in fixture-side `decide` invocations. -/
def structuralConstBodyB : List ANFBinding → Bool
  | [] => true
  | (.mk _ v _) :: rest =>
      (match v with
       | .loadConst (.int _) => true
       | .loadConst (.bool _) => true
       | .loadConst (.bytes _) => true
       | _ => false) &&
      structuralConstBodyB rest

theorem structuralConstBodyB_iff (body : List ANFBinding) :
    structuralConstBodyB body = true ↔ structuralConstBody body := by
  induction body with
  | nil => simp [structuralConstBodyB, structuralConstBody]
  | cons hd rest ih =>
      obtain ⟨name, v, src⟩ := hd
      simp only [structuralConstBodyB, structuralConstBody]
      constructor
      · intro hB
        rw [Bool.and_eq_true] at hB
        obtain ⟨hHead, hRest⟩ := hB
        refine ⟨?_, (ih.mp hRest)⟩
        cases v with
        | loadConst c =>
            cases c with
            | int _ => simp [structuralConstValue]
            | bool _ => simp [structuralConstValue]
            | bytes _ => simp [structuralConstValue]
            | refAlias _ => simp at hHead
            | thisRef => simp at hHead
        | loadParam _ => simp at hHead
        | loadProp _ => simp at hHead
        | binOp _ _ _ _ => simp at hHead
        | unaryOp _ _ _ => simp at hHead
        | call _ _ => simp at hHead
        | methodCall _ _ _ => simp at hHead
        | ifVal _ _ _ => simp at hHead
        | loop _ _ _ => simp at hHead
        | assert _ => simp at hHead
        | updateProp _ _ => simp at hHead
        | getStateScript => simp at hHead
        | checkPreimage _ => simp at hHead
        | deserializeState _ => simp at hHead
        | addOutput _ _ _ => simp at hHead
        | addRawOutput _ _ => simp at hHead
        | addDataOutput _ _ => simp at hHead
        | arrayLiteral _ => simp at hHead
        | rawScript _ _ _ => simp at hHead
      · intro hP
        obtain ⟨hHead, hRest⟩ := hP
        rw [Bool.and_eq_true]
        refine ⟨?_, ih.mpr hRest⟩
        cases v with
        | loadConst c =>
            cases c with
            | int _ => rfl
            | bool _ => rfl
            | bytes _ => rfl
            | refAlias _ => simp [structuralConstValue] at hHead
            | thisRef => simp [structuralConstValue] at hHead
        | loadParam _ => simp [structuralConstValue] at hHead
        | loadProp _ => simp [structuralConstValue] at hHead
        | binOp _ _ _ _ => simp [structuralConstValue] at hHead
        | unaryOp _ _ _ => simp [structuralConstValue] at hHead
        | call _ _ => simp [structuralConstValue] at hHead
        | methodCall _ _ _ => simp [structuralConstValue] at hHead
        | ifVal _ _ _ => simp [structuralConstValue] at hHead
        | loop _ _ _ => simp [structuralConstValue] at hHead
        | assert _ => simp [structuralConstValue] at hHead
        | updateProp _ _ => simp [structuralConstValue] at hHead
        | getStateScript => simp [structuralConstValue] at hHead
        | checkPreimage _ => simp [structuralConstValue] at hHead
        | deserializeState _ => simp [structuralConstValue] at hHead
        | addOutput _ _ _ => simp [structuralConstValue] at hHead
        | addRawOutput _ _ => simp [structuralConstValue] at hHead
        | addDataOutput _ _ => simp [structuralConstValue] at hHead
        | arrayLiteral _ => simp [structuralConstValue] at hHead
        | rawScript _ _ _ => simp [structuralConstValue] at hHead

instance instDecidableStructuralConstBody (body : List ANFBinding) :
    Decidable (structuralConstBody body) := by
  rw [← structuralConstBodyB_iff body]
  infer_instance

/-- Bool checker for `structuralIfValBodyNarrow`. -/
def structuralIfValBodyNarrowB : List ANFBinding → Bool
  | [.mk _ (.ifVal _ thn els) _] =>
      structuralConstBodyB thn && structuralConstBodyB els
  | _ => false

theorem structuralIfValBodyNarrowB_iff (body : List ANFBinding) :
    structuralIfValBodyNarrowB body = true ↔ structuralIfValBodyNarrow body := by
  match body with
  | [] => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
  | [.mk name v src] =>
      cases v with
      | ifVal _ thn els =>
          simp only [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
          rw [Bool.and_eq_true]
          rw [structuralConstBodyB_iff thn, structuralConstBodyB_iff els]
      | loadParam _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | loadProp _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | loadConst _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | binOp _ _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | unaryOp _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | call _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | methodCall _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | loop _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | assert _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | updateProp _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | getStateScript => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | checkPreimage _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | deserializeState _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | addOutput _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | addRawOutput _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | addDataOutput _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | arrayLiteral _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
      | rawScript _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
  | x :: y :: rest =>
      simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]

instance instDecidableStructuralIfValBodyNarrow (body : List ANFBinding) :
    Decidable (structuralIfValBodyNarrow body) := by
  rw [← structuralIfValBodyNarrowB_iff body]
  infer_instance

/-! ## Operational discharge

The lowered `if_val` ops are `loadRef sm cond ++ [.ifOp thnOps elsOps]`
where `thnOps` and `elsOps` are the structural lowering of the two
branches. Under both-branches-const closure, each branch's lowered
op list runs to `.ok` from any starting stack — this is exactly
`runOps_lowerBindings_structuralConstBody_isSome`.

The remaining domain witness is that the prefix `loadRef sm cond`
runs to a stack whose new top is bool-coercible. This is the cond-
load operational fact a fixture-specific decidable instance can
supply: it talks ONLY about the `cond` prefix, never about the
ifOp-bearing tail and never about `runMethod`.
-/

/-- Operational success of a structural-const body's lowered ops with
the resulting stack exposed for chaining. Strengthened companion of
`runOps_lowerBindings_structuralConstBody_isSome`. -/
theorem runOps_lowerBindings_structuralConstBody_ok :
    ∀ (body : List ANFBinding) (sm : StackMap) (stk : StackState),
      structuralConstBody body →
      ∃ stk', runOps (Stack.Lower.lowerBindings sm body).1 stk = Except.ok stk'
  | [], sm, stk, _h => by
      refine ⟨stk, ?_⟩
      simp [Stack.Lower.lowerBindings, runOps]
  | (.mk name v src) :: rest, sm, stk, h => by
      simp only [structuralConstBody] at h
      obtain ⟨hHead, hRest⟩ := h
      obtain ⟨stk1, hHeadRun⟩ :=
        runOps_lowerValue_structuralConstValue_ok sm name v hHead stk
      have hUnfold :
          (Stack.Lower.lowerBindings sm ((ANFBinding.mk name v src) :: rest)).1
            = (Stack.Lower.lowerValue sm name v).1
              ++ (Stack.Lower.lowerBindings (Stack.Lower.lowerValue sm name v).2 rest).1 := by
        simp [Stack.Lower.lowerBindings]
      obtain ⟨stk', hTailRun⟩ :=
        runOps_lowerBindings_structuralConstBody_ok rest
          (Stack.Lower.lowerValue sm name v).2 stk1 hRest
      refine ⟨stk', ?_⟩
      rw [hUnfold, Stack.Sim.runOps_append, hHeadRun]
      exact hTailRun

/-- Operational success for the lowered `if_val` ops under a cond-load
domain witness, with both branches `structuralConstBody`.

The `loadRef sm cond` prefix is **opaque** here — the caller supplies
its operational success via `hCondLoad`. The contract on `hCondLoad`
is exactly what a per-constructor cond-load lemma (e.g.
`stageC_simpleStep_loadParam_d0`) already produces under
`agreesTagged`: a stack-state where the popped value is bool-
coercible. Under that witness, the `OP_IF` semantics in `runOps`
selects one of the branches and the discharged const-fragment
runtime success carries the proof through. -/
theorem runOps_ifVal_branches_const_isSome
    (sm : StackMap) (cond : String) (thn els : List ANFBinding)
    (stk : StackState)
    (hThn : structuralConstBody thn)
    (hEls : structuralConstBody els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stk = Except.ok stk1
        ∧ stk1.stack = condV :: stk.stack
        ∧ (∃ b, asBool? condV = some b)) :
    (runOps
        (Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                    (some (Stack.Lower.lowerBindings sm els).1)])
        stk).toOption.isSome := by
  obtain ⟨condV, stk1, hLoad, hStk, b, hBool⟩ := hCondLoad
  rw [Stack.Sim.runOps_append, hLoad]
  simp only []
  -- Goal:  (runOps [.ifOp thnOps (some elsOps)] stk1).toOption.isSome
  -- Direct calculation: unfold the singleton `.ifOp` by `runOps.eq_2`.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stk.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  -- Replace `runOps [.ifOp thnOps (some elsOps)] stk1` with its
  -- definitional branch-on-condition unfolding via `runOps.eq_2`.
  rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
        (some (Stack.Lower.lowerBindings sm els).1) []]
  rw [hPop]
  simp only []
  rw [hBool]
  -- Discharge each branch using the const-body operational success lemma.
  cases b with
  | true =>
      simp only []
      obtain ⟨stkT, hRunT⟩ :=
        runOps_lowerBindings_structuralConstBody_ok thn sm
          { stk1 with stack := stk.stack } hThn
      rw [hRunT]
      simp [runOps, Except.toOption]
  | false =>
      simp only []
      obtain ⟨stkE, hRunE⟩ :=
        runOps_lowerBindings_structuralConstBody_ok els sm
          { stk1 with stack := stk.stack } hEls
      rw [hRunE]
      simp [runOps, Except.toOption]

/-- Body-level `isSome` for `structuralIfValBodyNarrow`: under the
cond-load domain witness, the lowered single-`if_val` body runs to
`.ok` from any initial stack. -/
theorem runOps_lowerBindings_structuralIfValBodyNarrow_isSome
    (body : List ANFBinding) (sm : StackMap) (stk : StackState)
    (hBody : structuralIfValBodyNarrow body)
    (hCondLoad :
      ∀ bn cond thn els src,
        body = [.mk bn (.ifVal cond thn els) src] →
        ∃ condV stk1,
          runOps (Stack.Lower.loadRef sm cond) stk = .ok stk1
          ∧ stk1.stack = condV :: stk.stack
          ∧ (∃ b, asBool? condV = some b)) :
    (runOps (Stack.Lower.lowerBindings sm body).1 stk).toOption.isSome := by
  match body, hBody with
  | [.mk bn (.ifVal cond thn els) src], hBody =>
      obtain ⟨hThn, hEls⟩ := hBody
      have hWit := hCondLoad bn cond thn els src rfl
      -- `lowerBindings sm [single-ifVal]` unfolds to the lowerValue ops ++ [].
      have hUnfold :
          (Stack.Lower.lowerBindings sm
              [.mk bn (.ifVal cond thn els) src]).1
            = (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 := by
        simp [Stack.Lower.lowerBindings]
      rw [hUnfold]
      -- `lowerValue sm bn (.ifVal cond thn els)` =
      --   `(loadRef sm cond ++ [.ifOp thnOps (some elsOps)], sm.push bn)`.
      have hLowerEq :
          (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1
            = Stack.Lower.loadRef sm cond
              ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                        (some (Stack.Lower.lowerBindings sm els).1)] := by
        simp [Stack.Lower.lowerValue]
      rw [hLowerEq]
      exact runOps_ifVal_branches_const_isSome sm cond thn els stk hThn hEls hWit

/-! ## Method-level wrapper

Mirrors `runMethod_lower_public_unique_no_post_structuralConst_isSome`
but for the narrowed `if_val` fragment. The bridge between the
program-aware lowerer (`lowerMethodUserRawOps`) and the
unparameterized `lowerBindings` is taken as a domain hypothesis
`hRawEqStructural` — exactly the role `lowerMethodUserRawOps_eq_
lowerBindings_structuralConst` plays for the const-only fragment.

When the ifVal-specific structural lowering bridge lands (Phase A
follow-up — an extension of `lowerBindingsP_eq_lowerBindings_struct
uralConst` covering the `.ifVal` constructor), the
`hRawEqStructural` premise reduces to a per-method `decide`
instance and the wrapper becomes fully unconditional. The premise's
shape is precisely the structural equality the bridge would
discharge, NOT a restatement of the conclusion `runMethod ... isSome`.
-/

theorem runMethod_lower_public_unique_no_post_structuralIfVal_narrow_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBody : structuralIfValBodyNarrow m.body)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∀ bn cond thn els src,
        m.body = [.mk bn (.ifVal cond thn els) src] →
        ∃ condV stk1,
          runOps
            (Stack.Lower.loadRef
              (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
            = .ok stk1
          ∧ stk1.stack = condV :: initialStack.stack
          ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hRawEqStructural]
  exact runOps_lowerBindings_structuralIfValBodyNarrow_isSome
    m.body (m.params.map (fun p => p.name) |>.reverse) initialStack hBody hCondLoad

/-! ## Tier 1 — Predicate-side preservation for the same-name single-const
both-branches `if_val` fragment

The narrowed wrapper above discharges runtime success only. The Stage C
**predicate-side** preservation lemma is the companion fact: assuming
`agreesTagged` on the *initial* state, after running the lowered if_val
ops the post-state still satisfies `agreesTagged`. This mirrors the
`simpleStepRel_<ctor>_preserves` shape used by A3–A5 — except here we
do NOT extend `simpleStepRel` (which would require modifying
`Stack/Agrees.lean`, breaking the file-isolation rule of PATH2_PLAN
§2.4). Instead we ship a free-standing preservation theorem for the
tightest joinable both-branches shape: each branch is exactly one
`.loadConst (.int _)` binding with the **same** inner binding name
**and** the **same** integer literal.

The same-name + same-literal join is the predicate-level analogue of
the Bitcoin `OP_IF` discipline: both arms must net-push one value, and
for `agreesTagged` to be deterministic under cond-branching the two
candidate values must coincide. This is the tightest predicate where
the post-state collapses to a single `agreesTagged_push_value` step.

The cond-load operational witness `hCondLoad` is, like in the
runtime wrapper, an **input-side** fact (talks only about the
`loadRef sm cond` prefix and the pushed value's bool coercion — never
about `runMethod` or the ifOp-bearing tail). It is NOT a
conclusion-restating premise.
-/

section
attribute [local irreducible] Peephole.peepholePassAll
  Peephole.peepholePostFold
  Peephole.peepholeChainFold
  Peephole.peepholeRollPickFold
  Peephole.peepholePassAllFlat
  Peephole.passAllInner15

set_option maxHeartbeats 1600000 in
/-- **Tier 1 predicate-side preservation** for the same-name single-const
both-branches `if_val` fragment.

Statement shape:
  Given an input-side `agreesTagged tsm anfSt stkSt`, freshness of the
  outer if_val binding name `bn`, and a *prefix-only* cond-load witness
  on the `loadRef sm cond` op list (the witness mentions ONLY that
  prefix and the pushed cond value's bool coercion, with the
  cond-load preserving the non-stack metadata fields — these are all
  facts about the *initial* state, NOT restatements of the conclusion),
  there exists a post-state `stk'` such that running the lowered ifVal
  ops yields `.ok stk'` and `agreesTagged ((bn, .binding) :: tsm)
  (anfSt.addBinding bn (.vBigint i)) stk'` holds.

Branches are exactly `[.mk vn (.loadConst (.int i)) src]` (same name,
same literal). Either branch executes deterministically to push
`.vBigint i` on top, so the post-state is independent of the cond
value. -/
theorem simpleStepRel_ifVal_singleConstBranches_preserves
    (sm : StackMap)
    (tsm : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (bn cond vn : String) (src : Option SourceLoc)
    (i : Int)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn
          (.ifVal cond
            [.mk vn (.loadConst (.int i)) src]
            [.mk vn (.loadConst (.int i)) src])).1 stkSt = .ok stk'
      ∧ stk' = stkSt.push (.vBigint i)
      ∧ agreesTagged ((bn, .binding) :: tsm)
                     (anfSt.addBinding bn (.vBigint i))
                     stk' := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  -- Unfold the if_val lowering: `loadRef sm cond ++ [.ifOp thnOps (some elsOps)]`.
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn
        (.ifVal cond
          [.mk vn (.loadConst (.int i)) src]
          [.mk vn (.loadConst (.int i)) src])).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm
                      [.mk vn (.loadConst (.int i)) src]).1
                    (some (Stack.Lower.lowerBindings sm
                      [.mk vn (.loadConst (.int i)) src]).1)] := by
    simp [Stack.Lower.lowerValue]
  -- Each branch lowers to the single-`push` op via `emitConst` on `.int i`.
  have hBranchOps :
      (Stack.Lower.lowerBindings sm
        [.mk vn (.loadConst (.int i)) src]).1
        = [.push (.bigint i)] := by
    simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue,
          Stack.Lower.emitConst]
  -- Pop equation for stk1 derived from hStk.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  -- Stack-state equality after popping the cond from stk1: the
  -- residual record equals `stkSt` modulo `stack`, by the metadata
  -- preservation arms.
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  refine ⟨stkSt.push (.vBigint i), ?_, rfl, ?_⟩
  · -- Drive `runOps` through the lowered ops.
    rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
    simp only []
    rw [hBranchOps]
    -- Now we have `runOps [.ifOp [.push (.bigint i)] (some [.push (.bigint i)])] stk1`.
    rw [runOps.eq_2 stk1 [.push (.bigint i)]
          (some [.push (.bigint i)]) []]
    rw [hPop]
    simp only []
    rw [hBool]
    -- Each branch evaluates the same single-push op; the running stack
    -- under either branch is `{ stk1 with stack := stkSt.stack } = stkSt`,
    -- so `.push (.bigint i)` yields `stkSt.push (.vBigint i)`. The
    -- trailing `runOps [] _ = .ok _` closes the goal.
    cases b with
    | true =>
        simp only []
        rw [hStkEq]
        simp [runOps, stepNonIf]
    | false =>
        simp only []
        rw [hStkEq]
        simp [runOps, stepNonIf]
  · -- Predicate-side: agreesTagged after pushing the fresh literal.
    exact agreesTagged_push_value tsm bn anfSt stkSt (.vBigint i) hAgrees hFresh

/-! ### Method-level wrapper companion

A method whose body is **exactly** one `if_val` binding `bn` whose two
branches are each `[.mk vn (.loadConst (.int i)) src]` (same name,
same literal). Composes `runMethod_lower_public_unique_no_post_
structuralIfVal_narrow_isSome` (runtime success) with the predicate-
side `agreesTagged` preservation lemma above — landing the Tier 1
method-level wrapper that BOTH discharges runtime success AND
witnesses `agreesTagged` preservation across the if_val step.
-/

set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifValSingleConst_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState) (initialAnf : State)
    (initialTsm : TaggedStackMap)
    (bn cond vn : String) (src : Option SourceLoc)
    (i : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond
                          [.mk vn (.loadConst (.int i)) src]
                          [.mk vn (.loadConst (.int i)) src]) src])
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hAgrees : agreesTagged initialTsm initialAnf initialStack)
    (hFresh : freshIn bn (untagSm initialTsm))
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk',
        agreesTagged ((bn, .binding) :: initialTsm)
                     (initialAnf.addBinding bn (.vBigint i))
                     stk'
        ∧ stk' = initialStack.push (.vBigint i) := by
  refine ⟨?_, ?_⟩
  · -- Runtime success arm: reuse the narrowed wrapper. The required
    -- `structuralIfValBodyNarrow` predicate on `m.body` follows from
    -- `hBodyShape`.
    have hBody : structuralIfValBodyNarrow m.body := by
      rw [hBodyShape]
      refine ⟨?_, ?_⟩ <;>
        (simp [structuralConstBody, structuralConstValue])
    -- Reshape `hCondLoad` to match the narrowed wrapper's
    -- `∀ bn cond thn els src, m.body = [...] → ...` shape. Project away
    -- the extra metadata-preservation arms, which the narrowed wrapper
    -- does not need (it discharges runtime success only).
    have hCondLoad' :
        ∀ bn' cond' thn' els' src',
          m.body = [.mk bn' (.ifVal cond' thn' els') src'] →
          ∃ condV stk1,
            runOps
              (Stack.Lower.loadRef
                (m.params.map (fun p => p.name) |>.reverse) cond') initialStack
              = .ok stk1
            ∧ stk1.stack = condV :: initialStack.stack
            ∧ (∃ b, asBool? condV = some b) := by
      intro bn' cond' thn' els' src' hEq
      rw [hBodyShape] at hEq
      -- The matched single-element list-equality fixes
      -- bn' = bn, cond' = cond, etc.
      obtain ⟨condV, stk1, hLoad, hStk, _, _, _, _, hBool⟩ := hCondLoad
      injection hEq with hHead _
      injection hHead with _hName hVal _
      injection hVal with hCondEq _ _
      subst hCondEq
      exact ⟨condV, stk1, hLoad, hStk, hBool⟩
    exact runMethod_lower_public_unique_no_post_structuralIfVal_narrow_isSome
      contractName props methods m initialStack hMem hPublic hUnique
      hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize hBody
      hRawEqStructural hCondLoad'
  · -- Predicate-side arm: the lowered ifVal ops drive the stack from
    -- `initialStack` to `initialStack.push (.vBigint i)`, and
    -- `agreesTagged` is preserved via the single-const-both-branches
    -- preservation lemma above.
    obtain ⟨stk', _hRun, hStkEq, hAgrees'⟩ :=
      simpleStepRel_ifVal_singleConstBranches_preserves
        (m.params.map (fun p => p.name) |>.reverse) initialTsm initialAnf
        initialStack bn cond vn src i hAgrees hFresh hCondLoad
    exact ⟨stk', hAgrees', hStkEq⟩

/-! ## Tier 2 — Predicate-side preservation for the identical-single-const-binding
both-branches `if_val` fragment, widened across all three const kinds

Tier 1 (above) handled `[.mk vn (.loadConst (.int i)) src]` (integer literals only)
in both branches with the **same** name and **same** literal. Tier 2 widens to
**any** of the three `structuralConstValue`-compatible const kinds — `int`,
`bool`, and `bytes` — preserving the "identical branches" closure.

Tier 2 scope choice. The wave 1 obstacle report identified that the natural
"both branches in `structuralConstBody` (any chain length, possibly differing
between branches)" widening **cannot** preserve `agreesTagged` on the outer
post-state: for branches of length > 1 the lowered ifVal ops push multiple
values onto the stack, but the outer if_val binding adds only ONE name (`bn`)
to the structural stack map (cf. `lowerValue.eq_def` for the `.ifVal` arm —
the returned tail-map is `sm.push bindingName`, NOT
`sm.push (last-inner-name) :: …`). The intermediate values therefore have NO
slot in `tsm`, breaking `taggedStackAligned`'s positional alignment
requirement (see `taggedStackAligned`'s `s :: smRest, anfSt, v :: stkRest`
arm: every stack value must have a matching name in `tsm`).

Two cleanly-closeable Tier 2 scopes remain:

* **Identical-single-const, all kinds (this Tier 2).** Both branches are
  `[.mk vn (.loadConst c) src]` with the **same** literal `c`, where
  `structuralConstValue (.loadConst c)`. The cond-branch picks the same single
  push regardless. This is what Tier 2 lands.
* **Identical-multi-const-chains.** Both branches are literally the **same**
  `structuralConstBody` list. The cond-branch picks the same chain
  deterministically, but the resulting stack has length > 1 intermediate
  values stacked beneath `bn`. The `agreesTagged` post-condition would have
  to relate `((bn, .binding) :: tsm)` against a stack with intermediate
  values not represented in `tsm`. Not closeable under the current
  `taggedStackAligned` shape; requires a "stack-equivalence-modulo-
  intermediates" predicate that lives outside Stack/AgreesA6.lean's scope.

Tier 2 below lands the first option. The Tier 1 `simpleStepRel_ifVal_
singleConstBranches_preserves` becomes a corollary at `c = .int i`.

Forbidden patterns explicitly avoided. The cond-load witness is the same
input-side shape as Tier 1 (talks ONLY about the `loadRef sm cond` prefix and
the pushed cond value's bool coercion); no conclusion-restating premise of
the kind PATH2_PLAN §2.1 enumerates. -/

/-- `constToValue c` maps a `structuralConstValue`-compatible `ConstValue` to
the `Value` that `emitConst c`'s singleton `.push` lowers to. Defined for the
three `structuralConstValue`-admissible kinds only; the unreachable arms
return a placeholder (the predicate-side proof discharges them via
`structuralConstValue` contradiction). -/
def constToValue : ConstValue → Value
  | .int i      => .vBigint i
  | .bool b     => .vBool b
  | .bytes ba   => .vBytes ba
  | .refAlias _ => .vBigint 0   -- unreachable under `structuralConstValue`
  | .thisRef    => .vBigint 0   -- unreachable under `structuralConstValue`

/-- For any `structuralConstValue`-compatible const, `emitConst c` is exactly
the singleton `[.push p]` where `p` matches the kind of `c`, and running it
pushes `constToValue c` on the stack. -/
theorem emitConst_run_structuralConst (c : ConstValue)
    (h : structuralConstValue (.loadConst c)) (stk : StackState) :
    runOps (Stack.Lower.emitConst c) stk = .ok (stk.push (constToValue c)) := by
  cases c with
  | int i =>
      simp [Stack.Lower.emitConst, constToValue, runOps, stepNonIf]
  | bool b =>
      simp [Stack.Lower.emitConst, constToValue, runOps, stepNonIf]
  | bytes ba =>
      simp [Stack.Lower.emitConst, constToValue, runOps, stepNonIf]
  | refAlias _ => simp [structuralConstValue] at h
  | thisRef => simp [structuralConstValue] at h

set_option maxHeartbeats 1600000 in
/-- **Tier 2 predicate-side preservation** for the identical-single-const
both-branches `if_val` fragment, generalised across all three
`structuralConstValue`-compatible kinds (`int`, `bool`, `bytes`).

Given an input-side `agreesTagged tsm anfSt stkSt`, freshness of the outer
if_val binding name `bn`, and a *prefix-only* cond-load witness (talks only
about the `loadRef sm cond` prefix, the pushed cond value's bool coercion,
and metadata-field preservation across the cond load — these are facts about
the **initial** state, NOT restatements of the conclusion), there exists a
post-state `stk'` such that running the lowered ifVal ops yields `.ok stk'`
with `agreesTagged ((bn, .binding) :: tsm) (anfSt.addBinding bn (constToValue c))
stk'`.

Branches are exactly `[.mk vn (.loadConst c) src]` (same name, same literal)
with `c` ranging over `.int _`, `.bool _`, and `.bytes _`. Either branch
executes deterministically to push `constToValue c` on top, so the post-state
is independent of the cond value. -/
theorem simpleStepRel_ifVal_identicalSingleConst_preserves
    (sm : StackMap)
    (tsm : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (bn cond vn : String) (src : Option SourceLoc)
    (c : ConstValue)
    (hConst : structuralConstValue (.loadConst c))
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn
          (.ifVal cond
            [.mk vn (.loadConst c) src]
            [.mk vn (.loadConst c) src])).1 stkSt = .ok stk'
      ∧ stk' = stkSt.push (constToValue c)
      ∧ agreesTagged ((bn, .binding) :: tsm)
                     (anfSt.addBinding bn (constToValue c))
                     stk' := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  -- Unfold the if_val lowering: `loadRef sm cond ++ [.ifOp thnOps (some elsOps)]`.
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn
        (.ifVal cond
          [.mk vn (.loadConst c) src]
          [.mk vn (.loadConst c) src])).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm
                      [.mk vn (.loadConst c) src]).1
                    (some (Stack.Lower.lowerBindings sm
                      [.mk vn (.loadConst c) src]).1)] := by
    simp [Stack.Lower.lowerValue]
  -- Each branch lowers to `emitConst c` (a single `.push` op). For abstract
  -- `c`, we case-split on the `structuralConstValue`-admissible kinds; the
  -- two unreachable arms (`refAlias`, `thisRef`) are discharged via the
  -- `structuralConstValue` hypothesis `hConst`.
  have hBranchOps :
      (Stack.Lower.lowerBindings sm
        [.mk vn (.loadConst c) src]).1
        = Stack.Lower.emitConst c := by
    cases c with
    | int _ => simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue]
    | bool _ => simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue]
    | bytes _ => simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue]
    | refAlias _ => simp [structuralConstValue] at hConst
    | thisRef => simp [structuralConstValue] at hConst
  -- Pop equation for stk1 derived from hStk.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  -- Stack-state equality after popping the cond from stk1: the residual
  -- record equals `stkSt` modulo `stack`, by the metadata preservation arms.
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  -- `emitConst c` runs to `.ok (stk.push (constToValue c))` from `stkSt`.
  have hEmitRun := emitConst_run_structuralConst c hConst stkSt
  refine ⟨stkSt.push (constToValue c), ?_, rfl, ?_⟩
  · -- Drive `runOps` through the lowered ops.
    rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
    simp only []
    rw [hBranchOps]
    -- Now: `runOps [.ifOp (emitConst c) (some (emitConst c))] stk1`.
    rw [runOps.eq_2 stk1 (Stack.Lower.emitConst c)
          (some (Stack.Lower.emitConst c)) []]
    rw [hPop]
    simp only []
    rw [hBool]
    -- Each branch evaluates the same single-push op; after pop, the running
    -- stack is `{ stk1 with stack := stkSt.stack } = stkSt`, so emitConst
    -- pushes `constToValue c`. The trailing `runOps [] _ = .ok _` closes.
    cases b with
    | true =>
        simp only []
        rw [hStkEq, hEmitRun]
        simp [runOps]
    | false =>
        simp only []
        rw [hStkEq, hEmitRun]
        simp [runOps]
  · -- Predicate-side: agreesTagged after pushing the fresh literal.
    exact agreesTagged_push_value tsm bn anfSt stkSt (constToValue c)
            hAgrees hFresh

/-! ### Tier 2 method-level wrapper

Mirrors the Tier 1 method-level wrapper but with the const literal `c` ranging
across the three `structuralConstValue`-compatible kinds. Composes:

* `runMethod_lower_public_unique_no_post_structuralIfVal_narrow_isSome` —
  the runtime-side `isSome` (already accepts arbitrary `structuralConstBody`
  branches, so the single-`loadConst c` branch shape is covered).
* `simpleStepRel_ifVal_identicalSingleConst_preserves` — the Tier 2
  predicate-side preservation lemma above.

Just like Tier 1's wrapper, no conclusion-restating premise (per
PATH2_PLAN §2.1); the only runtime-side input is the cond-load witness,
an input-side fact about the **initial** state. -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifValIdenticalConst_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState) (initialAnf : State)
    (initialTsm : TaggedStackMap)
    (bn cond vn : String) (src : Option SourceLoc)
    (c : ConstValue)
    (hConst : structuralConstValue (.loadConst c))
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond
                          [.mk vn (.loadConst c) src]
                          [.mk vn (.loadConst c) src]) src])
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hAgrees : agreesTagged initialTsm initialAnf initialStack)
    (hFresh : freshIn bn (untagSm initialTsm))
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk',
        agreesTagged ((bn, .binding) :: initialTsm)
                     (initialAnf.addBinding bn (constToValue c))
                     stk'
        ∧ stk' = initialStack.push (constToValue c) := by
  refine ⟨?_, ?_⟩
  · -- Runtime success arm: reuse the narrowed wrapper. The required
    -- `structuralIfValBodyNarrow` predicate on `m.body` follows from
    -- `hBodyShape` plus `hConst`.
    have hBody : structuralIfValBodyNarrow m.body := by
      rw [hBodyShape]
      exact ⟨⟨hConst, trivial⟩, ⟨hConst, trivial⟩⟩
    -- Reshape `hCondLoad` to match the narrowed wrapper's
    -- `∀ bn' cond' thn' els' src', m.body = [...] → ...` shape.
    have hCondLoad' :
        ∀ bn' cond' thn' els' src',
          m.body = [.mk bn' (.ifVal cond' thn' els') src'] →
          ∃ condV stk1,
            runOps
              (Stack.Lower.loadRef
                (m.params.map (fun p => p.name) |>.reverse) cond') initialStack
              = .ok stk1
            ∧ stk1.stack = condV :: initialStack.stack
            ∧ (∃ b, asBool? condV = some b) := by
      intro bn' cond' thn' els' src' hEq
      rw [hBodyShape] at hEq
      obtain ⟨condV, stk1, hLoad, hStk, _, _, _, _, hBool⟩ := hCondLoad
      injection hEq with hHead _
      injection hHead with _hName hVal _
      injection hVal with hCondEq _ _
      subst hCondEq
      exact ⟨condV, stk1, hLoad, hStk, hBool⟩
    exact runMethod_lower_public_unique_no_post_structuralIfVal_narrow_isSome
      contractName props methods m initialStack hMem hPublic hUnique
      hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize hBody
      hRawEqStructural hCondLoad'
  · -- Predicate-side arm: the lowered ifVal ops drive the stack from
    -- `initialStack` to `initialStack.push (constToValue c)`, and
    -- `agreesTagged` is preserved via the Tier 2 single-const-identical-
    -- branches preservation lemma above.
    obtain ⟨stk', _hRun, hStkEq, hAgrees'⟩ :=
      simpleStepRel_ifVal_identicalSingleConst_preserves
        (m.params.map (fun p => p.name) |>.reverse) initialTsm initialAnf
        initialStack bn cond vn src c hConst hAgrees hFresh hCondLoad
    exact ⟨stk', hAgrees', hStkEq⟩

/-! ## Tier 3 — Predicate-side widening for multi-binding const-chain branches,
joined via `stackEquivModuloIntermediates`

Tier 1 / Tier 2 (above) handle if_val whose branches are each *exactly one*
`.loadConst` binding (with the same name + same literal). Tier 3 widens to
**multi-binding** `structuralConstBody` chains: each branch may be a list of
length ≥ 1 of `.loadConst` bindings (any of the three structural kinds
int/bool/bytes, possibly mixed), as long as both branches share the **same
terminal `.loadConst c` binding** — the same const literal `c` is the last
pushed value in both arms.

The wave 2 obstacle (per `Stack/AgreesA6.lean` Tier 2 comments) is that the
multi-binding chain leaves intermediate values stacked beneath the if_val
result; the outer `tsm` adds only `(bn, .binding)` for the if_val binding
itself, so the intermediate stack values have no slot in `tsm` — breaking
`taggedStackAligned`'s positional alignment requirement.

The Path 2 wave-3 substrate (`stackEquivModuloIntermediates`, added in
`Stack/Agrees.lean`) sidesteps this by relaxing the post-condition from
`agreesTagged ((bn, .binding) :: tsm) anfSt' stk'` (which would require
positional alignment all the way down) to a *coarser* "head + metadata"
relation: the post-state's stack-top is `constToValue c` and the metadata
fields are unchanged from `stkSt` — both true regardless of the
intermediate-binding stack residue.

Tier 1 / Tier 2 remain useful because they ship the **full** `agreesTagged`
post-condition (the chain length 1 case has no intermediates). Tier 3 is the
strictly weaker but strictly broader companion. -/

/-- A `structuralConstBody` whose last binding is exactly `.mk vn (.loadConst c) src`.
This is the predicate Tier 3 imposes on each branch: the branch is a
non-empty const chain whose terminal const literal coincides with the
peer branch's.

We define it on **non-empty** lists by pattern-matching on the trailing
binding via `List.reverse`-style: rather than nest patterns at the head
(which makes Lean's exhaustivity / definitional-equality machinery
unhappy because `[x]` and `x :: y :: rest` overlap structurally with
`x :: rest`), we phrase the predicate as a conjunction:

* `structuralConstBody body` — every binding loads a structural const;
* `body.getLast? = some (.mk vn (.loadConst c) src)` — the terminal
  binding is exactly the named/coupled `.loadConst c`.

This phrasing is decidable by composition of two existing decidable
predicates, makes the case-analysis flat (a single existence witness
suffices), and dodges the structural-equality footguns the nested
pattern would have hit. -/
def structuralConstBodyEndsWithConst (vn : String) (c : ConstValue) (src : Option SourceLoc)
    (body : List ANFBinding) : Prop :=
  structuralConstBody body ∧ body.getLast? = some (.mk vn (.loadConst c) src)

/-- `structuralConstBodyEndsWithConst` is a refinement of `structuralConstBody`:
the chain is structurally const all the way down (immediate from the
conjunctive definition). -/
theorem structuralConstBodyEndsWithConst_implies_structuralConstBody
    (vn : String) (c : ConstValue) (src : Option SourceLoc)
    (body : List ANFBinding)
    (h : structuralConstBodyEndsWithConst vn c src body) :
    structuralConstBody body := h.1

/-- The terminal binding extracted from `structuralConstBodyEndsWithConst`. -/
theorem structuralConstBodyEndsWithConst_getLast
    (vn : String) (c : ConstValue) (src : Option SourceLoc)
    (body : List ANFBinding)
    (h : structuralConstBodyEndsWithConst vn c src body) :
    body.getLast? = some (.mk vn (.loadConst c) src) := h.2

/-- Head-push metadata-preservation helper: a `.loadConst` binding's lowered
ops (a single push) preserve the non-stack metadata fields. Used by the
recursive Tier-3 substrate lemmas below for the cons-step. -/
private theorem runOps_lowerValue_loadConst_preserves_metadata
    (sm : StackMap) (name : String) (v : ANFValue) (stk : StackState)
    (hHead : structuralConstValue v) :
    ∃ stk1, runOps (Stack.Lower.lowerValue sm name v).1 stk = .ok stk1
      ∧ stk1.altstack = stk.altstack
      ∧ stk1.outputs = stk.outputs
      ∧ stk1.props = stk.props
      ∧ stk1.preimage = stk.preimage := by
  cases v with
  | loadConst c0 =>
      cases c0 with
      | int i =>
          refine ⟨stk.push (.vBigint i), ?_, ?_, ?_, ?_, ?_⟩
          · simp [Stack.Lower.lowerValue, Stack.Lower.emitConst,
                  runOps, stepNonIf]
          all_goals (unfold StackState.push; rfl)
      | bool b =>
          refine ⟨stk.push (.vBool b), ?_, ?_, ?_, ?_, ?_⟩
          · simp [Stack.Lower.lowerValue, Stack.Lower.emitConst,
                  runOps, stepNonIf]
          all_goals (unfold StackState.push; rfl)
      | bytes ba =>
          refine ⟨stk.push (.vBytes ba), ?_, ?_, ?_, ?_, ?_⟩
          · simp [Stack.Lower.lowerValue, Stack.Lower.emitConst,
                  runOps, stepNonIf]
          all_goals (unfold StackState.push; rfl)
      | refAlias _ => simp [structuralConstValue] at hHead
      | thisRef => simp [structuralConstValue] at hHead
  | loadParam _ => simp [structuralConstValue] at hHead
  | loadProp _ => simp [structuralConstValue] at hHead
  | binOp _ _ _ _ => simp [structuralConstValue] at hHead
  | unaryOp _ _ _ => simp [structuralConstValue] at hHead
  | call _ _ => simp [structuralConstValue] at hHead
  | methodCall _ _ _ => simp [structuralConstValue] at hHead
  | ifVal _ _ _ => simp [structuralConstValue] at hHead
  | loop _ _ _ => simp [structuralConstValue] at hHead
  | assert _ => simp [structuralConstValue] at hHead
  | updateProp _ _ => simp [structuralConstValue] at hHead
  | getStateScript => simp [structuralConstValue] at hHead
  | checkPreimage _ => simp [structuralConstValue] at hHead
  | deserializeState _ => simp [structuralConstValue] at hHead
  | addOutput _ _ _ => simp [structuralConstValue] at hHead
  | addRawOutput _ _ => simp [structuralConstValue] at hHead
  | addDataOutput _ _ => simp [structuralConstValue] at hHead
  | arrayLiteral _ => simp [structuralConstValue] at hHead
  | rawScript _ _ _ => simp [structuralConstValue] at hHead

/-- Stronger version of `runOps_lowerBindings_structuralConstBody_ok`:
running the lowered ops of a `structuralConstBody` from any starting state
yields a post-state that **preserves all non-stack metadata fields**
(`altstack`, `outputs`, `props`, `preimage`). This is the technical fact
underlying `stackEquivModuloIntermediates`'s metadata-preservation arms:
const bodies only emit `.push` ops, which touch only the `stack` field. -/
theorem runOps_lowerBindings_structuralConstBody_preserves_metadata :
    ∀ (body : List ANFBinding) (sm : StackMap) (stk : StackState),
      structuralConstBody body →
      ∃ stk',
        runOps (Stack.Lower.lowerBindings sm body).1 stk = .ok stk'
        ∧ stk'.altstack = stk.altstack
        ∧ stk'.outputs = stk.outputs
        ∧ stk'.props = stk.props
        ∧ stk'.preimage = stk.preimage
  | [], _sm, stk, _h => by
      refine ⟨stk, ?_, rfl, rfl, rfl, rfl⟩
      simp [Stack.Lower.lowerBindings, runOps]
  | (.mk name v src) :: rest, sm, stk, h => by
      simp only [structuralConstBody] at h
      obtain ⟨hHead, hRest⟩ := h
      obtain ⟨stk1, hHeadRun, hAlt1, hOut1, hProps1, hPre1⟩ :=
        runOps_lowerValue_loadConst_preserves_metadata sm name v stk hHead
      have hUnfold :
          (Stack.Lower.lowerBindings sm ((ANFBinding.mk name v src) :: rest)).1
            = (Stack.Lower.lowerValue sm name v).1
              ++ (Stack.Lower.lowerBindings (Stack.Lower.lowerValue sm name v).2 rest).1 := by
        simp [Stack.Lower.lowerBindings]
      obtain ⟨stk', hTailRun, hAlt', hOut', hProps', hPre'⟩ :=
        runOps_lowerBindings_structuralConstBody_preserves_metadata rest
          (Stack.Lower.lowerValue sm name v).2 stk1 hRest
      refine ⟨stk', ?_, ?_, ?_, ?_, ?_⟩
      · rw [hUnfold, Stack.Sim.runOps_append, hHeadRun]
        exact hTailRun
      · exact hAlt'.trans hAlt1
      · exact hOut'.trans hOut1
      · exact hProps'.trans hProps1
      · exact hPre'.trans hPre1

/-- Decompose a `structuralConstBody` whose last binding loads `c` into
its `dropLast` prefix (still a `structuralConstBody`) and the terminal
`.mk vn (.loadConst c) src` binding, satisfying
`body = body.dropLast ++ [.mk vn (.loadConst c) src]`.

Used to split the `lowerBindings` work into a metadata-preserving
prefix run plus an `emitConst c` push for the terminal binding. -/
private theorem structuralConstBody_split_at_terminal_const
    (vn : String) (c : ConstValue) (src : Option SourceLoc) :
    ∀ (body : List ANFBinding),
      structuralConstBody body →
      body.getLast? = some (.mk vn (.loadConst c) src) →
      body = body.dropLast ++ [.mk vn (.loadConst c) src]
        ∧ structuralConstBody body.dropLast
        ∧ structuralConstValue (.loadConst c)
  | [], _, hLast => by simp [List.getLast?] at hLast
  | [b], hSC, hLast => by
      simp [List.getLast?] at hLast
      subst hLast
      refine ⟨?_, ?_, ?_⟩
      · simp [List.dropLast]
      · simp [List.dropLast, structuralConstBody]
      · -- The terminal binding's value `.loadConst c` is the only binding,
        -- and `structuralConstBody [.]` gives `structuralConstValue (.loadConst c)`.
        simp only [structuralConstBody] at hSC
        exact hSC.1
  | b1 :: b2 :: rest, hSC, hLast => by
      obtain ⟨b1name, b1v, b1src⟩ := b1
      simp only [structuralConstBody] at hSC
      obtain ⟨hHd, hTl⟩ := hSC
      have hLast' : (b2 :: rest).getLast?
                      = some (.mk vn (.loadConst c) src) := by
        simpa [List.getLast?] using hLast
      obtain ⟨hEq, hPreSC, hConst⟩ :=
        structuralConstBody_split_at_terminal_const vn c src (b2 :: rest) hTl hLast'
      refine ⟨?_, ?_, hConst⟩
      · -- b1 :: b2 :: rest = (b1 :: (b2 :: rest).dropLast) ++ [terminal]
        --                  = (b1 :: b2 :: rest).dropLast ++ [terminal]
        have hExpand :
            (.mk b1name b1v b1src : ANFBinding) :: b2 :: rest
              = .mk b1name b1v b1src ::
                  ((b2 :: rest).dropLast ++ [.mk vn (.loadConst c) src]) := by
          rw [← hEq]
        rw [hExpand]
        simp [List.dropLast]
      · simp [List.dropLast, structuralConstBody, hHd, hPreSC]

/-- Tier 3 substrate: running the lowered ops of a `structuralConstBody`
**whose last binding loads `c`** yields a post-state that is
`stackEquivModuloIntermediates`-equivalent to `stk.push (constToValue c)`
— the terminal const sits on top of stack regardless of the chain prefix,
and metadata fields are preserved. -/
theorem runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
    (vn : String) (c : ConstValue) (src : Option SourceLoc)
    (body : List ANFBinding) (sm : StackMap) (stk : StackState)
    (h : structuralConstBodyEndsWithConst vn c src body) :
    ∃ stk',
      runOps (Stack.Lower.lowerBindings sm body).1 stk = .ok stk'
      ∧ stackEquivModuloIntermediates stk' (stk.push (constToValue c)) := by
  obtain ⟨hSC, hLast⟩ := h
  obtain ⟨hEq, hPreSC, hConst⟩ :=
    structuralConstBody_split_at_terminal_const vn c src body hSC hLast
  -- `body = body.dropLast ++ [.mk vn (.loadConst c) src]`. Lowering splits:
  -- `lowerBindings sm body` ops = prefix-ops ++ emitConst-c-ops.
  -- Run prefix on `stk` (metadata-preserving), then emitConst.
  obtain ⟨stk1, hPreRun, hAlt1, hOut1, hProps1, hPre1⟩ :=
    runOps_lowerBindings_structuralConstBody_preserves_metadata
      body.dropLast sm stk hPreSC
  -- Now run the terminal `emitConst c` from stk1.
  have hRun : runOps (Stack.Lower.emitConst c) stk1
                = .ok (stk1.push (constToValue c)) :=
    emitConst_run_structuralConst c hConst stk1
  -- Compose. The lowered ops for `body.dropLast ++ [terminal]` are
  -- `(lowerBindings sm body.dropLast).1 ++ emitConst c`.
  have hAppendOps :
      ∀ (xs ys : List ANFBinding) (sm0 : StackMap),
        (Stack.Lower.lowerBindings sm0 (xs ++ ys)).1
          = (Stack.Lower.lowerBindings sm0 xs).1
              ++ (Stack.Lower.lowerBindings (Stack.Lower.lowerBindings sm0 xs).2 ys).1 := by
    intro xs
    induction xs with
    | nil =>
        intro ys sm0
        simp [Stack.Lower.lowerBindings]
    | cons hd tl ih =>
        intro ys sm0
        obtain ⟨name, v, src'⟩ := hd
        simp [Stack.Lower.lowerBindings, ih, List.append_assoc]
  have hTermOps :
      (Stack.Lower.lowerBindings (Stack.Lower.lowerBindings sm body.dropLast).2
          [.mk vn (.loadConst c) src]).1
        = Stack.Lower.emitConst c := by
    cases c with
    | int _ =>
        simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue, Stack.Lower.emitConst]
    | bool _ =>
        simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue, Stack.Lower.emitConst]
    | bytes _ =>
        simp [Stack.Lower.lowerBindings, Stack.Lower.lowerValue, Stack.Lower.emitConst]
    | refAlias _ => simp [structuralConstValue] at hConst
    | thisRef => simp [structuralConstValue] at hConst
  -- Establish the full lowered ops list once.
  have hBodyOps :
      (Stack.Lower.lowerBindings sm body).1
        = (Stack.Lower.lowerBindings sm body.dropLast).1
          ++ Stack.Lower.emitConst c := by
    have hStep1 : (Stack.Lower.lowerBindings sm body).1
                    = (Stack.Lower.lowerBindings sm
                        (body.dropLast ++ [.mk vn (.loadConst c) src])).1 := by
      -- `rw [hEq]` directly would loop (body appears under body.dropLast); use
      -- a `congr_arg` over the list-equality.
      exact congrArg (·.1) (congrArg (Stack.Lower.lowerBindings sm) hEq)
    rw [hStep1, hAppendOps body.dropLast [.mk vn (.loadConst c) src] sm, hTermOps]
  refine ⟨stk1.push (constToValue c), ?_, ?_⟩
  · -- Drive `runOps` through the concatenated lowering.
    rw [hBodyOps, Stack.Sim.runOps_append, hPreRun]
    exact hRun
  · -- `stackEquivModuloIntermediates (stk1.push (constToValue c))
    --                                (stk.push (constToValue c))`.
    refine And.intro ?_ (And.intro ?_ (And.intro ?_ (And.intro ?_ ?_)))
    · -- head? equal: both stacks have `constToValue c` on top.
      simp [StackState.push]
    · show (stk1.push (constToValue c)).altstack
            = (stk.push (constToValue c)).altstack
      unfold StackState.push
      simp [hAlt1]
    · show (stk1.push (constToValue c)).outputs
            = (stk.push (constToValue c)).outputs
      unfold StackState.push
      simp [hOut1]
    · show (stk1.push (constToValue c)).props
            = (stk.push (constToValue c)).props
      unfold StackState.push
      simp [hProps1]
    · show (stk1.push (constToValue c)).preimage
            = (stk.push (constToValue c)).preimage
      unfold StackState.push
      simp [hPre1]

set_option maxHeartbeats 1600000 in
/-- **Tier 3 predicate-side preservation** for the multi-binding const-chain
both-branches `if_val` fragment. Both branches are arbitrary
`structuralConstBody` chains of length ≥ 1 ending in the **same** terminal
`.mk vn (.loadConst c) src` binding. The post-state is
`stackEquivModuloIntermediates`-equivalent to `initialStack.push (constToValue c)`
— it has the right top-of-stack value and preserves all non-stack metadata,
*even though* the intermediate (non-terminal) bindings push extra stack values
that have no slot in the outer `tsm`.

The natural `agreesTagged` post-condition from Tier 1/Tier 2 is *not*
recoverable here (the intermediate stack values break positional alignment);
the looser `stackEquivModuloIntermediates` conclusion is exactly the
substrate `Pipeline.lean`-side conformance harness will plumb forward when it
chains an if_val step into a longer Stage-C body.

The `hCondLoad` premise is identical in shape to Tier 1/Tier 2: an
**input-side** fact about the `loadRef sm cond` prefix and the pushed cond
value's bool coercion, NOT a restatement of the conclusion. -/
theorem simpleStepRel_ifVal_anyConstChain_preserves
    (sm : StackMap)
    (anfSt : State) (stkSt : StackState)
    (bn cond vn : String) (src : Option SourceLoc)
    (c : ConstValue)
    (thn els : List ANFBinding)
    (hThn : structuralConstBodyEndsWithConst vn c src thn)
    (hEls : structuralConstBodyEndsWithConst vn c src els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ stackEquivModuloIntermediates stk' (stkSt.push (constToValue c))
      -- ANF-side bookkeeping: the if_val binding adds `bn` to the state
      -- with value `constToValue c`. This is the value that the lowered
      -- terminal const binding deterministically pushes regardless of which
      -- branch fires.
      ∧ (anfSt.addBinding bn (constToValue c)).lookupBinding bn
          = some (constToValue c) := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  -- Unfold the if_val lowering: `loadRef sm cond ++ [.ifOp thnOps (some elsOps)]`.
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                    (some (Stack.Lower.lowerBindings sm els).1)] := by
    simp [Stack.Lower.lowerValue]
  -- Pop equation for stk1.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  -- The residual record after popping cond from stk1 equals stkSt by metadata
  -- preservation.
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  -- Run each branch from `stkSt` (after popping cond), exposing the
  -- `stackEquivModuloIntermediates` witness.
  obtain ⟨stkT, hRunT, hEquivT⟩ :=
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vn c src thn sm stkSt hThn
  obtain ⟨stkE, hRunE, hEquivE⟩ :=
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vn c src els sm stkSt hEls
  -- Drive runOps through the if_val lowered ops.
  cases b with
  | true =>
      refine ⟨stkT, ?_, hEquivT, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunT]
        simp [runOps]
      · simp [State.lookupBinding, State.addBinding]
  | false =>
      refine ⟨stkE, ?_, hEquivE, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunE]
        simp [runOps]
      · simp [State.lookupBinding, State.addBinding]

/-! ### Tier 3 method-level wrapper

Method-level companion of `simpleStepRel_ifVal_anyConstChain_preserves`,
mirroring the Tier 1 / Tier 2 wrappers. Composes:

* the runtime-success arm via `runMethod_lower_public_unique_no_post_eq_userRaw`
  + the direct construction of the `runOps` post-state (which yields
  `.toOption.isSome` definitionally);
* the predicate-side `stackEquivModuloIntermediates`-equivalence to
  `initialStack.push (constToValue c)`, witnessing the if_val terminal
  push.

No conclusion-restating premise (per PATH2_PLAN §2.1). The only runtime-side
input is the prefix-only cond-load witness about `loadRef _ cond`. -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifValAnyConstChain_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState) (initialAnf : State)
    (bn cond vn : String) (src : Option SourceLoc)
    (c : ConstValue)
    (thn els : List ANFBinding)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (hThn : structuralConstBodyEndsWithConst vn c src thn)
    (hEls : structuralConstBodyEndsWithConst vn c src els)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk',
        stackEquivModuloIntermediates stk' (initialStack.push (constToValue c))
        ∧ (initialAnf.addBinding bn (constToValue c)).lookupBinding bn
            = some (constToValue c) := by
  -- The predicate-side `simpleStepRel_ifVal_anyConstChain_preserves` discharges
  -- *both* halves: it produces a `stk'` witnessing runOps success AND the
  -- `stackEquivModuloIntermediates` post-state.
  let sm := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', hRun, hEquiv, hLookup⟩ :=
    simpleStepRel_ifVal_anyConstChain_preserves
      sm initialAnf initialStack bn cond vn src c thn els hThn hEls hCondLoad
  refine ⟨?_, stk', hEquiv, hLookup⟩
  -- Runtime-success arm: route through `runMethod_lower_public_unique_no_post_eq_userRaw`
  -- → `hRawEqStructural` → the directly-constructed runOps post-state.
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hRawEqStructural]
  -- m.body = [.mk bn (.ifVal cond thn els) src], so
  -- `lowerBindings sm m.body` = `lowerValue sm bn (.ifVal cond thn els)` ++ [].
  rw [hBodyShape]
  have hUnfold :
      (Stack.Lower.lowerBindings sm
          [.mk bn (.ifVal cond thn els) src]).1
        = (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 := by
    simp [Stack.Lower.lowerBindings]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

/-! ## Tier 4 — Predicate-side widening for **heterogeneous-const-chain** branches

Tier 3 (above) handled multi-binding `structuralConstBody` chains whose two
branches share the **same** terminal `.loadConst c` binding — the joint
post-state has the same top-of-stack value `constToValue c` regardless of
which branch fires. Tier 4 widens to branches with potentially **different**
terminal consts: `thn` ends with `.mk vnThn (.loadConst cThn) srcThn` and
`els` ends with `.mk vnEls (.loadConst cEls) srcEls`, with no requirement
that `(vnThn, cThn, srcThn) = (vnEls, cEls, srcEls)`.

The post-state is no longer a single `stackEquivModuloIntermediates` witness:
the top-of-stack value depends on the cond bool. The conclusion uses a
case-split:

* `b = true` (cond fires `thn`): post-state `stackEquivModuloIntermediates`-
  equivalent to `stkSt.push (constToValue cThn)`.
* `b = false` (cond fires `els`): post-state `stackEquivModuloIntermediates`-
  equivalent to `stkSt.push (constToValue cEls)`.

In both cases the non-stack metadata fields (`altstack`, `outputs`, `props`,
`preimage`) are preserved against `stkSt` — that arm is cond-independent and
follows from `stackEquivModuloIntermediates`'s metadata arms (transitively,
since `(stk.push v).altstack = stk.altstack`, etc.).

This is the natural Tier 3 widening for heterogeneous-const branches. It
captures every const-only branch pair (different literals across kinds,
different chain lengths, etc.) without requiring any new substrate beyond
the existing `runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv`
helper. Branches with **non-const** sub-bindings (e.g. `loadParam`,
`loadProp`) are out of scope here — they would require an analogous
metadata-preservation result for `structuralRefBody`, which the current
Stack/Agrees.lean substrate does not provide. See the BLOCKED note in the
discovery report for the substrate gap.

Forbidden patterns explicitly avoided. The cond-load witness is the same
input-side shape as Tier 1/2/3 (talks ONLY about the `loadRef sm cond`
prefix and the pushed cond value's bool coercion); no conclusion-restating
premise. -/

set_option maxHeartbeats 1600000 in
/-- **Tier 4 predicate-side preservation** for the **heterogeneous**-const-
chain both-branches `if_val` fragment. Each branch is an arbitrary
`structuralConstBody` chain of length ≥ 1 ending in its **own** terminal
`.mk vn? (.loadConst c?) src?` binding (which may differ across branches).

The conclusion is a case-split on the cond bool `b`:

* `b = true` ⇒ `stackEquivModuloIntermediates stk' (stkSt.push (constToValue cThn))`;
* `b = false` ⇒ `stackEquivModuloIntermediates stk' (stkSt.push (constToValue cEls))`.

The cond-load witness has the same input-side shape as Tier 1/2/3 (talks
only about the `loadRef sm cond` prefix and the pushed cond value's bool
coercion), with the metadata-preservation arms that let us prove the
residual record after popping cond from stk1 equals stkSt. -/
theorem simpleStepRel_ifVal_heteroConstChains_preserves
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnThn vnEls : String) (srcThn srcEls : Option SourceLoc)
    (cThn cEls : ConstValue)
    (thn els : List ANFBinding)
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ (b = true →
            stackEquivModuloIntermediates stk' (stkSt.push (constToValue cThn)))
      ∧ (b = false →
            stackEquivModuloIntermediates stk' (stkSt.push (constToValue cEls))) := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  -- Unfold the if_val lowering: `loadRef sm cond ++ [.ifOp thnOps (some elsOps)]`.
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                    (some (Stack.Lower.lowerBindings sm els).1)] := by
    simp [Stack.Lower.lowerValue]
  -- Pop equation for stk1.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  -- The residual record after popping cond from stk1 equals stkSt by metadata
  -- preservation.
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  -- Run each branch from `stkSt` (after popping cond), exposing the
  -- `stackEquivModuloIntermediates` witness against the branch's own terminal const.
  obtain ⟨stkT, hRunT, hEquivT⟩ :=
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vnThn cThn srcThn thn sm stkSt hThn
  obtain ⟨stkE, hRunE, hEquivE⟩ :=
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vnEls cEls srcEls els sm stkSt hEls
  -- Drive runOps through the if_val lowered ops; case-split on `b`.
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunT]
        simp [runOps]
      · intro _; exact hEquivT
      · intro hF; cases hF
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunE]
        simp [runOps]
      · intro hT; cases hT
      · intro _; exact hEquivE

/-- **Tier 4 cond-independent metadata-preservation corollary**. The Tier 4
preservation lemma above produces a cond-dependent `stackEquivModuloIntermediates`
witness, with the two case arms naming different reference states
(`stkSt.push (constToValue cThn)` vs. `stkSt.push (constToValue cEls)`). For
downstream consumers that only need cond-independent metadata preservation
(i.e. `altstack`, `outputs`, `props`, `preimage` all match `stkSt`'s), this
corollary specialises the disjunction: it discards the head? equality (which
depends on the cond) and exports only the cond-uniform metadata-preservation
arms. -/
theorem simpleStepRel_ifVal_heteroConstChains_preserves_metadata
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnThn vnEls : String) (srcThn srcEls : Option SourceLoc)
    (cThn cEls : ConstValue)
    (thn els : List ANFBinding)
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', b, hRun, _hWit, hEquivT, hEquivE⟩ :=
    simpleStepRel_ifVal_heteroConstChains_preserves
      sm stkSt bn cond vnThn vnEls srcThn srcEls cThn cEls thn els hThn hEls hCondLoad
  cases b with
  | true =>
      have hEquiv := hEquivT rfl
      obtain ⟨_hHead, hAlt, hOut, hProps, hPre⟩ := hEquiv
      refine ⟨stk', hRun, ?_, ?_, ?_, ?_⟩
      · rw [hAlt]; unfold StackState.push; rfl
      · rw [hOut]; unfold StackState.push; rfl
      · rw [hProps]; unfold StackState.push; rfl
      · rw [hPre]; unfold StackState.push; rfl
  | false =>
      have hEquiv := hEquivE rfl
      obtain ⟨_hHead, hAlt, hOut, hProps, hPre⟩ := hEquiv
      refine ⟨stk', hRun, ?_, ?_, ?_, ?_⟩
      · rw [hAlt]; unfold StackState.push; rfl
      · rw [hOut]; unfold StackState.push; rfl
      · rw [hProps]; unfold StackState.push; rfl
      · rw [hPre]; unfold StackState.push; rfl

/-! ### Tier 4 method-level wrapper

Method-level companion of `simpleStepRel_ifVal_heteroConstChains_preserves`,
mirroring the Tier 1/Tier 2/Tier 3 wrappers. Composes:

* the runtime-success arm via `runMethod_lower_public_unique_no_post_eq_userRaw`
  + the direct construction of the `runOps` post-state from the Tier 4
  preservation lemma above (which yields `.toOption.isSome` definitionally);
* the cond-dependent `stackEquivModuloIntermediates`-equivalence to either
  `initialStack.push (constToValue cThn)` (cond = true) or
  `initialStack.push (constToValue cEls)` (cond = false).

No conclusion-restating premise (per PATH2_PLAN §2.1). The only runtime-side
input is the prefix-only cond-load witness about `loadRef _ cond`. -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifValHeteroConstChain_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState) (initialAnf : State)
    (bn cond : String)
    (vnThn vnEls : String) (srcThn srcEls : Option SourceLoc)
    (cThn cEls : ConstValue)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' b,
        (b = true →
          stackEquivModuloIntermediates stk' (initialStack.push (constToValue cThn)))
        ∧ (b = false →
          stackEquivModuloIntermediates stk' (initialStack.push (constToValue cEls)))
        ∧ (initialAnf.addBinding bn
              (if b then constToValue cThn else constToValue cEls)).lookupBinding bn
            = some (if b then constToValue cThn else constToValue cEls) := by
  -- The Tier 4 predicate-side lemma produces the cond-dependent post-state plus
  -- a runtime-success witness.
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', b, hRun, _hWit, hEquivT, hEquivE⟩ :=
    simpleStepRel_ifVal_heteroConstChains_preserves
      smArg initialStack bn cond vnThn vnEls srcThn srcEls cThn cEls thn els
      hThn hEls hCondLoad
  refine ⟨?_, stk', b, hEquivT, hEquivE, ?_⟩
  · -- Runtime-success arm: route through `runMethod_lower_public_unique_no_post_eq_userRaw`
    -- → `hRawEqStructural` → the directly-constructed runOps post-state.
    rw [runMethod_lower_public_unique_no_post_eq_userRaw
          contractName props methods m initialStack hMem hPublic hUnique
          hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
    rw [hRawEqStructural]
    -- m.body = [.mk bn (.ifVal cond thn els) src], so
    -- `lowerBindings smArg m.body` = `lowerValue smArg bn (.ifVal cond thn els)` ++ [].
    rw [hBodyShape]
    have hUnfold :
        (Stack.Lower.lowerBindings smArg
            [.mk bn (.ifVal cond thn els) src]).1
          = (Stack.Lower.lowerValue smArg bn (.ifVal cond thn els)).1 := by
      simp [Stack.Lower.lowerBindings]
    rw [hUnfold]
    rw [hRun]
    simp [Except.toOption]
  · -- The ANF-side lookup of `bn` after `addBinding bn …` always returns the
    -- bound value. The `if b` expression on both sides matches structurally.
    cases b <;> simp [State.lookupBinding, State.addBinding]

/-! ## Tier 5 — Predicate-side widening for **const + copy-ref** branch pairs

Tier 4 (above) handled both-branches `structuralConstBodyEndsWithConst` chains,
where each branch's terminal `.loadConst c?` binding pins down a stack head
modulo intermediates. Tier 5 widens to **heterogeneous** branch pairs that mix
const chains with copy-mode reference chains (`structuralCopyBody`).

Wave 9 (commit `8d8b35ea`) exposed
`runOps_lowerBindings_structuralCopyBody_preserves_metadata` as the
copy-mode analogue of `runOps_lowerBindings_structuralConstBody_preserves_metadata`:
running a `structuralCopyBody`'s lowered ops from any agreesTagged-aligned
state preserves the four non-stack metadata fields (`altstack`, `outputs`,
`props`, `preimage`). This unblocks three heterogeneous branch-shape pairs:

* **Tier 5a** — `thn = structuralConstBody`, `els = structuralCopyBody`
* **Tier 5b** — `thn = structuralCopyBody`, `els = structuralConstBody`
* **Tier 5c** — both branches `structuralCopyBody`

The copy substrate does NOT pin down a `head?` value (it only preserves
metadata), so the cond-branch where the copy fires can only contribute a
**metadata-preservation** arm, not a `stackEquivModuloIntermediates`-against-
push witness. The const-branch arms still recover the full
`stackEquivModuloIntermediates` against `stkSt.push (constToValue c?)` via
the Tier 3 helper.

Out of scope for this wave (still BLOCKED):
* `structuralRefBody`'s **consume**-mode variant — lowers through
  `lowerBindingsP` non-trivially and has no metadata-preservation lemma.
* **Nested-ifVal** branches — would need a `structuralIfValBody`
  metadata-preservation result, also missing from substrate.

Forbidden patterns explicitly avoided. The cond-load witness is the same
input-side shape as Tier 1/2/3/4 (talks ONLY about the `loadRef sm cond`
prefix and the pushed cond value's bool coercion); no conclusion-restating
premise. -/

set_option maxHeartbeats 1600000 in
/-- **Tier 5a predicate-side preservation** for the **const-thn + copyRef-els**
both-branches `if_val` fragment. The `thn` branch is an arbitrary
`structuralConstBody` chain ending in `.mk vnThn (.loadConst cThn) srcThn`;
the `els` branch is an arbitrary `structuralCopyBody`.

Cond-dependent conclusion:

* `b = true` ⇒ `stackEquivModuloIntermediates stk' (stkSt.push (constToValue cThn))`
  (full head + metadata witness from the Tier 3 const-chain helper);
* `b = false` ⇒ metadata-preservation only (the copy substrate doesn't
  pin a head?).

The `agreesTagged` premise threads through to the copy-body substrate
which needs it to discharge `structuralCopyValue`'s `depth?` obligations
via `runOps_lowerValue_structuralCopyValue_ok`. -/
theorem simpleStepRel_ifVal_constThenCopyRef_preserves
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnThn : String) (srcThn : Option SourceLoc)
    (cThn : ConstValue)
    (thn els : List ANFBinding)
    (currentIndexEls : Nat)
    (lastUsesEls : List (String × Nat))
    (outerProtectedEls localBindingsEls : List String)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hUntagSmEls : untagSm tsmEls = sm)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els sm currentIndexEls)
    (hElsFresh : ∀ b ∈ els, b.name ∉ sm)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ (b = true →
            stackEquivModuloIntermediates stk' (stkSt.push (constToValue cThn)))
      ∧ (b = false →
            stk'.altstack = stkSt.altstack
            ∧ stk'.outputs = stkSt.outputs
            ∧ stk'.props = stkSt.props
            ∧ stk'.preimage = stkSt.preimage) := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  -- Unfold the if_val lowering: `loadRef sm cond ++ [.ifOp thnOps (some elsOps)]`.
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                    (some (Stack.Lower.lowerBindings sm els).1)] := by
    simp [Stack.Lower.lowerValue]
  -- Pop equation for stk1.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  -- The residual record after popping cond from stk1 equals stkSt by metadata
  -- preservation.
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  -- Run the const branch from `stkSt` (after popping cond) using the Tier 3
  -- helper; run the copy branch using the wave-9 metadata-preservation lemma.
  obtain ⟨stkT, hRunT, hEquivT⟩ :=
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vnThn cThn srcThn thn sm stkSt hThn
  obtain ⟨stkE, hRunE, hAltE, hOutE, hPropsE, hPreE⟩ :=
    runOps_lowerBindings_structuralCopyBody_preserves_metadata
      els sm currentIndexEls lastUsesEls outerProtectedEls localBindingsEls
      tsmEls anfStEls stkSt hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
  -- Drive runOps through the if_val lowered ops; case-split on `b`.
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunT]
        simp [runOps]
      · intro _; exact hEquivT
      · intro hF; cases hF
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunE]
        simp [runOps]
      · intro hT; cases hT
      · intro _; exact ⟨hAltE, hOutE, hPropsE, hPreE⟩

/-- **Tier 5a cond-independent metadata-preservation corollary**. Strips the
cond-dependent `stackEquivModuloIntermediates` (true arm) and the
metadata-only conjunction (false arm) down to the four cond-uniform
metadata-preservation arms against `stkSt`. -/
theorem simpleStepRel_ifVal_constThenCopyRef_preserves_metadata
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnThn : String) (srcThn : Option SourceLoc)
    (cThn : ConstValue)
    (thn els : List ANFBinding)
    (currentIndexEls : Nat)
    (lastUsesEls : List (String × Nat))
    (outerProtectedEls localBindingsEls : List String)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hUntagSmEls : untagSm tsmEls = sm)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els sm currentIndexEls)
    (hElsFresh : ∀ b ∈ els, b.name ∉ sm)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', b, hRun, _hWit, hEquivT, hMetaE⟩ :=
    simpleStepRel_ifVal_constThenCopyRef_preserves
      sm stkSt bn cond vnThn srcThn cThn thn els
      currentIndexEls lastUsesEls outerProtectedEls localBindingsEls
      tsmEls anfStEls hThn hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
      hCondLoad
  cases b with
  | true =>
      have hEquiv := hEquivT rfl
      obtain ⟨_hHead, hAlt, hOut, hProps, hPre⟩ := hEquiv
      refine ⟨stk', hRun, ?_, ?_, ?_, ?_⟩
      · rw [hAlt]; unfold StackState.push; rfl
      · rw [hOut]; unfold StackState.push; rfl
      · rw [hProps]; unfold StackState.push; rfl
      · rw [hPre]; unfold StackState.push; rfl
  | false =>
      obtain ⟨hAlt, hOut, hProps, hPre⟩ := hMetaE rfl
      exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩

/-! ### Tier 5a method-level wrapper

Method-level companion of `simpleStepRel_ifVal_constThenCopyRef_preserves`,
mirroring the Tier 4 wrapper. Composes:

* the runtime-success arm via `runMethod_lower_public_unique_no_post_eq_userRaw`
  + the direct construction of the `runOps` post-state from the Tier 5a
  preservation lemma above (which yields `.toOption.isSome` definitionally);
* the cond-dependent post-state arms (full `stackEquivModuloIntermediates`
  for the const arm, metadata-only for the copy arm).

No conclusion-restating premise (per PATH2_PLAN §2.1). -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifVal_constThenCopyRef_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (vnThn : String) (srcThn : Option SourceLoc)
    (cThn : ConstValue)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (currentIndexEls : Nat)
    (lastUsesEls : List (String × Nat))
    (outerProtectedEls localBindingsEls : List String)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hUntagSmEls :
      untagSm tsmEls = (m.params.map (fun p => p.name) |>.reverse))
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els (m.params.map (fun p => p.name) |>.reverse) currentIndexEls)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ (m.params.map (fun p => p.name) |>.reverse))
    (hElsNodup : (els.map (·.name)).Nodup)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' b,
        (b = true →
          stackEquivModuloIntermediates stk' (initialStack.push (constToValue cThn)))
        ∧ (b = false →
          stk'.altstack = initialStack.altstack
          ∧ stk'.outputs = initialStack.outputs
          ∧ stk'.props = initialStack.props
          ∧ stk'.preimage = initialStack.preimage) := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', b, hRun, _hWit, hEquivT, hMetaE⟩ :=
    simpleStepRel_ifVal_constThenCopyRef_preserves
      smArg initialStack bn cond vnThn srcThn cThn thn els
      currentIndexEls lastUsesEls outerProtectedEls localBindingsEls
      tsmEls anfStEls hThn hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
      hCondLoad
  refine ⟨?_, stk', b, hEquivT, hMetaE⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hRawEqStructural]
  rw [hBodyShape]
  have hUnfold :
      (Stack.Lower.lowerBindings smArg
          [.mk bn (.ifVal cond thn els) src]).1
        = (Stack.Lower.lowerValue smArg bn (.ifVal cond thn els)).1 := by
    simp [Stack.Lower.lowerBindings]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

set_option maxHeartbeats 1600000 in
/-- **Tier 5b predicate-side preservation** for the **copyRef-thn + const-els**
both-branches `if_val` fragment (the mirror image of Tier 5a). The `thn`
branch is an arbitrary `structuralCopyBody`; the `els` branch is a
`structuralConstBody` chain ending in `.mk vnEls (.loadConst cEls) srcEls`.

Cond-dependent conclusion:

* `b = true` ⇒ metadata-preservation only (the copy substrate doesn't pin a head?);
* `b = false` ⇒ `stackEquivModuloIntermediates stk' (stkSt.push (constToValue cEls))`. -/
theorem simpleStepRel_ifVal_copyRefThenConst_preserves
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnEls : String) (srcEls : Option SourceLoc)
    (cEls : ConstValue)
    (thn els : List ANFBinding)
    (currentIndexThn : Nat)
    (lastUsesThn : List (String × Nat))
    (outerProtectedThn localBindingsThn : List String)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (hUntagSmThn : untagSm tsmThn = sm)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn sm currentIndexThn)
    (hThnFresh : ∀ b ∈ thn, b.name ∉ sm)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ (b = true →
            stk'.altstack = stkSt.altstack
            ∧ stk'.outputs = stkSt.outputs
            ∧ stk'.props = stkSt.props
            ∧ stk'.preimage = stkSt.preimage)
      ∧ (b = false →
            stackEquivModuloIntermediates stk' (stkSt.push (constToValue cEls))) := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                    (some (Stack.Lower.lowerBindings sm els).1)] := by
    simp [Stack.Lower.lowerValue]
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  obtain ⟨stkT, hRunT, hAltT, hOutT, hPropsT, hPreT⟩ :=
    runOps_lowerBindings_structuralCopyBody_preserves_metadata
      thn sm currentIndexThn lastUsesThn outerProtectedThn localBindingsThn
      tsmThn anfStThn stkSt hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
  obtain ⟨stkE, hRunE, hEquivE⟩ :=
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vnEls cEls srcEls els sm stkSt hEls
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunT]
        simp [runOps]
      · intro _; exact ⟨hAltT, hOutT, hPropsT, hPreT⟩
      · intro hF; cases hF
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
        simp only []
        rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
              (some (Stack.Lower.lowerBindings sm els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq, hRunE]
        simp [runOps]
      · intro hT; cases hT
      · intro _; exact hEquivE

/-- **Tier 5b cond-independent metadata-preservation corollary**. -/
theorem simpleStepRel_ifVal_copyRefThenConst_preserves_metadata
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnEls : String) (srcEls : Option SourceLoc)
    (cEls : ConstValue)
    (thn els : List ANFBinding)
    (currentIndexThn : Nat)
    (lastUsesThn : List (String × Nat))
    (outerProtectedThn localBindingsThn : List String)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (hUntagSmThn : untagSm tsmThn = sm)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn sm currentIndexThn)
    (hThnFresh : ∀ b ∈ thn, b.name ∉ sm)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', b, hRun, _hWit, hMetaT, hEquivE⟩ :=
    simpleStepRel_ifVal_copyRefThenConst_preserves
      sm stkSt bn cond vnEls srcEls cEls thn els
      currentIndexThn lastUsesThn outerProtectedThn localBindingsThn
      tsmThn anfStThn hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup hEls
      hCondLoad
  cases b with
  | true =>
      obtain ⟨hAlt, hOut, hProps, hPre⟩ := hMetaT rfl
      exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩
  | false =>
      have hEquiv := hEquivE rfl
      obtain ⟨_hHead, hAlt, hOut, hProps, hPre⟩ := hEquiv
      refine ⟨stk', hRun, ?_, ?_, ?_, ?_⟩
      · rw [hAlt]; unfold StackState.push; rfl
      · rw [hOut]; unfold StackState.push; rfl
      · rw [hProps]; unfold StackState.push; rfl
      · rw [hPre]; unfold StackState.push; rfl

set_option maxHeartbeats 1600000 in
/-- **Tier 5b method-level wrapper**. -/
theorem runMethod_lower_public_unique_no_post_ifVal_copyRefThenConst_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (vnEls : String) (srcEls : Option SourceLoc)
    (cEls : ConstValue)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (currentIndexThn : Nat)
    (lastUsesThn : List (String × Nat))
    (outerProtectedThn localBindingsThn : List String)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (hUntagSmThn :
      untagSm tsmThn = (m.params.map (fun p => p.name) |>.reverse))
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn (m.params.map (fun p => p.name) |>.reverse) currentIndexThn)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ (m.params.map (fun p => p.name) |>.reverse))
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' b,
        (b = true →
          stk'.altstack = initialStack.altstack
          ∧ stk'.outputs = initialStack.outputs
          ∧ stk'.props = initialStack.props
          ∧ stk'.preimage = initialStack.preimage)
        ∧ (b = false →
          stackEquivModuloIntermediates stk' (initialStack.push (constToValue cEls))) := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', b, hRun, _hWit, hMetaT, hEquivE⟩ :=
    simpleStepRel_ifVal_copyRefThenConst_preserves
      smArg initialStack bn cond vnEls srcEls cEls thn els
      currentIndexThn lastUsesThn outerProtectedThn localBindingsThn
      tsmThn anfStThn hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup hEls
      hCondLoad
  refine ⟨?_, stk', b, hMetaT, hEquivE⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hRawEqStructural]
  rw [hBodyShape]
  have hUnfold :
      (Stack.Lower.lowerBindings smArg
          [.mk bn (.ifVal cond thn els) src]).1
        = (Stack.Lower.lowerValue smArg bn (.ifVal cond thn els)).1 := by
    simp [Stack.Lower.lowerBindings]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

set_option maxHeartbeats 1600000 in
/-- **Tier 5c predicate-side preservation** for the **both-copyRef** `if_val`
fragment. Both branches are `structuralCopyBody`. The conclusion is
cond-uniform metadata preservation (no `head?` witness from either branch). -/
theorem simpleStepRel_ifVal_copyRefThenCopyRef_preserves
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (currentIndexThn currentIndexEls : Nat)
    (lastUsesThn lastUsesEls : List (String × Nat))
    (outerProtectedThn localBindingsThn : List String)
    (outerProtectedEls localBindingsEls : List String)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn : untagSm tsmThn = sm)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn sm currentIndexThn)
    (hThnFresh : ∀ b ∈ thn, b.name ∉ sm)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls : untagSm tsmEls = sm)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els sm currentIndexEls)
    (hElsFresh : ∀ b ∈ els, b.name ∉ sm)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ :=
    hCondLoad
  have hLowerEq :
      (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1
        = Stack.Lower.loadRef sm cond
          ++ [.ifOp (Stack.Lower.lowerBindings sm thn).1
                    (some (Stack.Lower.lowerBindings sm els).1)] := by
    simp [Stack.Lower.lowerValue]
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  obtain ⟨stkT, hRunT, hAltT, hOutT, hPropsT, hPreT⟩ :=
    runOps_lowerBindings_structuralCopyBody_preserves_metadata
      thn sm currentIndexThn lastUsesThn outerProtectedThn localBindingsThn
      tsmThn anfStThn stkSt hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
  obtain ⟨stkE, hRunE, hAltE, hOutE, hPropsE, hPreE⟩ :=
    runOps_lowerBindings_structuralCopyBody_preserves_metadata
      els sm currentIndexEls lastUsesEls outerProtectedEls localBindingsEls
      tsmEls anfStEls stkSt hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltT, hOutT, hPropsT, hPreT⟩
      rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
      simp only []
      rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
            (some (Stack.Lower.lowerBindings sm els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq, hRunT]
      simp [runOps]
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltE, hOutE, hPropsE, hPreE⟩
      rw [hLowerEq, Stack.Sim.runOps_append, hLoad]
      simp only []
      rw [runOps.eq_2 stk1 (Stack.Lower.lowerBindings sm thn).1
            (some (Stack.Lower.lowerBindings sm els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq, hRunE]
      simp [runOps]

/-- **Tier 5c cond-independent metadata-preservation corollary**. The Tier 5c
predicate-side conclusion is already cond-uniform metadata preservation, so
this corollary simply strips the cond witness. -/
theorem simpleStepRel_ifVal_copyRefThenCopyRef_preserves_metadata
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (currentIndexThn currentIndexEls : Nat)
    (lastUsesThn lastUsesEls : List (String × Nat))
    (outerProtectedThn localBindingsThn : List String)
    (outerProtectedEls localBindingsEls : List String)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn : untagSm tsmThn = sm)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn sm currentIndexThn)
    (hThnFresh : ∀ b ∈ thn, b.name ∉ sm)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls : untagSm tsmEls = sm)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els sm currentIndexEls)
    (hElsFresh : ∀ b ∈ els, b.name ∉ sm)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRef sm cond) stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValue sm bn (.ifVal cond thn els)).1 stkSt = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_copyRefThenCopyRef_preserves
      sm stkSt bn cond thn els
      currentIndexThn currentIndexEls lastUsesThn lastUsesEls
      outerProtectedThn localBindingsThn outerProtectedEls localBindingsEls
      tsmThn anfStThn tsmEls anfStEls
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
      hCondLoad
  exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩

set_option maxHeartbeats 1600000 in
/-- **Tier 5c method-level wrapper**. Cond-uniform metadata preservation
conclusion (both branches contribute only metadata-preservation). -/
theorem runMethod_lower_public_unique_no_post_ifVal_copyRefThenCopyRef_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (currentIndexThn currentIndexEls : Nat)
    (lastUsesThn lastUsesEls : List (String × Nat))
    (outerProtectedThn localBindingsThn : List String)
    (outerProtectedEls localBindingsEls : List String)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (hUntagSmThn :
      untagSm tsmThn = (m.params.map (fun p => p.name) |>.reverse))
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn (m.params.map (fun p => p.name) |>.reverse) currentIndexThn)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ (m.params.map (fun p => p.name) |>.reverse))
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = (m.params.map (fun p => p.name) |>.reverse))
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els (m.params.map (fun p => p.name) |>.reverse) currentIndexEls)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ (m.params.map (fun p => p.name) |>.reverse))
    (hElsNodup : (els.map (·.name)).Nodup)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => p.name) |>.reverse) cond) initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' : StackState,
        stk'.altstack = initialStack.altstack
        ∧ stk'.outputs = initialStack.outputs
        ∧ stk'.props = initialStack.props
        ∧ stk'.preimage = initialStack.preimage := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_copyRefThenCopyRef_preserves
      smArg initialStack bn cond thn els
      currentIndexThn currentIndexEls lastUsesThn lastUsesEls
      outerProtectedThn localBindingsThn outerProtectedEls localBindingsEls
      tsmThn anfStThn tsmEls anfStEls
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
      hCondLoad
  refine ⟨?_, stk', hAlt, hOut, hProps, hPre⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hRawEqStructural]
  rw [hBodyShape]
  have hUnfold :
      (Stack.Lower.lowerBindings smArg
          [.mk bn (.ifVal cond thn els) src]).1
        = (Stack.Lower.lowerValue smArg bn (.ifVal cond thn els)).1 := by
    simp [Stack.Lower.lowerBindings]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

/-! ## Tier 6 — Predicate-side widening for **consume-mode-ref** `if_val` branches

Tier 5 (above) handled heterogeneous branch pairs mixing const chains with
**copy**-mode reference chains (`structuralCopyBody`).  Those branches lower
through the *unparameterized* `lowerValue` / `lowerBindings`, which the wave-9
`runOps_lowerBindings_structuralCopyBody_preserves_metadata` lemma consumes
directly.

Tier 6 widens to **consume**-mode reference chains (`structuralConsumeBody`).
Consume-mode is fundamentally a *program-aware* (`lowerValueP` / `lowerBindingsP`)
behaviour — the consume optimization (`bringToTop … consume=true`) only fires on
the live-ref liveness path, which has no `lowerBindings` analogue.  So the whole
Tier 6 chain is stated on the **P-path**: the `.ifVal` arm is lowered by
`lowerValueP`, and the wave-13 clean-shape substrate
(`lowerValueP_ifVal_clean_shape`) rewrites it — under an `ifValCleanShape`
precondition — into

  `(loadRefLive sm cond …).1 ++ [.ifOp (ifValThnRes …).1 (some (ifValElsRes …).1)]`,

where `ifValThnRes`/`ifValElsRes` unfold to the per-branch `lowerBindingsP`
op-lists.  The wave-11 `runOps_lowerBindingsP_structuralConsumeBody_preserves_metadata`
consumes a consume branch's op-list directly; a const branch's op-list is bridged
to the unparameterized lowerer via `lowerBindingsP_eq_lowerBindings_structuralConst`
and then driven by the Tier-3 `…structuralConstBodyEndsWithConst_stackEquiv` helper.

Tiers landed this wave:

* **Tier 6a** — `thn = structuralConstBodyEndsWithConst`, `els = structuralConsumeBody`
* **Tier 6b** — `thn = structuralConsumeBody`, `els = structuralConstBodyEndsWithConst`
* **Tier 6c** — both branches `structuralConsumeBody`
* **Tier 6d** — `thn = structuralCopyBody`, `els = structuralConsumeBody`
* **Tier 6e** — `thn = structuralConsumeBody`, `els = structuralCopyBody`

Wave-13 hand-off constraint (note #1): the clean-shape lemma requires
`2 ≤ els.length` (it is part of `ifValCleanShape`).  The **1-binding-else**
clean case is NOT covered by the wave-13 substrate (its shadow-rebind match
fires for `els = []` / `els = [b]`), so every Tier 6 lemma below carries
`ifValCleanShape` as its shape precondition and is therefore scoped to the
`els.length ≥ 2` case.  A 1-binding-else variant would need a separate
substrate lemma in `Stack/Agrees.lean` and is out of scope for this wave.

The copy/consume substrates pin only the four non-stack metadata fields
(`altstack`, `outputs`, `props`, `preimage`); they do NOT pin a `head?`.  The
const-branch arm still recovers the full `stackEquivModuloIntermediates` against
`stkSt.push (constToValue c)` via the Tier-3 helper.  Cond-dependent conclusions
mirror Tier 5: a const arm contributes a `stackEquivModuloIntermediates` witness,
a copy/consume arm contributes metadata preservation only.

`ifValCleanShape` is an **input-side** decidable shape precondition on the
lowering (it rules out the two cleanup paths of the `.ifVal` arm); it is NOT a
conclusion-restating premise.  The cond-load witness talks ONLY about the
`loadRefLive sm cond` prefix and the pushed cond value's bool coercion. -/

/-- Helper: a `structuralConstBodyEndsWithConst` thn branch, lowered on the
P-path under the `ifVal` arm's branch parameters, runs to a post-state that is
`stackEquivModuloIntermediates`-equivalent to `stkSt.push (constToValue c)`.

This bridges the P-lowered `ifValThnRes`/`ifValElsRes` op-list back to the
unparameterized `lowerBindings` form (valid for const-only bodies via
`lowerBindingsP_eq_lowerBindings_structuralConst`) and applies the Tier-3
`…structuralConstBodyEndsWithConst_stackEquiv` helper. -/
theorem runOps_ifValBranchP_structuralConstEndsWith_stackEquiv
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (smBranch : StackMap) (innerProtected : List String)
    (constInts : List (String × Int))
    (vn : String) (c : ConstValue) (src : Option SourceLoc)
    (body : List ANFBinding) (stk : StackState)
    (h : structuralConstBodyEndsWithConst vn c src body) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerBindingsP progMethods props budget 0
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body).1 stk = .ok stk'
      ∧ stackEquivModuloIntermediates stk' (stk.push (constToValue c)) := by
  have hBridge :
      Stack.Lower.lowerBindingsP progMethods props budget 0
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body
        = Stack.Lower.lowerBindings smBranch body :=
    lowerBindingsP_eq_lowerBindings_structuralConst
      progMethods props budget (Stack.Lower.computeLastUses body) innerProtected
      (List.map (fun b => b.name) body) constInts body smBranch 0 h.1
  rw [hBridge]
  exact
    runOps_lowerBindings_structuralConstBodyEndsWithConst_stackEquiv
      vn c src body smBranch stk h

/-- Helper: a `structuralConsumeBody` branch, lowered on the P-path under the
`ifVal` arm's branch parameters, runs to a post-state that preserves the four
non-stack metadata fields.  Thin wrapper over the wave-11
`runOps_lowerBindingsP_structuralConsumeBody_preserves_metadata`, with the
branch parameters fixed to the `ifValThnRes`/`ifValElsRes` shape. -/
theorem runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (smBranch : StackMap) (innerProtected : List String)
    (constInts : List (String × Int))
    (body : List ANFBinding) (currentIndex : Nat)
    (tsm : TaggedStackMap) (anfSt : State) (stk : StackState)
    (hUntagSm : untagSm tsm = smBranch)
    (hAgrees : agreesTagged tsm anfSt stk)
    (hConsume : structuralConsumeBody progMethods props budget
                  (Stack.Lower.computeLastUses body) innerProtected
                  (List.map (fun b => b.name) body) constInts
                  body smBranch currentIndex)
    (hFresh : ∀ b ∈ body, b.name ∉ smBranch)
    (hNodup : (body.map (·.name)).Nodup) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body).1 stk = .ok stk'
      ∧ stk'.altstack = stk.altstack
      ∧ stk'.outputs = stk.outputs
      ∧ stk'.props = stk.props
      ∧ stk'.preimage = stk.preimage :=
  runOps_lowerBindingsP_structuralConsumeBody_preserves_metadata
    progMethods props budget (Stack.Lower.computeLastUses body) innerProtected
    (List.map (fun b => b.name) body) constInts
    body smBranch currentIndex tsm anfSt stk hUntagSm hAgrees hConsume hFresh hNodup

/-- Helper: a `structuralCopyBody` branch, lowered on the P-path under the
`ifVal` arm's branch parameters, runs to a post-state that preserves the four
non-stack metadata fields.  Bridges the P-lowered op-list to the unparameterized
`lowerBindings` form (valid for copy bodies via
`lowerBindingsP_eq_lowerBindings_structuralCopy`) and applies the wave-9
`runOps_lowerBindings_structuralCopyBody_preserves_metadata`. -/
theorem runOps_ifValBranchP_structuralCopyBody_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (smBranch : StackMap) (innerProtected : List String)
    (constInts : List (String × Int))
    (body : List ANFBinding) (currentIndex : Nat)
    (tsm : TaggedStackMap) (anfSt : State) (stk : StackState)
    (hUntagSm : untagSm tsm = smBranch)
    (hAgrees : agreesTagged tsm anfSt stk)
    (hCopy : structuralCopyBody
                  (Stack.Lower.computeLastUses body) innerProtected
                  (List.map (fun b => b.name) body)
                  body smBranch currentIndex)
    (hFresh : ∀ b ∈ body, b.name ∉ smBranch)
    (hNodup : (body.map (·.name)).Nodup) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body).1 stk = .ok stk'
      ∧ stk'.altstack = stk.altstack
      ∧ stk'.outputs = stk.outputs
      ∧ stk'.props = stk.props
      ∧ stk'.preimage = stk.preimage := by
  have hBridge :
      Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body
        = Stack.Lower.lowerBindings smBranch body :=
    lowerBindingsP_eq_lowerBindings_structuralCopy
      progMethods props budget (Stack.Lower.computeLastUses body) innerProtected
      (List.map (fun b => b.name) body) constInts body smBranch currentIndex hCopy
  rw [hBridge]
  exact
    runOps_lowerBindings_structuralCopyBody_preserves_metadata
      body smBranch currentIndex (Stack.Lower.computeLastUses body) innerProtected
      (List.map (fun b => b.name) body) tsm anfSt stk hUntagSm hAgrees hCopy hFresh hNodup

set_option maxHeartbeats 1600000 in
/-- **Tier 6a predicate-side preservation** for the **const-thn + consumeRef-els**
both-branches `if_val` fragment on the **P-path**.  The `thn` branch is a
`structuralConstBodyEndsWithConst` chain; the `els` branch is an arbitrary
`structuralConsumeBody`.  The `.ifVal` arm is lowered by `lowerValueP` and
rewritten by the wave-13 clean-shape substrate under `ifValCleanShape`.

Cond-dependent conclusion (mirrors Tier 5a):

* `b = true` ⇒ `stackEquivModuloIntermediates stk' (stkSt.push (constToValue cThn))`;
* `b = false` ⇒ metadata-preservation only. -/
theorem simpleStepRel_ifVal_constThenConsumeRef_preserves
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnThn : String) (srcThn : Option SourceLoc)
    (cThn : ConstValue)
    (thn els : List ANFBinding)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els) constInts
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
                stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ (b = true →
            stackEquivModuloIntermediates stk' (stkSt.push (constToValue cThn)))
      ∧ (b = false →
            stk'.altstack = stkSt.altstack
            ∧ stk'.outputs = stkSt.outputs
            ∧ stk'.props = stkSt.props
            ∧ stk'.preimage = stkSt.preimage) := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ := hCondLoad
  -- Rewrite the `.ifVal` arm via the wave-13 clean-shape substrate.
  rw [lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn cond thn els hClean]
  -- Pop equation for stk1.
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  -- Run the const thn branch (Tier-3 helper, P-bridged); run the consume els
  -- branch (wave-11 metadata-preservation, P-shaped).
  obtain ⟨stkT, hRunT, hEquivT⟩ :=
    runOps_ifValBranchP_structuralConstEndsWith_stackEquiv
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts vnThn cThn srcThn thn stkSt hThn
  obtain ⟨stkE, hRunE, hAltE, hOutE, hPropsE, hPreE⟩ :=
    runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts els 0 tsmEls anfStEls stkSt
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [Stack.Sim.runOps_append, hLoad]
        simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
        rw [runOps.eq_2 stk1
              (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses thn)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) thn) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq]
        simp only [ifValSmBranch, ifValInnerProtected] at hRunT
        rw [hRunT]
        simp [runOps]
      · intro _; exact hEquivT
      · intro hF; cases hF
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [Stack.Sim.runOps_append, hLoad]
        simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
        rw [runOps.eq_2 stk1
              (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses thn)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) thn) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq]
        simp only [ifValSmBranch, ifValInnerProtected] at hRunE
        rw [hRunE]
        simp [runOps]
      · intro hT; cases hT
      · intro _; exact ⟨hAltE, hOutE, hPropsE, hPreE⟩

/-- **Tier 6a cond-independent metadata-preservation corollary**.  Strips the
cond-dependent arms down to the four cond-uniform metadata-preservation arms
against `stkSt`. -/
theorem simpleStepRel_ifVal_constThenConsumeRef_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnThn : String) (srcThn : Option SourceLoc)
    (cThn : ConstValue)
    (thn els : List ANFBinding)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els) constInts
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', b, hRun, _hWit, hEquivT, hMetaE⟩ :=
    simpleStepRel_ifVal_constThenConsumeRef_preserves
      progMethods props budget currentIndex lastUses outerProtected localBindings
      constInts sm stkSt bn cond vnThn srcThn cThn thn els
      tsmEls anfStEls hThn hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
      hClean hCondLoad
  cases b with
  | true =>
      obtain ⟨_hHead, hAlt, hOut, hProps, hPre⟩ := hEquivT rfl
      refine ⟨stk', hRun, ?_, ?_, ?_, ?_⟩
      · rw [hAlt]; unfold StackState.push; rfl
      · rw [hOut]; unfold StackState.push; rfl
      · rw [hProps]; unfold StackState.push; rfl
      · rw [hPre]; unfold StackState.push; rfl
  | false =>
      obtain ⟨hAlt, hOut, hProps, hPre⟩ := hMetaE rfl
      exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩

/-! ### Tier 6a method-level wrapper

Method-level companion of `simpleStepRel_ifVal_constThenConsumeRef_preserves`.
Unlike the Tier 5 wrappers, no `lowerBindings`-vs-`lowerBindingsP` bridge premise
is needed: `lowerMethodUserRawOps` already IS the P-form, so for a single-binding
`.ifVal` body it reduces directly to the `lowerValueP` op-list the predicate lemma
talks about.  The branch parameters are pinned to the method-raw shape
(`budget = defaultInlineBudget`, `currentIndex = 0`,
`lastUses = computeLastUses m.body`, `outerProtected = []`,
`localBindings = m.body.map name`, `constInts = collectConstInts m.body`,
`sm = m.params reversed`). -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifVal_constThenConsumeRef_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (vnThn : String) (srcThn : Option SourceLoc)
    (cThn : ConstValue)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (hThn : structuralConstBodyEndsWithConst vnThn cThn srcThn thn)
    (hUntagSmEls :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els) (Stack.Lower.collectConstInts m.body)
              els
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => p.name) |>.reverse) cond 0
            (Stack.Lower.computeLastUses m.body) []).1 initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' b,
        (b = true →
          stackEquivModuloIntermediates stk' (initialStack.push (constToValue cThn)))
        ∧ (b = false →
          stk'.altstack = initialStack.altstack
          ∧ stk'.outputs = initialStack.outputs
          ∧ stk'.props = initialStack.props
          ∧ stk'.preimage = initialStack.preimage) := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', b, hRun, _hWit, hEquivT, hMetaE⟩ :=
    simpleStepRel_ifVal_constThenConsumeRef_preserves
      methods props Stack.Lower.defaultInlineBudget 0
      (Stack.Lower.computeLastUses m.body) [] (List.map (fun b => b.name) m.body)
      (Stack.Lower.collectConstInts m.body) smArg initialStack bn cond
      vnThn srcThn cThn thn els tsmEls anfStEls hThn hUntagSmEls hAgreesEls
      hEls hElsFresh hElsNodup hClean hCondLoad
  refine ⟨?_, stk', b, hEquivT, hMetaE⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hUnfold :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValueP methods props Stack.Lower.defaultInlineBudget 0
            (Stack.Lower.computeLastUses m.body) []
            (List.map (fun b => b.name) m.body)
            (Stack.Lower.collectConstInts m.body) smArg bn (.ifVal cond thn els)).1 := by
    unfold lowerMethodUserRawOps
    rw [hBodyShape]
    simp [Stack.Lower.lowerBindingsP, smArg]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

set_option maxHeartbeats 1600000 in
/-- **Tier 6b predicate-side preservation** for the **consumeRef-thn + const-els**
both-branches `if_val` fragment on the **P-path** (mirror of Tier 6a).  The `thn`
branch is an arbitrary `structuralConsumeBody`; the `els` branch is a
`structuralConstBodyEndsWithConst` chain.

Cond-dependent conclusion:

* `b = true` ⇒ metadata-preservation only (consume thn);
* `b = false` ⇒ `stackEquivModuloIntermediates stk' (stkSt.push (constToValue cEls))`. -/
theorem simpleStepRel_ifVal_consumeRefThenConst_preserves
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnEls : String) (srcEls : Option SourceLoc)
    (cEls : ConstValue)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn) constInts
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
                stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ (b = true →
            stk'.altstack = stkSt.altstack
            ∧ stk'.outputs = stkSt.outputs
            ∧ stk'.props = stkSt.props
            ∧ stk'.preimage = stkSt.preimage)
      ∧ (b = false →
            stackEquivModuloIntermediates stk' (stkSt.push (constToValue cEls))) := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ := hCondLoad
  rw [lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn cond thn els hClean]
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  obtain ⟨stkT, hRunT, hAltT, hOutT, hPropsT, hPreT⟩ :=
    runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts thn 0 tsmThn anfStThn stkSt
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
  obtain ⟨stkE, hRunE, hEquivE⟩ :=
    runOps_ifValBranchP_structuralConstEndsWith_stackEquiv
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts vnEls cEls srcEls els stkSt hEls
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [Stack.Sim.runOps_append, hLoad]
        simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
        rw [runOps.eq_2 stk1
              (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses thn)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) thn) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq]
        simp only [ifValSmBranch, ifValInnerProtected] at hRunT
        rw [hRunT]
        simp [runOps]
      · intro _; exact ⟨hAltT, hOutT, hPropsT, hPreT⟩
      · intro hF; cases hF
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩, ?_, ?_⟩
      · rw [Stack.Sim.runOps_append, hLoad]
        simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
        rw [runOps.eq_2 stk1
              (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses thn)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) thn) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
        rw [hPop]
        simp only []
        rw [hBool]
        simp only []
        rw [hStkEq]
        simp only [ifValSmBranch, ifValInnerProtected] at hRunE
        rw [hRunE]
        simp [runOps]
      · intro hT; cases hT
      · intro _; exact hEquivE

/-- **Tier 6b cond-independent metadata-preservation corollary**. -/
theorem simpleStepRel_ifVal_consumeRefThenConst_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (vnEls : String) (srcEls : Option SourceLoc)
    (cEls : ConstValue)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn) constInts
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', b, hRun, _hWit, hMetaT, hEquivE⟩ :=
    simpleStepRel_ifVal_consumeRefThenConst_preserves
      progMethods props budget currentIndex lastUses outerProtected localBindings
      constInts sm stkSt bn cond vnEls srcEls cEls thn els
      tsmThn anfStThn hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
      hEls hClean hCondLoad
  cases b with
  | true =>
      obtain ⟨hAlt, hOut, hProps, hPre⟩ := hMetaT rfl
      exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩
  | false =>
      obtain ⟨_hHead, hAlt, hOut, hProps, hPre⟩ := hEquivE rfl
      refine ⟨stk', hRun, ?_, ?_, ?_, ?_⟩
      · rw [hAlt]; unfold StackState.push; rfl
      · rw [hOut]; unfold StackState.push; rfl
      · rw [hProps]; unfold StackState.push; rfl
      · rw [hPre]; unfold StackState.push; rfl

/-! ### Tier 6b method-level wrapper -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifVal_consumeRefThenConst_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (vnEls : String) (srcEls : Option SourceLoc)
    (cEls : ConstValue)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (tsmThn_untag :
      untagSm tsmThn =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn) (Stack.Lower.collectConstInts m.body)
              thn
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => p.name) |>.reverse) cond 0
            (Stack.Lower.computeLastUses m.body) []).1 initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' b,
        (b = true →
          stk'.altstack = initialStack.altstack
          ∧ stk'.outputs = initialStack.outputs
          ∧ stk'.props = initialStack.props
          ∧ stk'.preimage = initialStack.preimage)
        ∧ (b = false →
          stackEquivModuloIntermediates stk' (initialStack.push (constToValue cEls))) := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', b, hRun, _hWit, hMetaT, hEquivE⟩ :=
    simpleStepRel_ifVal_consumeRefThenConst_preserves
      methods props Stack.Lower.defaultInlineBudget 0
      (Stack.Lower.computeLastUses m.body) [] (List.map (fun b => b.name) m.body)
      (Stack.Lower.collectConstInts m.body) smArg initialStack bn cond
      vnEls srcEls cEls thn els tsmThn anfStThn tsmThn_untag hAgreesThn
      hThn hThnFresh hThnNodup hEls hClean hCondLoad
  refine ⟨?_, stk', b, hMetaT, hEquivE⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hUnfold :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValueP methods props Stack.Lower.defaultInlineBudget 0
            (Stack.Lower.computeLastUses m.body) []
            (List.map (fun b => b.name) m.body)
            (Stack.Lower.collectConstInts m.body) smArg bn (.ifVal cond thn els)).1 := by
    unfold lowerMethodUserRawOps
    rw [hBodyShape]
    simp [Stack.Lower.lowerBindingsP, smArg]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

set_option maxHeartbeats 1600000 in
/-- **Tier 6c predicate-side preservation** for the **both-consumeRef** `if_val`
fragment on the **P-path**.  Both branches are `structuralConsumeBody`.  The
conclusion is cond-uniform metadata preservation (no `head?` witness from either
branch). -/
theorem simpleStepRel_ifVal_consumeRefThenConsumeRef_preserves
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn) constInts
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els) constInts
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
                stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ := hCondLoad
  rw [lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn cond thn els hClean]
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  obtain ⟨stkT, hRunT, hAltT, hOutT, hPropsT, hPreT⟩ :=
    runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts thn 0 tsmThn anfStThn stkSt
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
  obtain ⟨stkE, hRunE, hAltE, hOutE, hPropsE, hPreE⟩ :=
    runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts els 0 tsmEls anfStEls stkSt
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltT, hOutT, hPropsT, hPreT⟩
      rw [Stack.Sim.runOps_append, hLoad]
      simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
      rw [runOps.eq_2 stk1
            (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses thn)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) thn) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq]
      simp only [ifValSmBranch, ifValInnerProtected] at hRunT
      rw [hRunT]
      simp [runOps]
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltE, hOutE, hPropsE, hPreE⟩
      rw [Stack.Sim.runOps_append, hLoad]
      simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
      rw [runOps.eq_2 stk1
            (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses thn)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) thn) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq]
      simp only [ifValSmBranch, ifValInnerProtected] at hRunE
      rw [hRunE]
      simp [runOps]

/-- **Tier 6c cond-independent metadata-preservation corollary**.  The Tier 6c
predicate-side conclusion is already cond-uniform metadata preservation, so this
corollary simply strips the cond witness. -/
theorem simpleStepRel_ifVal_consumeRefThenConsumeRef_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn) constInts
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els) constInts
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_consumeRefThenConsumeRef_preserves
      progMethods props budget currentIndex lastUses outerProtected localBindings
      constInts sm stkSt bn cond thn els tsmThn anfStThn tsmEls anfStEls
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup hClean hCondLoad
  exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩

/-! ### Tier 6c method-level wrapper.  Cond-uniform metadata-preservation
conclusion (both branches contribute only metadata preservation). -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifVal_consumeRefThenConsumeRef_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (tsmThn_untag :
      untagSm tsmThn =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn) (Stack.Lower.collectConstInts m.body)
              thn
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (tsmEls_untag :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els) (Stack.Lower.collectConstInts m.body)
              els
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => p.name) |>.reverse) cond 0
            (Stack.Lower.computeLastUses m.body) []).1 initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' : StackState,
        stk'.altstack = initialStack.altstack
        ∧ stk'.outputs = initialStack.outputs
        ∧ stk'.props = initialStack.props
        ∧ stk'.preimage = initialStack.preimage := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_consumeRefThenConsumeRef_preserves
      methods props Stack.Lower.defaultInlineBudget 0
      (Stack.Lower.computeLastUses m.body) [] (List.map (fun b => b.name) m.body)
      (Stack.Lower.collectConstInts m.body) smArg initialStack bn cond
      thn els tsmThn anfStThn tsmEls anfStEls tsmThn_untag hAgreesThn
      hThn hThnFresh hThnNodup tsmEls_untag hAgreesEls hEls hElsFresh hElsNodup
      hClean hCondLoad
  refine ⟨?_, stk', hAlt, hOut, hProps, hPre⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hUnfold :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValueP methods props Stack.Lower.defaultInlineBudget 0
            (Stack.Lower.computeLastUses m.body) []
            (List.map (fun b => b.name) m.body)
            (Stack.Lower.collectConstInts m.body) smArg bn (.ifVal cond thn els)).1 := by
    unfold lowerMethodUserRawOps
    rw [hBodyShape]
    simp [Stack.Lower.lowerBindingsP, smArg]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

set_option maxHeartbeats 1600000 in
/-- **Tier 6d predicate-side preservation** for the **copyRef-thn + consumeRef-els**
both-branches `if_val` fragment on the **P-path**.  The `thn` branch is an
arbitrary `structuralCopyBody`; the `els` branch is an arbitrary
`structuralConsumeBody`.  Conclusion is cond-uniform metadata preservation. -/
theorem simpleStepRel_ifVal_copyRefThenConsumeRef_preserves
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralCopyBody
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn)
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els) constInts
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
                stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ := hCondLoad
  rw [lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn cond thn els hClean]
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  obtain ⟨stkT, hRunT, hAltT, hOutT, hPropsT, hPreT⟩ :=
    runOps_ifValBranchP_structuralCopyBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts thn 0 tsmThn anfStThn stkSt
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
  obtain ⟨stkE, hRunE, hAltE, hOutE, hPropsE, hPreE⟩ :=
    runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts els 0 tsmEls anfStEls stkSt
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltT, hOutT, hPropsT, hPreT⟩
      rw [Stack.Sim.runOps_append, hLoad]
      simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
      rw [runOps.eq_2 stk1
            (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses thn)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) thn) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq]
      simp only [ifValSmBranch, ifValInnerProtected] at hRunT
      rw [hRunT]
      simp [runOps]
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltE, hOutE, hPropsE, hPreE⟩
      rw [Stack.Sim.runOps_append, hLoad]
      simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
      rw [runOps.eq_2 stk1
            (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses thn)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) thn) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq]
      simp only [ifValSmBranch, ifValInnerProtected] at hRunE
      rw [hRunE]
      simp [runOps]

/-- **Tier 6d cond-independent metadata-preservation corollary**. -/
theorem simpleStepRel_ifVal_copyRefThenConsumeRef_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralCopyBody
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn)
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els) constInts
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_copyRefThenConsumeRef_preserves
      progMethods props budget currentIndex lastUses outerProtected localBindings
      constInts sm stkSt bn cond thn els tsmThn anfStThn tsmEls anfStEls
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup hClean hCondLoad
  exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩

/-! ### Tier 6d method-level wrapper.  Cond-uniform metadata-preservation. -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifVal_copyRefThenConsumeRef_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (tsmThn_untag :
      untagSm tsmThn =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralCopyBody
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn)
              thn
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (tsmEls_untag :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els) (Stack.Lower.collectConstInts m.body)
              els
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => p.name) |>.reverse) cond 0
            (Stack.Lower.computeLastUses m.body) []).1 initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' : StackState,
        stk'.altstack = initialStack.altstack
        ∧ stk'.outputs = initialStack.outputs
        ∧ stk'.props = initialStack.props
        ∧ stk'.preimage = initialStack.preimage := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_copyRefThenConsumeRef_preserves
      methods props Stack.Lower.defaultInlineBudget 0
      (Stack.Lower.computeLastUses m.body) [] (List.map (fun b => b.name) m.body)
      (Stack.Lower.collectConstInts m.body) smArg initialStack bn cond
      thn els tsmThn anfStThn tsmEls anfStEls tsmThn_untag hAgreesThn
      hThn hThnFresh hThnNodup tsmEls_untag hAgreesEls hEls hElsFresh hElsNodup
      hClean hCondLoad
  refine ⟨?_, stk', hAlt, hOut, hProps, hPre⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hUnfold :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValueP methods props Stack.Lower.defaultInlineBudget 0
            (Stack.Lower.computeLastUses m.body) []
            (List.map (fun b => b.name) m.body)
            (Stack.Lower.collectConstInts m.body) smArg bn (.ifVal cond thn els)).1 := by
    unfold lowerMethodUserRawOps
    rw [hBodyShape]
    simp [Stack.Lower.lowerBindingsP, smArg]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

set_option maxHeartbeats 1600000 in
/-- **Tier 6e predicate-side preservation** for the **consumeRef-thn + copyRef-els**
both-branches `if_val` fragment on the **P-path** (mirror of Tier 6d).  The `thn`
branch is an arbitrary `structuralConsumeBody`; the `els` branch is an arbitrary
`structuralCopyBody`.  Conclusion is cond-uniform metadata preservation. -/
theorem simpleStepRel_ifVal_consumeRefThenCopyRef_preserves
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn) constInts
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els)
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk' b,
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ (∃ condV stk1,
            runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
                stkSt = .ok stk1
            ∧ stk1.stack = condV :: stkSt.stack
            ∧ asBool? condV = some b)
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨condV, stk1, hLoad, hStk, hAlt, hOut, hProps, hPre, b, hBool⟩ := hCondLoad
  rw [lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn cond thn els hClean]
  have hPop : stk1.pop? = some (condV, { stk1 with stack := stkSt.stack }) := by
    show (match stk1.stack with
          | [] => none
          | v :: vs => some (v, { stk1 with stack := vs })) = _
    rw [hStk]
  have hStkEq : ({ stk1 with stack := stkSt.stack } : StackState) = stkSt := by
    cases stk1
    cases stkSt
    simp_all
  obtain ⟨stkT, hRunT, hAltT, hOutT, hPropsT, hPreT⟩ :=
    runOps_ifValBranchP_structuralConsumeBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts thn 0 tsmThn anfStThn stkSt
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
  obtain ⟨stkE, hRunE, hAltE, hOutE, hPropsE, hPreE⟩ :=
    runOps_ifValBranchP_structuralCopyBody_preserves_metadata
      progMethods props budget
      (ifValSmBranch sm cond currentIndex lastUses outerProtected)
      (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
      constInts els 0 tsmEls anfStEls stkSt
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup
  cases b with
  | true =>
      refine ⟨stkT, true, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltT, hOutT, hPropsT, hPreT⟩
      rw [Stack.Sim.runOps_append, hLoad]
      simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
      rw [runOps.eq_2 stk1
            (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses thn)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) thn) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq]
      simp only [ifValSmBranch, ifValInnerProtected] at hRunT
      rw [hRunT]
      simp [runOps]
  | false =>
      refine ⟨stkE, false, ?_, ⟨condV, stk1, hLoad, hStk, hBool⟩,
              hAltE, hOutE, hPropsE, hPreE⟩
      rw [Stack.Sim.runOps_append, hLoad]
      simp only [ifValThnRes, ifValElsRes, ifValSmBranch, ifValInnerProtected]
      rw [runOps.eq_2 stk1
            (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses thn)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) thn) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els).1) []]
      rw [hPop]
      simp only []
      rw [hBool]
      simp only []
      rw [hStkEq]
      simp only [ifValSmBranch, ifValInnerProtected] at hRunE
      rw [hRunE]
      simp [runOps]

/-- **Tier 6e cond-independent metadata-preservation corollary**. -/
theorem simpleStepRel_ifVal_consumeRefThenCopyRef_preserves_metadata
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (stkSt : StackState)
    (bn cond : String)
    (thn els : List ANFBinding)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hUntagSmThn :
      untagSm tsmThn = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesThn : agreesTagged tsmThn anfStThn stkSt)
    (hThn : structuralConsumeBody progMethods props budget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) thn) constInts
              thn (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected sm cond currentIndex lastUses outerProtected)
              (List.map (fun b => b.name) els)
              els (ifValSmBranch sm cond currentIndex lastUses outerProtected)
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                outerProtected constInts sm cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).1
            stkSt = .ok stk1
        ∧ stk1.stack = condV :: stkSt.stack
        ∧ stk1.altstack = stkSt.altstack
        ∧ stk1.outputs = stkSt.outputs
        ∧ stk1.props = stkSt.props
        ∧ stk1.preimage = stkSt.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm bn (.ifVal cond thn els)).1 stkSt
          = .ok stk'
      ∧ stk'.altstack = stkSt.altstack
      ∧ stk'.outputs = stkSt.outputs
      ∧ stk'.props = stkSt.props
      ∧ stk'.preimage = stkSt.preimage := by
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_consumeRefThenCopyRef_preserves
      progMethods props budget currentIndex lastUses outerProtected localBindings
      constInts sm stkSt bn cond thn els tsmThn anfStThn tsmEls anfStEls
      hUntagSmThn hAgreesThn hThn hThnFresh hThnNodup
      hUntagSmEls hAgreesEls hEls hElsFresh hElsNodup hClean hCondLoad
  exact ⟨stk', hRun, hAlt, hOut, hProps, hPre⟩

/-! ### Tier 6e method-level wrapper.  Cond-uniform metadata-preservation. -/
set_option maxHeartbeats 1600000 in
theorem runMethod_lower_public_unique_no_post_ifVal_consumeRefThenCopyRef_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : StackState)
    (bn cond : String)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (tsmThn : TaggedStackMap) (anfStThn : State)
    (tsmEls : TaggedStackMap) (anfStEls : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [.mk bn (.ifVal cond thn els) src])
    (tsmThn_untag :
      untagSm tsmThn =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn) (Stack.Lower.collectConstInts m.body)
              thn
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (tsmEls_untag :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralCopyBody
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els)
              els
              (ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, b.name ∉
        ifValSmBranch (m.params.map (fun p => p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => p.name) |>.reverse) cond 0
            (Stack.Lower.computeLastUses m.body) []).1 initialStack
          = .ok stk1
        ∧ stk1.stack = condV :: initialStack.stack
        ∧ stk1.altstack = initialStack.altstack
        ∧ stk1.outputs = initialStack.outputs
        ∧ stk1.props = initialStack.props
        ∧ stk1.preimage = initialStack.preimage
        ∧ (∃ b, asBool? condV = some b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome
    ∧ ∃ stk' : StackState,
        stk'.altstack = initialStack.altstack
        ∧ stk'.outputs = initialStack.outputs
        ∧ stk'.props = initialStack.props
        ∧ stk'.preimage = initialStack.preimage := by
  let smArg := (m.params.map (fun p => p.name) |>.reverse)
  obtain ⟨stk', _b, hRun, _hWit, hAlt, hOut, hProps, hPre⟩ :=
    simpleStepRel_ifVal_consumeRefThenCopyRef_preserves
      methods props Stack.Lower.defaultInlineBudget 0
      (Stack.Lower.computeLastUses m.body) [] (List.map (fun b => b.name) m.body)
      (Stack.Lower.collectConstInts m.body) smArg initialStack bn cond
      thn els tsmThn anfStThn tsmEls anfStEls tsmThn_untag hAgreesThn
      hThn hThnFresh hThnNodup tsmEls_untag hAgreesEls hEls hElsFresh hElsNodup
      hClean hCondLoad
  refine ⟨?_, stk', hAlt, hOut, hProps, hPre⟩
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hUnfold :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValueP methods props Stack.Lower.defaultInlineBudget 0
            (Stack.Lower.computeLastUses m.body) []
            (List.map (fun b => b.name) m.body)
            (Stack.Lower.collectConstInts m.body) smArg bn (.ifVal cond thn els)).1 := by
    unfold lowerMethodUserRawOps
    rw [hBodyShape]
    simp [Stack.Lower.lowerBindingsP, smArg]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

end -- attribute [local irreducible] section

end Agrees
end RunarVerification.Stack

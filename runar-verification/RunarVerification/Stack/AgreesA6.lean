import RunarVerification.Stack.Agrees
import RunarVerification.Stack.AgreesA3

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
  | [.mk _ (.ifVal _ thn els _) _] =>
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
        | ifVal _ _ _ _ => simp at hHead
        | loop _ _ _ _ _ => simp at hHead
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
        | ifVal _ _ _ _ => simp [structuralConstValue] at hHead
        | loop _ _ _ _ _ => simp [structuralConstValue] at hHead
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
  | [.mk _ (.ifVal _ thn els _) _] =>
      structuralConstBodyB thn && structuralConstBodyB els
  | _ => false

theorem structuralIfValBodyNarrowB_iff (body : List ANFBinding) :
    structuralIfValBodyNarrowB body = true ↔ structuralIfValBodyNarrow body := by
  match body with
  | [] => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
  | [.mk name v src] =>
      cases v with
      | ifVal _ thn els _ =>
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
      | loop _ _ _ _ _ => simp [structuralIfValBodyNarrowB, structuralIfValBodyNarrow]
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
      ∀ bn cond thn els results src,
        body = [.mk bn (.ifVal cond thn els results) src] →
        ∃ condV stk1,
          runOps (Stack.Lower.loadRef sm cond) stk = .ok stk1
          ∧ stk1.stack = condV :: stk.stack
          ∧ (∃ b, asBool? condV = some b)) :
    (runOps (Stack.Lower.lowerBindings sm body).1 stk).toOption.isSome := by
  match body, hBody with
  | [.mk bn (.ifVal cond thn els results) src], hBody =>
      obtain ⟨hThn, hEls⟩ := hBody
      have hWit := hCondLoad bn cond thn els results src rfl
      -- `lowerBindings sm [single-ifVal]` unfolds to the lowerValue ops ++ [].
      have hUnfold :
          (Stack.Lower.lowerBindings sm
              [.mk bn (.ifVal cond thn els results) src]).1
            = (Stack.Lower.lowerValue sm bn (.ifVal cond thn els results)).1 := by
        simp [Stack.Lower.lowerBindings]
      rw [hUnfold]
      -- `lowerValue sm bn (.ifVal cond thn els)` =
      --   `(loadRef sm cond ++ [.ifOp thnOps (some elsOps)], sm.push bn)`.
      have hLowerEq :
          (Stack.Lower.lowerValue sm bn (.ifVal cond thn els results)).1
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
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∀ bn cond thn els results src,
        m.body = [.mk bn (.ifVal cond thn els results) src] →
        ∃ condV stk1,
          runOps
            (Stack.Lower.loadRef
              (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
    m.body (m.params.map (fun p => some p.name) |>.reverse) initialStack hBody hCondLoad

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

/-! ## Wave 40 — `if_val` foundational lemma: arith-branch iff transport

The arith sub-omnibus (wave 39) was retired by the per-binding lockstep
walk `agreesTagged_arith_walk_iff` (in `Stack/AgreesA3.lean`), which
turns the all-bigint typed-entry invariant into a body-level
`successAgrees` iff for an `emittableArithChainReady` body.  The walk is
the value-dependent core that A6's earlier DEFERRED note flagged as the
real blocker for `if_val` (the branch bodies need the same
value-dependent success/failure discharge that arith just solved).

This wave lands the FIRST reusable `if_val` piece on top of that walk:
the **branch-selection iff transport**.  Given

* the ANF condition resolves to a known `.vBool b`,
* a Script-side cond-load witness that pushes a bool-coercible `condV`
  with the SAME truth value `b` on top of the post-load branch stack
  `branchStk`, and
* the per-branch arith walk iffs (the exact output of
  `agreesTagged_arith_walk_iff` applied to each branch body against
  `branchStk`),

the lemma transports the iff across Bitcoin's `OP_IF`: the ANF
`evalValue (.ifVal cond thn els)` succeeds iff the lowered
`loadRef sm cond ++ [.ifOp thnOps elsOps]` succeeds.  Only the ACTIVE
branch's iff is consumed (the inactive branch is never run on either
side), so the transport is `cases b` followed by the matching per-branch
iff.

The two per-branch iff premises are input-side (they are produced by the
arith walk, never by inspecting the `.ifOp` conclusion) — no
conclusion-restating hypothesis (PATH2_PLAN §2.1).  This is the analogue
of the arith per-binding step, lifted to the conditional: the remaining
A6 retirement pieces (the both-branch op-shape via `AreRunarEmittableWithIf`,
the `agreesTagged` cond-load discharge, and the dispatch assembly) compose
ON TOP of this transport, exactly as the arith walk + op-shape + shape
composed for wave 39. -/

/-- **ANF-side branch reduction.**  When the condition resolves to a known
`.vBool b`, the success bit of `evalValue (.ifVal cond thn els)` is exactly
the success bit of running the active branch's `evalBindings`.  The
post-branch `getLast?` lookups never fail (every arm returns `.ok`), so
they do not affect the `isSome` projection. -/
theorem evalValue_ifVal_isSome_iff_activeBranch
    (anfSt : State) (cond : String) (thn els : List ANFBinding) (b : Bool)
    (hCond : anfSt.resolveRef cond = some (.vBool b)) :
    (RunarVerification.ANF.Eval.evalValue anfSt (.ifVal cond thn els)).toOption.isSome ↔
    (if b then (RunarVerification.ANF.Eval.evalBindings anfSt thn).toOption.isSome
          else (RunarVerification.ANF.Eval.evalBindings anfSt els).toOption.isSome) := by
  have hLk : RunarVerification.ANF.Eval.lookupRef anfSt cond
      = .ok (.vBool b) := by
    simp only [RunarVerification.ANF.Eval.lookupRef, hCond]
  -- Reduce `evalValue (.ifVal …)` through the cond-lookup to the active
  -- branch's `evalBindings`, then a getLast?-driven post-processing that
  -- never fails.  The success bit equals the active branch's success bit.
  have hEq :
      (RunarVerification.ANF.Eval.evalValue anfSt (.ifVal cond thn els)).toOption.isSome
        = (if b then (RunarVerification.ANF.Eval.evalBindings anfSt thn).toOption.isSome
                else (RunarVerification.ANF.Eval.evalBindings anfSt els).toOption.isSome) := by
    cases b with
    | true =>
        rw [if_pos (rfl : (true = true))]
        simp only [RunarVerification.ANF.Eval.evalValue, hLk, bind, Except.bind]
        cases hRun : RunarVerification.ANF.Eval.evalBindings anfSt thn with
        | error e => simp only [Except.toOption, Option.isSome]
        | ok s' =>
            cases thn.getLast? with
            | none => simp only [Except.toOption, Option.isSome]
            | some lb =>
                cases hLb : s'.lookupBinding lb.name with
                | none => simp only [hLb, Except.toOption, Option.isSome]
                | some v => simp only [hLb, pure, Except.pure, Except.toOption, Option.isSome]
    | false =>
        rw [if_neg (by decide : ¬ ((false : Bool) = true))]
        simp only [RunarVerification.ANF.Eval.evalValue, hLk, bind, Except.bind]
        cases hRun : RunarVerification.ANF.Eval.evalBindings anfSt els with
        | error e => simp only [Except.toOption, Option.isSome]
        | ok s' =>
            cases els.getLast? with
            | none => simp only [Except.toOption, Option.isSome]
            | some lb =>
                cases hLb : s'.lookupBinding lb.name with
                | none => simp only [hLb, Except.toOption, Option.isSome]
                | some v => simp only [hLb, pure, Except.pure, Except.toOption, Option.isSome]
  rw [hEq]

/-- **Script-side branch reduction.**  When the cond-load prefix runs to a
stack whose new top `condV` is bool-coercible to `b`, the success bit of
`condOps ++ [.ifOp thnOps elsOps]` is exactly the success bit of running
the active branch's ops against the post-pop stack `branchStk`. -/
theorem runOps_ifVal_isSome_iff_activeBranch
    (condOps thnOps : List StackOp) (elsOps : Option (List StackOp))
    (stk branchStk : StackState) (condV : Value) (b : Bool)
    (hCondLoad :
      runOps condOps stk = .ok { branchStk with stack := condV :: branchStk.stack })
    (hBool : asBool? condV = some b) :
    (runOps (condOps ++ [.ifOp thnOps elsOps]) stk).toOption.isSome ↔
    (if b then (runOps thnOps branchStk).toOption.isSome
          else (match elsOps with
                | none => true
                | some e => (runOps e branchStk).toOption.isSome)) := by
  rw [Stack.Sim.runOps_append, hCondLoad]
  simp only []
  -- Goal: `(runOps [.ifOp thnOps elsOps] branchStk').toOption.isSome` where
  -- `branchStk' = { branchStk with stack := condV :: branchStk.stack }`.
  have hPop : ({ branchStk with stack := condV :: branchStk.stack } : StackState).pop?
      = some (condV, branchStk) := by
    show (match condV :: branchStk.stack with
          | [] => none
          | v :: vs => some (v, { branchStk with stack := vs })) = _
    rfl
  rw [runOps.eq_2 { branchStk with stack := condV :: branchStk.stack } thnOps elsOps []]
  rw [hPop]
  simp only []
  rw [hBool]
  cases b with
  | true =>
      dsimp only
      rw [if_pos (rfl : (true = true))]
      cases hT : runOps thnOps branchStk with
      | error e =>
          simp only [Except.toOption, Option.isSome]
      | ok s'' =>
          simp only [Stack.Eval.runOps_nil, Except.toOption, Option.isSome]
  | false =>
      dsimp only
      rw [if_neg (by decide : ¬ ((false : Bool) = true))]
      cases elsOps with
      | none =>
          dsimp only
          simp only [Stack.Eval.runOps_nil, Except.toOption, Option.isSome]
      | some e =>
          dsimp only
          cases hE : runOps e branchStk with
          | error err =>
              simp only [Except.toOption, Option.isSome]
          | ok s'' =>
              simp only [Stack.Eval.runOps_nil, Except.toOption, Option.isSome]

/-- **Wave 40 foundational lemma — `if_val` arith-branch iff transport.**

Composes the two branch reductions above with the per-branch arith walk
iffs.  Under a matched cond resolution (ANF `.vBool b` ⇔ Script
bool-coercible `condV`) and the per-branch arith walks, the
`evalValue (.ifVal cond thn els)` success bit equals the lowered
`condOps ++ [.ifOp thnOps elsOps]` success bit.  Only the active branch's
walk iff is consumed.

The `hThnIff` / `hElsIff` premises are precisely the iff that
`agreesTagged_arith_walk_iff` returns for each branch body lowered against
`branchStk`; the smoke test below feeds them from that walk. -/
theorem agreesTagged_ifVal_arith_iff
    (anfSt : State) (cond : String) (thn els : List ANFBinding)
    (condOps thnOps : List StackOp) (elsOps : Option (List StackOp))
    (stk branchStk : StackState) (condV : Value) (b : Bool)
    (hCond : anfSt.resolveRef cond = some (.vBool b))
    (hCondLoad :
      runOps condOps stk = .ok { branchStk with stack := condV :: branchStk.stack })
    (hBool : asBool? condV = some b)
    (hThnIff :
      (RunarVerification.ANF.Eval.evalBindings anfSt thn).toOption.isSome ↔
      (runOps thnOps branchStk).toOption.isSome)
    (hElsIff :
      ∀ e, elsOps = some e →
        ((RunarVerification.ANF.Eval.evalBindings anfSt els).toOption.isSome ↔
         (runOps e branchStk).toOption.isSome))
    (hElsNoneIff :
      elsOps = none →
        (RunarVerification.ANF.Eval.evalBindings anfSt els).toOption.isSome) :
    (RunarVerification.ANF.Eval.evalValue anfSt (.ifVal cond thn els)).toOption.isSome ↔
    (runOps (condOps ++ [.ifOp thnOps elsOps]) stk).toOption.isSome := by
  rw [evalValue_ifVal_isSome_iff_activeBranch anfSt cond thn els b hCond]
  rw [runOps_ifVal_isSome_iff_activeBranch condOps thnOps elsOps stk branchStk condV b
        hCondLoad hBool]
  cases b with
  | true =>
      rw [if_pos (rfl : (true = true))]
      exact hThnIff
  | false =>
      rw [if_neg (by decide : ¬ ((false : Bool) = true))]
      cases hE : elsOps with
      | none =>
          exact iff_of_true (hElsNoneIff hE) rfl
      | some e =>
          exact hElsIff e hE

/-! ### Wave 40 — MANDATORY smoke: `if_val` arith-branch transport FIRES

A concrete `if_val` whose THEN branch is the real single-binding arith
chain `t0 = p0 + p1` (`p0 = 3`, `p1 = 4`, both `.bigint`) and whose ELSE
branch is empty.  The THEN-branch iff is produced by the arith
deliverable `successAgrees_arith_consume_unconditional` (the wave-39
machinery, type-invariant DERIVED from typed entry — no `taggedAllBigint`
hypothesis), and `agreesTagged_ifVal_arith_iff` transports it across the
conditional.  We discharge both sides concretely (the THEN branch
evaluates to a final bigint, so the active-branch ANF eval succeeds), so
the transported iff is `True ↔ True` — anti-vacuous: the arith branch is
genuinely run on both sides under the `OP_IF` selection. -/

/-- Smoke ANF state: condition `c = true`, params `p0 = 3`, `p1 = 4`. -/
private def w40SmokeAnf : State :=
  { params := [("c", .vBool true), ("p0", .vBigint 3), ("p1", .vBigint 4)] }

/-- Smoke branch stack (post cond-pop): `p0`, `p1` aligned. -/
private def w40SmokeBranchStk : StackState :=
  { stack := [.vBigint 3, .vBigint 4] }

/-- Smoke THEN branch: the single-binding arith chain `t0 = p0 + p1`. -/
private def w40SmokeThn : List ANFBinding :=
  [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none]

/-- Smoke tagged stack map for the branch entry: two `.param` slots. -/
private def w40SmokeTsm : TaggedStackMap :=
  [("p0", .param), ("p1", .param)]

/-- Smoke typing context: `p0`, `p1` declared `.bigint`. -/
private def w40SmokeEnv : RunarVerification.ANF.WellTyped.TypeEnv :=
  (RunarVerification.ANF.Typed.TypeEnv.empty.extend "p0" .bigint).extend "p1" .bigint

/-- The THEN-branch lowered ops (the real arith chunk under sm `["p0","p1"]`). -/
private def w40SmokeThnOps : List StackOp :=
  (Stack.Lower.lowerBindingsP [] [] 1000 0 (Stack.Lower.computeLastUses w40SmokeThn)
      [] [] [] ["p0", "p1"] w40SmokeThn).1

private theorem w40_untag : untagSm w40SmokeTsm = (["p0", "p1"] : Stack.Lower.StackMap) := by
  unfold w40SmokeTsm untagSm; rfl

private theorem w40_agreesTagged :
    agreesTagged w40SmokeTsm w40SmokeAnf w40SmokeBranchStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned w40SmokeTsm w40SmokeAnf w40SmokeBranchStk.stack
  refine ⟨?_, ?_, ?_⟩
  · show lookupAnfByKind w40SmokeAnf ("p0", .param) = some (.vBigint 3); rfl
  · show lookupAnfByKind w40SmokeAnf ("p1", .param) = some (.vBigint 4); rfl
  · trivial

private theorem w40_chainReady :
    emittableArithChainReady (Stack.Lower.computeLastUses w40SmokeThn) w40SmokeThn
      ["p0", "p1"] 0 := by
  unfold w40SmokeThn
  exact ⟨Or.inl rfl, by decide, by unfold freshIn; decide, True.intro⟩

private theorem w40_entryBigintTyped :
    RunarVerification.ANF.WellTyped.EntryBigintTyped w40SmokeEnv w40SmokeAnf := by
  intro n hn
  by_cases h0 : n = "p0"
  · subst h0; exact ⟨.vBigint 3, rfl, ⟨3, rfl⟩⟩
  · by_cases h1 : n = "p1"
    · subst h1; exact ⟨.vBigint 4, rfl, ⟨4, rfl⟩⟩
    · exfalso
      have hp1 : ("p1" == n) = false := by
        rw [beq_eq_false_iff_ne]; exact fun h => h1 h.symm
      have hp0 : ("p0" == n) = false := by
        rw [beq_eq_false_iff_ne]; exact fun h => h0 h.symm
      simp only [w40SmokeEnv, RunarVerification.ANF.Typed.TypeEnv.lookup,
        RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
        List.find?_cons, hp1, hp0, List.find?_nil, Option.map_none, reduceCtorEq] at hn

private theorem w40_entryTsmArithTyped :
    entryTsmArithTyped w40SmokeEnv w40SmokeTsm := by
  intro s hs
  unfold RunarVerification.ANF.WellTyped.arithOperandBigint
  simp only [w40SmokeTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with h | h <;> (subst h; decide)

private theorem w40_tsmCoherent :
    tsmCoherent w40SmokeAnf w40SmokeTsm := by
  intro s hs
  simp only [w40SmokeTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with h | h <;> (subst h; rfl)

/-- **Wave 40 smoke — the `if_val` arith-branch transport fires.**

(1) The per-branch arith walk iff (from the wave-39 deliverable).
(2) The transported `if_val` iff (from `agreesTagged_ifVal_arith_iff`).
(3) The ANF `evalValue (.ifVal …)` side concretely succeeds.
(4) Hence the Script `condOps ++ [.ifOp thnOps none]` side succeeds. -/
theorem wave40_ifVal_arith_transport_smoke :
    -- (2) the transported iff for the arith-then / empty-else if_val.
    ((RunarVerification.ANF.Eval.evalValue w40SmokeAnf
        (.ifVal "c" w40SmokeThn [])).toOption.isSome
      ↔ (runOps ([] ++ [.ifOp w40SmokeThnOps none])
            { w40SmokeBranchStk with stack := (.vBool true) :: w40SmokeBranchStk.stack
            }).toOption.isSome)
    -- (3) the ANF if_val side concretely succeeds.
    ∧ (RunarVerification.ANF.Eval.evalValue w40SmokeAnf
        (.ifVal "c" w40SmokeThn [])).toOption.isSome
    -- (4) hence the Script side succeeds.
    ∧ (runOps ([] ++ [.ifOp w40SmokeThnOps none])
          { w40SmokeBranchStk with stack := (.vBool true) :: w40SmokeBranchStk.stack
          }).toOption.isSome := by
  -- (1) The per-branch arith walk iff: ANF branch eval ↔ Script branch run.
  have hThnIff :
      (RunarVerification.ANF.Eval.evalBindings w40SmokeAnf w40SmokeThn).toOption.isSome ↔
      (runOps w40SmokeThnOps w40SmokeBranchStk).toOption.isSome :=
    successAgrees_arith_consume_unconditional [] [] 1000
      (Stack.Lower.computeLastUses w40SmokeThn) [] w40SmokeEnv
      w40SmokeThn ["p0", "p1"] [] 0 w40SmokeTsm
      w40SmokeAnf w40SmokeBranchStk
      w40_untag w40_agreesTagged w40_chainReady
      w40_entryBigintTyped w40_entryTsmArithTyped w40_tsmCoherent
  -- (2) Transport across the conditional.  cond resolves to `.vBool true`;
  -- the (trivial) cond-load runs `[]` to the bool-topped branch stack.
  have hCond : w40SmokeAnf.resolveRef "c" = some (.vBool true) := rfl
  have hCondLoad :
      runOps [] { w40SmokeBranchStk with stack := (.vBool true) :: w40SmokeBranchStk.stack }
        = .ok { w40SmokeBranchStk with
            stack := (.vBool true) :: w40SmokeBranchStk.stack } :=
    Stack.Eval.runOps_nil _
  have hElsNone :
      (none : Option (List StackOp)) = none →
        (RunarVerification.ANF.Eval.evalBindings w40SmokeAnf []).toOption.isSome := by
    intro _; simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  have hIff :=
    agreesTagged_ifVal_arith_iff w40SmokeAnf "c" w40SmokeThn [] [] w40SmokeThnOps none
      { w40SmokeBranchStk with stack := (.vBool true) :: w40SmokeBranchStk.stack }
      w40SmokeBranchStk (.vBool true) true
      hCond hCondLoad rfl hThnIff (fun e he => absurd he (by simp)) hElsNone
  -- (3) The ANF if_val side concretely succeeds (THEN branch evaluates the
  -- arith chain `t0 = 3 + 4 = 7`).
  have hANF :
      (RunarVerification.ANF.Eval.evalValue w40SmokeAnf
          (.ifVal "c" w40SmokeThn [])).toOption.isSome := by
    rw [evalValue_ifVal_isSome_iff_activeBranch w40SmokeAnf "c" w40SmokeThn [] true hCond]
    rw [if_pos (rfl : (true = true))]
    show (RunarVerification.ANF.Eval.evalBindings w40SmokeAnf
      [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isSome
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          w40SmokeAnf "t0" "+" "p0" "p1" none none 3 4 _ (Or.inl rfl) rfl rfl]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  exact ⟨hIff, hANF, hIff.mp hANF⟩

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
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hAgrees : agreesTagged initialTsm initialAnf initialStack)
    (hFresh : freshIn bn (untagSm initialTsm))
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
        ∀ bn' cond' thn' els' results' src',
          m.body = [.mk bn' (.ifVal cond' thn' els' results') src'] →
          ∃ condV stk1,
            runOps
              (Stack.Lower.loadRef
                (m.params.map (fun p => some p.name) |>.reverse) cond') initialStack
              = .ok stk1
            ∧ stk1.stack = condV :: initialStack.stack
            ∧ (∃ b, asBool? condV = some b) := by
      intro bn' cond' thn' els' results' src' hEq
      rw [hBodyShape] at hEq
      -- The matched single-element list-equality fixes
      -- bn' = bn, cond' = cond, etc.
      obtain ⟨condV, stk1, hLoad, hStk, _, _, _, _, hBool⟩ := hCondLoad
      injection hEq with hHead _
      injection hHead with _hName hVal _
      injection hVal with hCondEq _ _ _
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
        (m.params.map (fun p => some p.name) |>.reverse) initialTsm initialAnf
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
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hAgrees : agreesTagged initialTsm initialAnf initialStack)
    (hFresh : freshIn bn (untagSm initialTsm))
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
        ∀ bn' cond' thn' els' results' src',
          m.body = [.mk bn' (.ifVal cond' thn' els' results') src'] →
          ∃ condV stk1,
            runOps
              (Stack.Lower.loadRef
                (m.params.map (fun p => some p.name) |>.reverse) cond') initialStack
              = .ok stk1
            ∧ stk1.stack = condV :: initialStack.stack
            ∧ (∃ b, asBool? condV = some b) := by
      intro bn' cond' thn' els' results' src' hEq
      rw [hBodyShape] at hEq
      obtain ⟨condV, stk1, hLoad, hStk, _, _, _, _, hBool⟩ := hCondLoad
      injection hEq with hHead _
      injection hHead with _hName hVal _
      injection hVal with hCondEq _ _ _
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
        (m.params.map (fun p => some p.name) |>.reverse) initialTsm initialAnf
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
  | ifVal _ _ _ _ => simp [structuralConstValue] at hHead
  | loop _ _ _ _ _ => simp [structuralConstValue] at hHead
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
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
  let sm := (m.params.map (fun p => some p.name) |>.reverse)
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
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    (hElsFresh : ∀ b ∈ els, some b.name ∉ sm)
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
    (hElsFresh : ∀ b ∈ els, some b.name ∉ sm)
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
      untagSm tsmEls = (m.params.map (fun p => some p.name) |>.reverse))
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els (m.params.map (fun p => some p.name) |>.reverse) currentIndexEls)
    (hElsFresh :
      ∀ b ∈ els, some b.name ∉ (m.params.map (fun p => some p.name) |>.reverse))
    (hElsNodup : (els.map (·.name)).Nodup)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    (hThnFresh : ∀ b ∈ thn, some b.name ∉ sm)
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
    (hThnFresh : ∀ b ∈ thn, some b.name ∉ sm)
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
      untagSm tsmThn = (m.params.map (fun p => some p.name) |>.reverse))
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn (m.params.map (fun p => some p.name) |>.reverse) currentIndexThn)
    (hThnFresh :
      ∀ b ∈ thn, some b.name ∉ (m.params.map (fun p => some p.name) |>.reverse))
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    (hThnFresh : ∀ b ∈ thn, some b.name ∉ sm)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls : untagSm tsmEls = sm)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els sm currentIndexEls)
    (hElsFresh : ∀ b ∈ els, some b.name ∉ sm)
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
    (hThnFresh : ∀ b ∈ thn, some b.name ∉ sm)
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls : untagSm tsmEls = sm)
    (hAgreesEls : agreesTagged tsmEls anfStEls stkSt)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els sm currentIndexEls)
    (hElsFresh : ∀ b ∈ els, some b.name ∉ sm)
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
      untagSm tsmThn = (m.params.map (fun p => some p.name) |>.reverse))
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralCopyBody lastUsesThn outerProtectedThn localBindingsThn
              thn (m.params.map (fun p => some p.name) |>.reverse) currentIndexThn)
    (hThnFresh :
      ∀ b ∈ thn, some b.name ∉ (m.params.map (fun p => some p.name) |>.reverse))
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hUntagSmEls :
      untagSm tsmEls = (m.params.map (fun p => some p.name) |>.reverse))
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralCopyBody lastUsesEls outerProtectedEls localBindingsEls
              els (m.params.map (fun p => some p.name) |>.reverse) currentIndexEls)
    (hElsFresh :
      ∀ b ∈ els, some b.name ∉ (m.params.map (fun p => some p.name) |>.reverse))
    (hElsNodup : (els.map (·.name)).Nodup)
    (hRawEqStructural :
      lowerMethodUserRawOps methods props m =
        (Stack.Lower.lowerBindings
          (m.params.map (fun p => some p.name) |>.reverse) m.body).1)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRef
            (m.params.map (fun p => some p.name) |>.reverse) cond) initialStack
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
          (List.map (fun b => b.name) body) constInts smBranch body [] true).1 stk = .ok stk'
      ∧ stackEquivModuloIntermediates stk' (stk.push (constToValue c)) := by
  -- Issue #150: the arm lowers at `insideBranch = true`; a const body reads
  -- none of the four flag-sensitive constructors, so this is the default
  -- lowering and every bridge below applies unchanged.
  rw [lowerBindingsP_insideBranch_irrelevant progMethods props budget
    (Stack.Lower.computeLastUses body) innerProtected constInts [] true
    body (List.map (fun b => b.name) body) smBranch 0
    (insideBranchFreeBodyB_of_structuralConstBody body h.1)]
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
    (hFresh : ∀ b ∈ body, some b.name ∉ smBranch)
    (hNodup : (body.map (·.name)).Nodup) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body [] true).1 stk = .ok stk'
      ∧ stk'.altstack = stk.altstack
      ∧ stk'.outputs = stk.outputs
      ∧ stk'.props = stk.props
      ∧ stk'.preimage = stk.preimage := by
  -- Issue #150: consume bodies admit literals / `loadParam` / `@ref` only,
  -- none of which reads `insideBranch`, so the arm's `true` lowering is the
  -- default lowering the wave-11 lemma is stated at.
  rw [lowerBindingsP_insideBranch_irrelevant progMethods props budget
    (Stack.Lower.computeLastUses body) innerProtected constInts [] true
    body (List.map (fun b => b.name) body) smBranch currentIndex
    (insideBranchFreeBodyB_of_structuralConsumeBody progMethods props budget
      (Stack.Lower.computeLastUses body) innerProtected
      (List.map (fun b => b.name) body) constInts body smBranch currentIndex hConsume)]
  exact runOps_lowerBindingsP_structuralConsumeBody_preserves_metadata
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
    (hFresh : ∀ b ∈ body, some b.name ∉ smBranch)
    (hNodup : (body.map (·.name)).Nodup) :
    ∃ stk',
      runOps
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          (Stack.Lower.computeLastUses body) innerProtected
          (List.map (fun b => b.name) body) constInts smBranch body [] true).1 stk = .ok stk'
      ∧ stk'.altstack = stk.altstack
      ∧ stk'.outputs = stk.outputs
      ∧ stk'.props = stk.props
      ∧ stk'.preimage = stk.preimage := by
  -- Issue #150: copy bodies are flag-free, so the arm's `true` lowering is
  -- the default lowering the wave-9 bridge is stated at.
  rw [lowerBindingsP_insideBranch_irrelevant progMethods props budget
    (Stack.Lower.computeLastUses body) innerProtected constInts [] true
    body (List.map (fun b => b.name) body) smBranch currentIndex
    (insideBranchFreeBodyB_of_structuralCopyBody (Stack.Lower.computeLastUses body)
      innerProtected (List.map (fun b => b.name) body) body smBranch currentIndex hCopy)]
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els) (Stack.Lower.collectConstInts m.body)
              els
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => some p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => some p.name) |>.reverse) cond 0
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    -- NEW-004: neither arm of this `if` contains a byte-array
    -- producer, so the singleton body marks no raw slot.
    have hRawThn : Stack.Lower.collectRawSlotsGo [] thn = [] := by
      have := collectRawSlots_nil_of_structuralConstBody thn
        (structuralConstBodyEndsWithConst_implies_structuralConstBody _ _ _ _ hThn)
      simpa [Stack.Lower.collectRawSlots] using this
    have hRawEls : Stack.Lower.collectRawSlotsGo [] els = [] := by
      have := collectRawSlots_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hEls
      simpa [Stack.Lower.collectRawSlots] using this
    -- …and neither arm binds an `array_literal`.
    have hArrThn : Stack.Lower.arrayElemsOf thn = [] :=
      arrayElemsOf_nil_of_structuralConstBody thn
        (structuralConstBodyEndsWithConst_implies_structuralConstBody _ _ _ _ hThn)
    have hArrEls : Stack.Lower.arrayElemsOf els = [] :=
      arrayElemsOf_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hEls
    rw [Stack.Lower.collectRawSlots_singleton_ifVal_of_arms
          bn cond thn els _ src hRawThn hRawEls]
    simp [Stack.Lower.lowerBindingsP, smArg,
      Stack.Lower.arrayElemsOf, hArrThn, hArrEls]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
              (some (Stack.Lower.lowerBindingsP progMethods props budget 0
                (Stack.Lower.computeLastUses els)
                (Stack.Lower.computeBranchProtected
                  ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                  lastUses currentIndex outerProtected)
                (List.map (fun b => b.name) els) constInts
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn) (Stack.Lower.collectConstInts m.body)
              thn
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (hEls : structuralConstBodyEndsWithConst vnEls cEls srcEls els)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => some p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => some p.name) |>.reverse) cond 0
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    -- NEW-004: neither arm of this `if` contains a byte-array
    -- producer, so the singleton body marks no raw slot.
    have hRawThn : Stack.Lower.collectRawSlotsGo [] thn = [] := by
      have := collectRawSlots_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hThn
      simpa [Stack.Lower.collectRawSlots] using this
    have hRawEls : Stack.Lower.collectRawSlotsGo [] els = [] := by
      have := collectRawSlots_nil_of_structuralConstBody els
        (structuralConstBodyEndsWithConst_implies_structuralConstBody _ _ _ _ hEls)
      simpa [Stack.Lower.collectRawSlots] using this
    -- …and neither arm binds an `array_literal`.
    have hArrThn : Stack.Lower.arrayElemsOf thn = [] :=
      arrayElemsOf_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hThn
    have hArrEls : Stack.Lower.arrayElemsOf els = [] :=
      arrayElemsOf_nil_of_structuralConstBody els
        (structuralConstBodyEndsWithConst_implies_structuralConstBody _ _ _ _ hEls)
    rw [Stack.Lower.collectRawSlots_singleton_ifVal_of_arms
          bn cond thn els _ src hRawThn hRawEls]
    simp [Stack.Lower.lowerBindingsP, smArg,
      Stack.Lower.arrayElemsOf, hArrThn, hArrEls]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn) (Stack.Lower.collectConstInts m.body)
              thn
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (tsmEls_untag :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els) (Stack.Lower.collectConstInts m.body)
              els
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => some p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => some p.name) |>.reverse) cond 0
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    -- NEW-004: neither arm of this `if` contains a byte-array
    -- producer, so the singleton body marks no raw slot.
    have hRawThn : Stack.Lower.collectRawSlotsGo [] thn = [] := by
      have := collectRawSlots_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hThn
      simpa [Stack.Lower.collectRawSlots] using this
    have hRawEls : Stack.Lower.collectRawSlotsGo [] els = [] := by
      have := collectRawSlots_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hEls
      simpa [Stack.Lower.collectRawSlots] using this
    -- …and neither arm binds an `array_literal`.
    have hArrThn : Stack.Lower.arrayElemsOf thn = [] :=
      arrayElemsOf_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hThn
    have hArrEls : Stack.Lower.arrayElemsOf els = [] :=
      arrayElemsOf_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hEls
    rw [Stack.Lower.collectRawSlots_singleton_ifVal_of_arms
          bn cond thn els _ src hRawThn hRawEls]
    simp [Stack.Lower.lowerBindingsP, smArg,
      Stack.Lower.arrayElemsOf, hArrThn, hArrEls]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralCopyBody
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn)
              thn
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (tsmEls_untag :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els) (Stack.Lower.collectConstInts m.body)
              els
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => some p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => some p.name) |>.reverse) cond 0
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    -- NEW-004: neither arm of this `if` contains a byte-array
    -- producer, so the singleton body marks no raw slot.
    have hRawThn : Stack.Lower.collectRawSlotsGo [] thn = [] := by
      have := collectRawSlots_nil_of_structuralCopyBody _ _ _ _ _ _ hThn
      simpa [Stack.Lower.collectRawSlots] using this
    have hRawEls : Stack.Lower.collectRawSlotsGo [] els = [] := by
      have := collectRawSlots_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hEls
      simpa [Stack.Lower.collectRawSlots] using this
    -- …and neither arm binds an `array_literal`.
    have hArrThn : Stack.Lower.arrayElemsOf thn = [] :=
      arrayElemsOf_nil_of_structuralCopyBody _ _ _ _ _ _ hThn
    have hArrEls : Stack.Lower.arrayElemsOf els = [] :=
      arrayElemsOf_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hEls
    rw [Stack.Lower.collectRawSlots_singleton_ifVal_of_arms
          bn cond thn els _ src hRawThn hRawEls]
    simp [Stack.Lower.lowerBindingsP, smArg,
      Stack.Lower.arrayElemsOf, hArrThn, hArrEls]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) thn [] true).1
            (some (Stack.Lower.lowerBindingsP progMethods props budget 0
              (Stack.Lower.computeLastUses els)
              (Stack.Lower.computeBranchProtected
                ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1)
                lastUses currentIndex outerProtected)
              (List.map (fun b => b.name) els) constInts
              ((Stack.Lower.loadRefLive sm cond currentIndex lastUses outerProtected).2.popN 1) els [] true).1) []]
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
      ∀ b ∈ thn, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
      ∀ b ∈ els, some b.name ∉ ifValSmBranch sm cond currentIndex lastUses outerProtected)
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
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesThn : agreesTagged tsmThn anfStThn initialStack)
    (hThn : structuralConsumeBody methods props Stack.Lower.defaultInlineBudget
              (Stack.Lower.computeLastUses thn)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) thn) (Stack.Lower.collectConstInts m.body)
              thn
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hThnFresh :
      ∀ b ∈ thn, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hThnNodup : (thn.map (·.name)).Nodup)
    (tsmEls_untag :
      untagSm tsmEls =
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hAgreesEls : agreesTagged tsmEls anfStEls initialStack)
    (hEls : structuralCopyBody
              (Stack.Lower.computeLastUses els)
              (ifValInnerProtected (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              (List.map (fun b => b.name) els)
              els
              (ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
                (Stack.Lower.computeLastUses m.body) [])
              0)
    (hElsFresh :
      ∀ b ∈ els, some b.name ∉
        ifValSmBranch (m.params.map (fun p => some p.name) |>.reverse) cond 0
          (Stack.Lower.computeLastUses m.body) [])
    (hElsNodup : (els.map (·.name)).Nodup)
    (hClean : ifValCleanShape methods props Stack.Lower.defaultInlineBudget 0
                (Stack.Lower.computeLastUses m.body) []
                (Stack.Lower.collectConstInts m.body)
                (m.params.map (fun p => some p.name) |>.reverse) cond thn els)
    (hCondLoad :
      ∃ condV stk1,
        runOps
          (Stack.Lower.loadRefLive
            (m.params.map (fun p => some p.name) |>.reverse) cond 0
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
  let smArg := (m.params.map (fun p => some p.name) |>.reverse)
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
    -- NEW-004: neither arm of this `if` contains a byte-array
    -- producer, so the singleton body marks no raw slot.
    have hRawThn : Stack.Lower.collectRawSlotsGo [] thn = [] := by
      have := collectRawSlots_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hThn
      simpa [Stack.Lower.collectRawSlots] using this
    have hRawEls : Stack.Lower.collectRawSlotsGo [] els = [] := by
      have := collectRawSlots_nil_of_structuralCopyBody _ _ _ _ _ _ hEls
      simpa [Stack.Lower.collectRawSlots] using this
    -- …and neither arm binds an `array_literal`.
    have hArrThn : Stack.Lower.arrayElemsOf thn = [] :=
      arrayElemsOf_nil_of_structuralConsumeBody _ _ _ _ _ _ _ _ _ _ hThn
    have hArrEls : Stack.Lower.arrayElemsOf els = [] :=
      arrayElemsOf_nil_of_structuralCopyBody _ _ _ _ _ _ hEls
    rw [Stack.Lower.collectRawSlots_singleton_ifVal_of_arms
          bn cond thn els _ src hRawThn hRawEls]
    simp [Stack.Lower.lowerBindingsP, smArg,
      Stack.Lower.arrayElemsOf, hArrThn, hArrEls]
  rw [hUnfold]
  rw [hRun]
  simp [Except.toOption]

/-! ## Wave 41 — the `if_val` retirement substrate

This wave lands the four reusable substrate pieces the `if_val` codegen
retirement (86→85) assembles from, mirroring the wave-39 arith framework
(`successAgrees_arith_consume_unconditional` + `loweredEmittableArithNoDblNeg_opShape`
+ `instDecidableEmittableArithChainReadyNoDblNeg` →
`compileSafe_observational_correct_arith_consume`).

The fragment is a single `.ifVal` binding whose `thn` / `els` are each
`emittableArithChainReadyNoDblNeg` arith bodies, restricted to
**self-contained branches** (`ifValCleanShape`, the wave-13 substrate in
`Stack/Agrees.lean`): no parent-ref consumption, so the cleanup-tail /
shadow-rebind of `lowerValueP .ifVal` is empty and the lowering collapses
to `condOps ++ [.ifOp thnOps (some elsOps)]` via
`lowerValueP_ifVal_clean_shape`.

* **A** — `ifValArithBody` fragment predicate + Bool + decidability
  (`instDecidableIfValArithBody`).
* **B** — `ifValArithCondLoad` cond-load lemma (cond resolves to a `.vBool`
  on the ANF side and a bool-coercible Script value on top of the post-load
  stack, from `agreesTagged` + the cond being a bool-typed tagged slot).
* **C** — `successAgrees_ifVal_arith_unconditional` the body-level walk
  wrapper, composing `agreesTagged_ifVal_arith_iff` (wave 40) with the
  per-branch wave-35 arith walks + the clean-shape collapse.
* **D** — `loweredIfValArith_opShape` the `.ifOp`-bearing op-shape
  (`AreRunarEmittableWithIf` + the peephole-identity), the analogue of
  `loweredEmittableArithNoDblNeg_opShape`.
-/

/-! ### A — the `if_val` arith body fragment predicate + decidability -/

/-- `ifValCleanShape` is a conjunction of decidable atoms (a `Nat` ≤, two
list-equalities of `ifValDrops`, a length equality, and a `≠ []`); decide it
by unfolding to that conjunction. -/
instance instDecidableIfValCleanShape
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (constInts : List (String × Int))
    (sm : StackMap) (cond : String) (thn els : List ANFBinding) :
    Decidable (ifValCleanShape progMethods props budget currentIndex lastUses
      outerProtected constInts sm cond thn els) := by
  unfold ifValCleanShape
  infer_instance

/-- **Wave 41 A — `if_val` arith body fragment.**

A method body that is exactly one `.ifVal` binding whose condition is a
ref, and whose THEN / ELSE bodies are each `emittableArithChainReadyNoDblNeg`
arith chains lowered against the post-cond-pop branch stack
(`ifValSmBranch`), under the self-contained-branch `ifValCleanShape`
(so the lowering collapses to `condOps ++ [.ifOp thnOps (some elsOps)]`).

The `ifValCleanShape` conjunct is the wave-13 substrate predicate (decidable
and input-side: it talks only about the branch lowerings, never the
conclusion). The two arith-readiness conjuncts pin each branch to the
wave-38 emittable no-double-negate fragment, so each branch's per-binding
walk iff and op-shape are exactly the wave-35 / wave-38 deliverables. -/
def ifValArithBody
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (constInts : List (String × Int))
    (sm : StackMap) :
    List ANFBinding → Prop
  | [.mk _bn (.ifVal cond thn els []) _src] =>
      emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses thn) thn
        (ifValSmBranch sm cond currentIndex lastUses outerProtected) 0 false ∧
      emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses els) els
        (ifValSmBranch sm cond currentIndex lastUses outerProtected) 0 false ∧
      ifValCleanShape progMethods props budget currentIndex lastUses
        outerProtected constInts sm cond thn els
  | _ => False

/-- NEW-004: both arms of an `ifValArithBody` are emittable arith chains
(`+ - *` and unary `-`), so neither marks a raw slot and the singleton
value-`if` body marks none either. -/
theorem collectRawSlots_nil_of_ifValArithBody
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (constInts : List (String × Int))
    (sm : StackMap) :
    ∀ (body : List ANFBinding),
      ifValArithBody progMethods props budget currentIndex lastUses
        outerProtected constInts sm body →
      Stack.Lower.collectRawSlots body = [] := by
  intro body h
  match body, h with
  | [.mk bn (.ifVal cond thn els []) src], ⟨hThn, hEls, _⟩ =>
      have hRawThn : Stack.Lower.collectRawSlotsGo [] thn = [] := by
        have := collectRawSlots_nil_of_emittableArithChainReadyNoDblNeg
          (Stack.Lower.computeLastUses thn) thn _ 0 false hThn
        simpa [Stack.Lower.collectRawSlots] using this
      have hRawEls : Stack.Lower.collectRawSlotsGo [] els = [] := by
        have := collectRawSlots_nil_of_emittableArithChainReadyNoDblNeg
          (Stack.Lower.computeLastUses els) els _ 0 false hEls
        simpa [Stack.Lower.collectRawSlots] using this
      exact Stack.Lower.collectRawSlots_singleton_ifVal_of_arms
        bn cond thn els [] src hRawThn hRawEls

/-- **Wave 41 A — Bool mirror of `ifValArithBody`.**  Mirrors the predicate
arm-for-arm: the `emittableArithChainReadyNoDblNeg` conjuncts become their
Bool mirrors (`emittableArithChainReadyNoDblNegBool`) and `ifValCleanShape`
becomes a `decide` (it is `Decidable` via its conjuncts). -/
def ifValArithBodyBool
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (constInts : List (String × Int))
    (sm : StackMap) :
    List ANFBinding → Bool
  | [.mk _bn (.ifVal cond thn els []) _src] =>
      emittableArithChainReadyNoDblNegBool (Stack.Lower.computeLastUses thn) thn
        (ifValSmBranch sm cond currentIndex lastUses outerProtected) 0 false &&
      emittableArithChainReadyNoDblNegBool (Stack.Lower.computeLastUses els) els
        (ifValSmBranch sm cond currentIndex lastUses outerProtected) 0 false &&
      decide (ifValCleanShape progMethods props budget currentIndex lastUses
        outerProtected constInts sm cond thn els)
  | _ => false

/-- **Wave 41 A — reflection: Bool mirror ↔ `Prop`.** -/
theorem ifValArithBodyBool_iff
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (constInts : List (String × Int))
    (sm : StackMap) :
    ∀ (body : List ANFBinding),
      ifValArithBodyBool progMethods props budget currentIndex lastUses
        outerProtected constInts sm body = true ↔
      ifValArithBody progMethods props budget currentIndex lastUses
        outerProtected constInts sm body
  | [] => by
      simp only [ifValArithBodyBool, ifValArithBody, Bool.false_eq_true]
  | [.mk _bn (.ifVal cond thn els []) _src] => by
      simp only [ifValArithBodyBool, ifValArithBody, Bool.and_eq_true,
        emittableArithChainReadyNoDblNegBool_iff, decide_eq_true_eq, and_assoc]
  -- Multi-result `if`: outside this fragment. Its lowering emits the
  -- extra result-adoption ops (`adoptDeclaredResults`), which the
  -- op-shape lemmas below do not cover, so both sides are `False`.
  | [.mk _ (.ifVal _ _ _ (_ :: _)) _] => by
      simp only [ifValArithBodyBool, ifValArithBody, Bool.false_eq_true]
  | [.mk _ (.loadParam _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.loadProp _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.loadConst _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.binOp _ _ _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.unaryOp _ _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.call _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.methodCall _ _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.loop _ _ _ _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.assert _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.updateProp _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ .getStateScript _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.checkPreimage _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.deserializeState _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.addOutput _ _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.addRawOutput _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.addDataOutput _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.arrayLiteral _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | [.mk _ (.rawScript _ _ _) _] => by simp only [ifValArithBodyBool, ifValArithBody, reduceCtorEq]
  | _ :: _ :: _ => by
      simp only [ifValArithBodyBool, ifValArithBody, Bool.false_eq_true]

/-- **Wave 41 A — `Decidable` instance via the reflection.** -/
instance instDecidableIfValArithBody
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (constInts : List (String × Int))
    (sm : StackMap) (body : List ANFBinding) :
    Decidable (ifValArithBody progMethods props budget currentIndex lastUses
      outerProtected constInts sm body) :=
  decidable_of_iff
    (ifValArithBodyBool progMethods props budget currentIndex lastUses
      outerProtected constInts sm body = true)
    (ifValArithBodyBool_iff progMethods props budget currentIndex lastUses
      outerProtected constInts sm body)

/-! ### A — MANDATORY smoke: a concrete `ifValArithBody`

`if (c) { t0 = p0 + p1; t1 = t0 + p2 } else { u0 = p0 - p1; u1 = u0 - p2 }`,
with cond `c` a bool param, both branches genuine two-binding arith chains
consuming the parent operands `p0`,`p1`,`p2`.  The branches are
depth-balanced (both net `["p0","p1","p2"]` → a single result), neither
consumes a parent slot the other keeps, so `ifValCleanShape` holds and
`ifValArithBody` is inhabited — anti-vacuous (both branches are genuinely
arith, neither empty nor const). -/

/-- Helper: the `.2` (stack-map + local-bindings) projection of a binOp
`lowerValueP` consuming depth-0 / depth-1, from the public smOut +
localBindings lemmas (the private `.1`-ops lemma is not needed here). -/
private theorem lvp_binOp_snd
    (pm : List ANFMethod) (pr : List ANFProperty) (bud ci : Nat)
    (lu : List (String × Nat)) (lb : List String) (cs : List (String × Int))
    (smm : StackMap) (nm op l r : String) (rt : Option String)
    (hl : smm.depth? l = some 0) (hr : smm.depth? r = some 1)
    (hll : Stack.Lower.isLastUse lu l ci = true)
    (hlr : Stack.Lower.isLastUse lu r ci = true) :
    (Stack.Lower.lowerValueP pm pr bud ci lu [] lb cs smm nm (.binOp op l r rt)).2
      = (some nm :: smm.tail.tail, lb) :=
  Prod.ext
    (lowerValueP_binOp_d0d1_smOut pm pr bud ci lu lb cs smm nm op l r rt hl hr hll hlr)
    (lowerValueP_binOp_localBindings pm pr bud ci lu [] lb cs smm nm op l r rt)

private def sA_thn : List ANFBinding :=
  [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
   ANFBinding.mk "t1" (.binOp "+" "t0" "p2" none) none]
private def sA_els : List ANFBinding :=
  [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
   ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]
private def sA_body : List ANFBinding :=
  [ANFBinding.mk "r" (.ifVal "c" sA_thn sA_els) none]
private def sA_sm : StackMap := ["c", "p0", "p1", "p2"]
private def sA_lu : List (String × Nat) := Stack.Lower.computeLastUses sA_body

private theorem sA_smBranch :
    ifValSmBranch sA_sm "c" 0 sA_lu [] = (["p0", "p1", "p2"] : Stack.Lower.StackMap) := by
  unfold ifValSmBranch Stack.Lower.loadRefLive Stack.Lower.bringToTop
    sA_sm sA_lu sA_body sA_thn sA_els
  decide

private theorem sA_ip :
    ifValInnerProtected sA_sm "c" 0 sA_lu [] = [] := by
  unfold ifValInnerProtected ifValSmBranch Stack.Lower.loadRefLive Stack.Lower.bringToTop
    Stack.Lower.computeBranchProtected sA_sm sA_lu sA_body sA_thn sA_els
  decide

private theorem sA_thnSm :
    (ifValThnRes [] [] 8 0 sA_lu [] [] sA_sm "c" sA_thn).2 = (["t1"] : Stack.Lower.StackMap) := by
  rw [ifValThnRes_eq_default [] [] 8 0 sA_lu [] [] sA_sm "c" sA_thn (by rfl)]
  rw [sA_smBranch, sA_ip, sA_thn]
  simp only [List.map_cons, List.map_nil, ANFBinding.name]
  rw [Stack.Lower.lowerBindingsP.eq_2]
  rcases h1 : Stack.Lower.lowerValueP [] [] 8 0 (Stack.Lower.computeLastUses
      [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
       ANFBinding.mk "t1" (.binOp "+" "t0" "p2" none) none]) []
      ["t0", "t1"] [] ["p0", "p1", "p2"] "t0" (.binOp "+" "p0" "p1" none)
    with ⟨o1, s1, l1⟩
  have e1 : (s1, l1) = ((["t0", "p2"] : Stack.Lower.StackMap), ["t0", "t1"]) := by
    have := lvp_binOp_snd [] [] 8 0 (Stack.Lower.computeLastUses
      [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
       ANFBinding.mk "t1" (.binOp "+" "t0" "p2" none) none]) ["t0", "t1"] []
      ["p0", "p1", "p2"] "t0" "+" "p0" "p1" none (by decide) (by decide) (by decide) (by decide)
    rw [h1] at this; exact this
  obtain ⟨hs1, hl1⟩ := Prod.mk.injEq .. ▸ e1
  subst hs1; subst hl1
  simp only []
  rw [Stack.Lower.lowerBindingsP.eq_2]
  rcases h2 : Stack.Lower.lowerValueP [] [] 8 1 (Stack.Lower.computeLastUses
      [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
       ANFBinding.mk "t1" (.binOp "+" "t0" "p2" none) none]) []
      ["t0", "t1"] [] ["t0", "p2"] "t1" (.binOp "+" "t0" "p2" none)
    with ⟨o2, s2, l2⟩
  have e2 : (s2, l2) = ((["t1"] : Stack.Lower.StackMap), ["t0", "t1"]) := by
    have := lvp_binOp_snd [] [] 8 1 (Stack.Lower.computeLastUses
      [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
       ANFBinding.mk "t1" (.binOp "+" "t0" "p2" none) none]) ["t0", "t1"] []
      ["t0", "p2"] "t1" "+" "t0" "p2" none (by decide) (by decide) (by decide) (by decide)
    rw [h2] at this; exact this
  obtain ⟨hs2, hl2⟩ := Prod.mk.injEq .. ▸ e2
  subst hs2; subst hl2
  simp only [Stack.Lower.lowerBindingsP]

private theorem sA_elsSm :
    (ifValElsRes [] [] 8 0 sA_lu [] [] sA_sm "c" sA_els).2 = (["u1"] : Stack.Lower.StackMap) := by
  rw [ifValElsRes_eq_default [] [] 8 0 sA_lu [] [] sA_sm "c" sA_els (by rfl)]
  rw [sA_smBranch, sA_ip, sA_els]
  simp only [List.map_cons, List.map_nil, ANFBinding.name]
  rw [Stack.Lower.lowerBindingsP.eq_2]
  rcases h1 : Stack.Lower.lowerValueP [] [] 8 0 (Stack.Lower.computeLastUses
      [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
       ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]) []
      ["u0", "u1"] [] ["p0", "p1", "p2"] "u0" (.binOp "-" "p0" "p1" none)
    with ⟨o1, s1, l1⟩
  have e1 : (s1, l1) = ((["u0", "p2"] : Stack.Lower.StackMap), ["u0", "u1"]) := by
    have := lvp_binOp_snd [] [] 8 0 (Stack.Lower.computeLastUses
      [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
       ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]) ["u0", "u1"] []
      ["p0", "p1", "p2"] "u0" "-" "p0" "p1" none (by decide) (by decide) (by decide) (by decide)
    rw [h1] at this; exact this
  obtain ⟨hs1, hl1⟩ := Prod.mk.injEq .. ▸ e1
  subst hs1; subst hl1
  simp only []
  rw [Stack.Lower.lowerBindingsP.eq_2]
  rcases h2 : Stack.Lower.lowerValueP [] [] 8 1 (Stack.Lower.computeLastUses
      [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
       ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]) []
      ["u0", "u1"] [] ["u0", "p2"] "u1" (.binOp "-" "u0" "p2" none)
    with ⟨o2, s2, l2⟩
  have e2 : (s2, l2) = ((["u1"] : Stack.Lower.StackMap), ["u0", "u1"]) := by
    have := lvp_binOp_snd [] [] 8 1 (Stack.Lower.computeLastUses
      [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
       ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]) ["u0", "u1"] []
      ["u0", "p2"] "u1" "-" "u0" "p2" none (by decide) (by decide) (by decide) (by decide)
    rw [h2] at this; exact this
  obtain ⟨hs2, hl2⟩ := Prod.mk.injEq .. ▸ e2
  subst hs2; subst hl2
  simp only [Stack.Lower.lowerBindingsP]

private theorem sA_elsOps :
    (ifValElsRes [] [] 8 0 sA_lu [] [] sA_sm "c" sA_els).1 ≠ [] := by
  rw [ifValElsRes_eq_default [] [] 8 0 sA_lu [] [] sA_sm "c" sA_els (by rfl)]
  rw [sA_smBranch, sA_ip, sA_els]
  simp only [List.map_cons, List.map_nil, ANFBinding.name]
  rw [Stack.Lower.lowerBindingsP.eq_2]
  rcases h1 : Stack.Lower.lowerValueP [] [] 8 0 (Stack.Lower.computeLastUses
      [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
       ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]) []
      ["u0", "u1"] [] ["p0", "p1", "p2"] "u0" (.binOp "-" "p0" "p1" none)
    with ⟨o1, s1, l1⟩
  have ho1 : o1 ≠ [] := by
    have hfst : o1 = (Stack.Lower.lowerValueP [] [] 8 0 (Stack.Lower.computeLastUses
        [ANFBinding.mk "u0" (.binOp "-" "p0" "p1" none) none,
         ANFBinding.mk "u1" (.binOp "-" "u0" "p2" none) none]) []
        ["u0", "u1"] [] ["p0", "p1", "p2"] "u0" (.binOp "-" "p0" "p1" none)).1 :=
      (congrArg Prod.fst h1).symm
    rw [hfst]
    unfold Stack.Lower.lowerValueP Stack.Lower.loadRefOperand
      Stack.Lower.operandConsume Stack.Lower.bringToTop
    decide
  simp only []
  intro hcontra
  exact ho1 (List.append_eq_nil_iff.mp hcontra).1

private theorem sA_clean :
    ifValCleanShape [] [] 8 0 sA_lu [] [] sA_sm "c" sA_thn sA_els := by
  -- Issue #149 is repaired in the PARENT (`sinkResultBlock`), so the clean
  -- shape no longer carries a per-arm reconcile conjunct.
  refine ⟨by decide, ?_, ?_, ?_, sA_elsOps⟩
  · rw [sA_smBranch, sA_elsSm, sA_thnSm]; decide
  · rw [sA_smBranch, sA_thnSm, sA_elsSm]; decide
  · rw [sA_thnSm, sA_elsSm]; rfl

/-- **Wave 41 A smoke — `ifValArithBody` is inhabited.**  Both branches
genuinely two-binding arith chains consuming the same parent operands; the
predicate (arith-readiness ×2 + `ifValCleanShape`) discharges. -/
theorem wave41_ifValArithBody_smoke :
    ifValArithBody [] [] 8 0 sA_lu [] [] sA_sm sA_body := by
  show emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses sA_thn) sA_thn
        (ifValSmBranch sA_sm "c" 0 sA_lu []) 0 false ∧
      emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses sA_els) sA_els
        (ifValSmBranch sA_sm "c" 0 sA_lu []) 0 false ∧
      ifValCleanShape [] [] 8 0 sA_lu [] [] sA_sm "c" sA_thn sA_els
  refine ⟨?_, ?_, sA_clean⟩
  · rw [sA_smBranch]; unfold sA_thn; decide
  · rw [sA_smBranch]; unfold sA_els; decide

/-! ### B — the cond-load lemma

When the `if_val` condition `cond` is the **head** tagged slot — a bool-typed
slot whose ANF value is a known `.vBool b` (a prior comparison result or a
bool param sitting on top of the branch stack at the if) — both sides agree:

* ANF: `anfSt.resolveRef cond = some (.vBool b)` (head correspondence of
  `agreesTagged` + the slot resolving to its tagged value via `tsmCoherent`);
* Script: the cond is on top of `stkSt.stack` (head alignment), bool-coercible
  to the same `b`, and the cond-load `loadRefLive (cond :: rest) cond …` at
  depth 0 with a last-use consume emits no ops (`[]`) — the cond is already on
  top, and the structural `OP_IF` pops it.

This is the input-side cond-load witness `agreesTagged_ifVal_arith_iff`
(wave 40) consumes: `condOps = []`, `condV = .vBool b`, `branchStk = stkSt`
with the cond head popped.  It is NOT a restatement of the conclusion (it
talks only about the cond head + the load prefix, never about the `.ifOp`
tail). -/
theorem ifValArithCondLoad
    (cond : String) (k : SlotKind) (rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState) (restStk : List Value) (b : Bool)
    (lastUses : List (String × Nat)) (currentIndex : Nat)
    (hAgrees : agreesTagged ((cond, k) :: rest) anfSt stkSt)
    (hCondVal : lookupAnfByKind anfSt (cond, k) = some (.vBool b))
    (hCoh : tsmCoherent anfSt ((cond, k) :: rest))
    (hStk : stkSt.stack = (.vBool b) :: restStk)
    (hLast : Stack.Lower.isLastUse lastUses cond currentIndex = true) :
    -- ANF side: cond resolves to the known bool.
    anfSt.resolveRef cond = some (.vBool b)
    -- Script side: the cond-load runs to the bool-topped branch stack with
    -- `condOps = []`, and the top is bool-coercible to the same `b`.
    ∧ (Stack.Lower.loadRefLive (Agrees.untagSm ((cond, k) :: rest)) cond
          currentIndex lastUses []).1 = []
    ∧ runOps (Stack.Lower.loadRefLive (Agrees.untagSm ((cond, k) :: rest)) cond
          currentIndex lastUses []).1 stkSt
        = .ok { stkSt with stack := (.vBool b) :: { stkSt with stack := restStk }.stack }
    ∧ asBool? (.vBool b) = some b := by
  refine ⟨?_, ?_, ?_, rfl⟩
  · -- ANF: head correspondence of `agreesTagged` identifies the cond value;
    -- `tsmCoherent` transports `lookupAnfByKind` to `resolveRef`.
    have hc := hCoh (cond, k) (List.mem_cons_self)
    rw [← hc]; exact hCondVal
  · -- The cond-load shape: cond at depth 0, last use → `loadRefLive` emits `[]`.
    show (Stack.Lower.loadRefLive (cond :: Agrees.untagSm rest) cond currentIndex lastUses []).1 = []
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and, hLast,
      Stack.Lower.StackMap.depth?, List.findIdx?_cons, beq_self_eq_true, if_true]
  · -- The cond-load runs to the same stack (`[]` ops); rewrite the top via hStk.
    have hOps : (Stack.Lower.loadRefLive (Agrees.untagSm ((cond, k) :: rest)) cond
          currentIndex lastUses []).1 = [] := by
      show (Stack.Lower.loadRefLive (cond :: Agrees.untagSm rest) cond currentIndex lastUses []).1 = []
      unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
      simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and, hLast,
        Stack.Lower.StackMap.depth?, List.findIdx?_cons, beq_self_eq_true, if_true]
    rw [hOps, Stack.Eval.runOps_nil]
    cases stkSt with
    | mk stack altstack outputs props preimage =>
        simp only at hStk
        subst hStk
        rfl

/-! ### B — MANDATORY smoke: the cond-load fires on a concrete bool head

cond `c` is the head `.param` slot resolving to `.vBool true`, sitting on
top of the branch stack `[.vBool true, .vBigint 3, .vBigint 4]`.  Both
sides agree (`resolveRef c = some (.vBool true)`, the cond-load runs `[]`,
the top is bool-coercible to `true`). -/
private def sB_anf : State :=
  { params := [("c", .vBool true), ("p0", .vBigint 3), ("p1", .vBigint 4)] }
private def sB_stk : StackState :=
  { stack := [.vBool true, .vBigint 3, .vBigint 4] }
private def sB_rest : TaggedStackMap := [("p0", .param), ("p1", .param)]

private theorem sB_agrees :
    agreesTagged (("c", .param) :: sB_rest) sB_anf sB_stk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned (("c", .param) :: sB_rest) sB_anf sB_stk.stack
  refine ⟨rfl, ?_, ?_, ?_⟩
  · show lookupAnfByKind sB_anf ("p0", .param) = some (.vBigint 3); rfl
  · show lookupAnfByKind sB_anf ("p1", .param) = some (.vBigint 4); rfl
  · trivial

private theorem sB_coh : tsmCoherent sB_anf (("c", .param) :: sB_rest) := by
  intro s hs
  simp only [sB_rest, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with h | h | h <;> (subst h; rfl)

/-- **Wave 41 B smoke — the cond-load fires.**  The cond `c` resolves to
`.vBool true` on both sides, the cond-load runs to the bool-topped branch
stack with no ops, and the top is bool-coercible to `true`. -/
theorem wave41_ifValArithCondLoad_smoke :
    sB_anf.resolveRef "c" = some (.vBool true)
    ∧ (Stack.Lower.loadRefLive (Agrees.untagSm (("c", .param) :: sB_rest)) "c"
          0 [("c", 0)] []).1 = []
    ∧ asBool? (.vBool true) = some true := by
  obtain ⟨hRes, hOps, _hRun, hBool⟩ :=
    ifValArithCondLoad "c" .param sB_rest sB_anf sB_stk [.vBigint 3, .vBigint 4] true
      [("c", 0)] 0 sB_agrees rfl sB_coh rfl (by decide)
  exact ⟨hRes, hOps, hBool⟩

/-! ### B (Wave 44) — branch-pop transport (the entry bridge)

`ifValArithCondLoad` (wave 41) takes the full method entry alignment but
its `hStk` premise (`stkSt.stack = .vBool b :: restStk`) already encodes
the cond being on top of the entry stack.  Wave 44's bridge closes the last
gap the omnibus entry bundle leaves open: from the SAME entry alignment
`agreesTagged ((cond, k) :: branchTsm) initialAnf initialStack` plus the
cond resolving to a `.vBool b` runtime value, it
**transports the branch-level entry alignment** — `agreesTagged branchTsm
initialAnf branchStk` for the cond-popped branch stack `branchStk` — and
re-derives the cond-load facts, so each branch's
`successAgrees_arith_consume_unconditional` fires against `branchStk`.

The cond is consumed (popped) for the branch's purposes: the cond-load at
depth 0 + last use emits `[]` (the cond is already on top), and the
structural `OP_IF` pops it.  So `branchStk = { initialStack with stack :=
restStk }` and `branchTsm` (the tail of the entry tsm) aligns with it.

The transported `EntryBigintTyped` / `CondBoolTyped` are facts about
`initialAnf` (unchanged across the pop) and ride along unchanged; the
branch's `entryTsmArithTyped` is the omnibus's branch-slot premise; the
branch's `tsmCoherent` is the tail of the entry coherence.  This lemma
supplies the stack-side branch transport (`agreesTagged`) + the cond-load
witnesses — never the `.ifOp` conclusion. -/
theorem agreesTagged_ifVal_pop_cond
    (cond : String) (k : SlotKind) (branchTsm : TaggedStackMap)
    (initialAnf : State) (initialStack : StackState) (restStk : List Value)
    (b : Bool) (lastUses : List (String × Nat)) (currentIndex : Nat)
    (hAgrees : agreesTagged ((cond, k) :: branchTsm) initialAnf initialStack)
    (hCondVal : lookupAnfByKind initialAnf (cond, k) = some (.vBool b))
    (hCoh : tsmCoherent initialAnf ((cond, k) :: branchTsm))
    (hStk : initialStack.stack = (.vBool b) :: restStk)
    (hLast : Stack.Lower.isLastUse lastUses cond currentIndex = true) :
    ∃ branchStk : StackState,
      -- The branch stack is the entry stack with the cond head popped.
      branchStk = { initialStack with stack := restStk }
      -- The branch-level entry alignment (cond-popped).
      ∧ agreesTagged branchTsm initialAnf branchStk
      -- The branch-level coherence (tail of the entry coherence).
      ∧ tsmCoherent initialAnf branchTsm
      -- ANF side: cond resolves to the known bool.
      ∧ initialAnf.resolveRef cond = some (.vBool b)
      -- Script side: the cond-load runs to the bool-topped branch stack.
      ∧ runOps (Stack.Lower.loadRefLive (Agrees.untagSm ((cond, k) :: branchTsm)) cond
            currentIndex lastUses []).1 initialStack
          = .ok { branchStk with stack := (.vBool b) :: branchStk.stack }
      -- Script side: the cond top is bool-coercible to the same `b`.
      ∧ asBool? (.vBool b) = some b := by
  -- The wave-41 cond-load lemma supplies the ANF / cond-load / asBool? facts.
  obtain ⟨hRes, _hOps, hRun, hBool⟩ :=
    ifValArithCondLoad cond k branchTsm initialAnf initialStack restStk b
      lastUses currentIndex hAgrees hCondVal hCoh hStk hLast
  refine ⟨{ initialStack with stack := restStk }, rfl, ?_, ?_, hRes, ?_, hBool⟩
  · -- Branch alignment: pop the cond head off `taggedStackAligned`.
    obtain ⟨hAlign, hProps, hOuts⟩ := hAgrees
    refine ⟨?_, hProps, hOuts⟩
    rw [hStk] at hAlign
    -- `taggedStackAligned ((cond,k) :: branchTsm) anf (v :: restStk)` ⇒ tail.
    exact hAlign.2
  · -- Branch coherence: tail of the entry coherence.
    intro s hs
    exact hCoh s (List.mem_cons_of_mem _ hs)
  · -- The cond-load result, rewritten to the branch-stack record.
    exact hRun

/-! ### B (Wave 44) — MANDATORY smoke: the branch-pop transport fires

Same concrete `c=true` head over `[p0=3,p1=4]`.  From the entry alignment,
the transport produces the cond-popped branch stack `[p0,p1]`, the branch
alignment, the branch coherence, and the cond-load running to the
bool-topped stack — anti-vacuous (the branch alignment genuinely holds). -/
theorem wave44_agreesTagged_ifVal_pop_cond_smoke :
    ∃ branchStk : StackState,
      branchStk = { sB_stk with stack := [.vBigint 3, .vBigint 4] }
      ∧ agreesTagged sB_rest sB_anf branchStk
      ∧ sB_anf.resolveRef "c" = some (.vBool true) := by
  obtain ⟨branchStk, hEq, hAgr, _hCoh, hRes, _hRun, _hBool⟩ :=
    agreesTagged_ifVal_pop_cond "c" .param sB_rest sB_anf sB_stk
      [.vBigint 3, .vBigint 4] true [("c", 0)] 0 sB_agrees rfl sB_coh rfl (by decide)
  exact ⟨branchStk, hEq, hAgr, hRes⟩

/-! ### C — the body-level walk wrapper

`successAgrees_ifVal_arith_unconditional` lifts the wave-39 arith walk to a
single self-contained `ifValArithBody`.  It composes:

* the ANF / Script singleton-body bridges
  (`evalBindings [ifVal] ↔ evalValue (.ifVal)`,
   `lowerBindingsP [ifVal] = (lowerValueP (.ifVal)).1`),
* the clean-shape collapse `lowerValueP_ifVal_clean_shape` (so the lowered
  op-list is `condOps ++ [.ifOp thnOps (some elsOps)]` — the analogue of the
  arith chunk-split), and
* the wave-40 transport `agreesTagged_ifVal_arith_iff`, fed the cond-load
  (Deliverable B's `condV` / `branchStk` / `asBool?` facts) and the two
  per-branch arith walk iffs (each the output of the wave-39
  `successAgrees_arith_consume_unconditional` against `branchStk`).

The branch iffs and the cond facts are taken as input-side premises (each is
produced by the arith walk / Deliverable B against the cond-popped branch
stack `branchStk`, never by inspecting the `.ifOp` conclusion).  The smoke
below feeds them from the real wave-39 walk + Deliverable B. -/
theorem successAgrees_ifVal_arith_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (bn cond : String) (thn els : List ANFBinding)
    (src : Option SourceLoc)
    (initialAnf : State) (initialStack : StackState) (branchStk : StackState)
    (condV : Value) (b : Bool)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                [] constInts sm cond thn els)
    (hCond : initialAnf.resolveRef cond = some (.vBool b))
    (hCondLoad :
      runOps (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1 initialStack
        = .ok { branchStk with stack := condV :: branchStk.stack })
    (hBool : asBool? condV = some b)
    (hThnIff :
      (RunarVerification.ANF.Eval.evalBindings initialAnf thn).toOption.isSome ↔
      (runOps (ifValThnRes progMethods props budget currentIndex lastUses
                [] constInts sm cond thn).1 branchStk).toOption.isSome)
    (hElsIff :
      (RunarVerification.ANF.Eval.evalBindings initialAnf els).toOption.isSome ↔
      (runOps (ifValElsRes progMethods props budget currentIndex lastUses
                [] constInts sm cond els).1 branchStk).toOption.isSome) :
    (RunarVerification.ANF.Eval.evalBindings initialAnf
        [.mk bn (.ifVal cond thn els) src]).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1
            initialStack).toOption.isSome := by
  -- ANF bridge: evalBindings of the singleton ifVal ↔ evalValue (.ifVal).
  have hAnfBridge :
      (RunarVerification.ANF.Eval.evalBindings initialAnf
          [.mk bn (.ifVal cond thn els) src]).toOption.isSome
        ↔ (RunarVerification.ANF.Eval.evalValue initialAnf (.ifVal cond thn els)).toOption.isSome := by
    simp only [RunarVerification.ANF.Eval.evalBindings]
    cases h : RunarVerification.ANF.Eval.evalValue initialAnf (.ifVal cond thn els) with
    | error e => simp only [bind, Except.bind, Except.toOption, Option.isSome]
    | ok p => simp only [bind, Except.bind, Except.toOption, Option.isSome]
  -- Script bridge: lowerBindingsP of the singleton ifVal = (lowerValueP).1,
  -- then clean-shape collapse to `condOps ++ [.ifOp thnOps (some elsOps)]`.
  have hScriptBridge :
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1
        = (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1
          ++ [StackOp.ifOp
                (ifValThnRes progMethods props budget currentIndex lastUses
                  [] constInts sm cond thn).1
                (some (ifValElsRes progMethods props budget currentIndex lastUses
                  [] constInts sm cond els).1)] := by
    rw [Stack.Lower.lowerBindingsP.eq_2]
    rcases h : Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm bn (.ifVal cond thn els) with ⟨o, s, l⟩
    simp only [Stack.Lower.lowerBindingsP, List.append_nil]
    have hcs := lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
      [] localBindings constInts sm bn cond thn els hClean
    rw [h] at hcs
    exact hcs
  rw [hAnfBridge, hScriptBridge]
  -- Transport across the conditional via the wave-40 lemma.
  exact agreesTagged_ifVal_arith_iff initialAnf cond thn els
    (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1
    (ifValThnRes progMethods props budget currentIndex lastUses [] constInts sm cond thn).1
    (some (ifValElsRes progMethods props budget currentIndex lastUses [] constInts sm cond els).1)
    initialStack branchStk condV b hCond hCondLoad hBool hThnIff
    (fun e he => by rw [Option.some.injEq] at he; subst he; exact hElsIff)
    (fun he => by exact absurd he (by simp))

/-! ### C — MANDATORY smoke: the body-level walk wrapper fires

The same `if (c) { t0=p0+p1; t1=t0+p2 } else { u0=p0-p1; u1=u0-p2 }`, now
with a full ANF state (`c=true`, `p0=3`,`p1=4`,`p2=5`) and aligned stacks.
The two branch iffs come from the REAL wave-39
`successAgrees_arith_consume_unconditional` (NO `taggedAllBigint`
hypothesis — DERIVED from typed entry), the cond-load from Deliverable B,
and the clean-shape from the Deliverable-A smoke machinery.  We obtain the
body-level iff and confirm the ANF side concretely succeeds, so the Script
side succeeds — anti-vacuous (both branches genuinely arith). -/
private def sC_anf : State :=
  { params := [("c", .vBool true), ("p0", .vBigint 3), ("p1", .vBigint 4), ("p2", .vBigint 5)] }
private def sC_stk : StackState :=
  { stack := [.vBool true, .vBigint 3, .vBigint 4, .vBigint 5] }
private def sC_branchStk : StackState :=
  { stack := [.vBigint 3, .vBigint 4, .vBigint 5] }
private def sC_branchTsm : TaggedStackMap :=
  [("p0", .param), ("p1", .param), ("p2", .param)]
private def sC_env : RunarVerification.ANF.WellTyped.TypeEnv :=
  (((RunarVerification.ANF.Typed.TypeEnv.empty.extend "p0" .bigint).extend "p1" .bigint).extend "p2" .bigint)

private theorem sC_branchAgrees : agreesTagged sC_branchTsm sC_anf sC_branchStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned sC_branchTsm sC_anf sC_branchStk.stack
  refine ⟨rfl, rfl, rfl, ?_⟩; trivial

private theorem sC_entryTyped :
    RunarVerification.ANF.WellTyped.EntryBigintTyped sC_env sC_anf := by
  intro n hn
  by_cases h0 : n = "p0"
  · subst h0; exact ⟨.vBigint 3, rfl, ⟨3, rfl⟩⟩
  · by_cases h1 : n = "p1"
    · subst h1; exact ⟨.vBigint 4, rfl, ⟨4, rfl⟩⟩
    · by_cases h2 : n = "p2"
      · subst h2; exact ⟨.vBigint 5, rfl, ⟨5, rfl⟩⟩
      · exfalso
        have hp2 : ("p2" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h2 h.symm
        have hp1 : ("p1" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h1 h.symm
        have hp0 : ("p0" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h0 h.symm
        simp only [sC_env, RunarVerification.ANF.Typed.TypeEnv.lookup,
          RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
          List.find?_cons, hp2, hp1, hp0, List.find?_nil, Option.map_none, reduceCtorEq] at hn

private theorem sC_tsmTyped : entryTsmArithTyped sC_env sC_branchTsm := by
  intro s hs
  unfold RunarVerification.ANF.WellTyped.arithOperandBigint
  simp only [sC_branchTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with h | h | h <;> (subst h; decide)

private theorem sC_coh : tsmCoherent sC_anf sC_branchTsm := by
  intro s hs
  simp only [sC_branchTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with h | h | h <;> (subst h; rfl)

/-- Branch walk iff (the exact shape Deliverable C's `hThnIff` / `hElsIff`
demand), produced by the wave-39 walk + the `ifValInnerProtected = []` /
`ifValSmBranch` rewrites from the Deliverable-A smoke. -/
private theorem sC_branchWalk (branch : List ANFBinding)
    (hChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses branch) branch
      ["p0", "p1", "p2"] 0 false)
    (hRes :
      ifValThnRes [] [] 8 0 sA_lu [] (Stack.Lower.collectConstInts sA_body) sA_sm "c" branch
        = Stack.Lower.lowerBindingsP [] [] 8 0 (Stack.Lower.computeLastUses branch) []
            (List.map (fun b => b.name) branch) (Stack.Lower.collectConstInts sA_body)
            ["p0", "p1", "p2"] branch) :
    (RunarVerification.ANF.Eval.evalBindings sC_anf branch).toOption.isSome ↔
    (runOps (ifValThnRes [] [] 8 0 sA_lu [] (Stack.Lower.collectConstInts sA_body) sA_sm "c" branch).1
        sC_branchStk).toOption.isSome := by
  rw [hRes]
  exact successAgrees_arith_consume_unconditional [] [] 8
    (Stack.Lower.computeLastUses branch) (Stack.Lower.collectConstInts sA_body) sC_env
    branch ["p0", "p1", "p2"] (List.map (fun b => b.name) branch) 0 sC_branchTsm sC_anf sC_branchStk
    (by unfold sC_branchTsm untagSm; rfl) sC_branchAgrees
    (emittableArithChainReadyNoDblNeg_imp_ready _ branch ["p0", "p1", "p2"] 0 false hChain)
    sC_entryTyped sC_tsmTyped sC_coh

/-- **Wave 41 C smoke — the body-level walk wrapper fires.**  The body-level
iff holds, and the ANF `if_val` side concretely succeeds (THEN branch
evaluates `t0 = 3+4 = 7`, `t1 = 7+5 = 12`), so the Script side succeeds. -/
theorem wave41_successAgrees_ifVal_arith_smoke :
    ((RunarVerification.ANF.Eval.evalBindings sC_anf sA_body).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 8 0 sA_lu []
            (List.map (fun b => b.name) sA_body) (Stack.Lower.collectConstInts sA_body)
            sA_sm sA_body).1 sC_stk).toOption.isSome)
    ∧ (RunarVerification.ANF.Eval.evalBindings sC_anf sA_body).toOption.isSome := by
  -- `collectConstInts sA_body = []` (pure-param arith, no const ints).
  have hCCI : Stack.Lower.collectConstInts sA_body = [] := by
    unfold sA_body sA_thn sA_els
    simp only [Stack.Lower.collectConstInts, List.append_nil]
  rw [hCCI]
  have hCondAgrees : agreesTagged (("c", .param) :: sC_branchTsm) sC_anf sC_stk := by
    refine ⟨?_, rfl, rfl⟩
    show taggedStackAligned (("c", .param) :: sC_branchTsm) sC_anf sC_stk.stack
    refine ⟨rfl, rfl, rfl, rfl, ?_⟩; trivial
  have hCondCoh : tsmCoherent sC_anf (("c", .param) :: sC_branchTsm) := by
    intro s hs
    simp only [sC_branchTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with h | h | h | h <;> (subst h; rfl)
  obtain ⟨hCondRes, _hCondOps, hCondRun, hCondBool⟩ :=
    ifValArithCondLoad "c" .param sC_branchTsm sC_anf sC_stk
      [.vBigint 3, .vBigint 4, .vBigint 5] true sA_lu 0
      hCondAgrees rfl hCondCoh rfl (by decide)
  have hUntagSm : Agrees.untagSm (("c", .param) :: sC_branchTsm) = sA_sm := by
    unfold sC_branchTsm untagSm sA_sm; rfl
  rw [hUntagSm] at hCondRun
  have hThn := sC_branchWalk sA_thn (by unfold sA_thn; decide)
    (by rw [ifValThnRes_eq_default [] [] 8 0 sA_lu []
          (Stack.Lower.collectConstInts sA_body) sA_sm "c" sA_thn (by rfl),
        sA_smBranch, sA_ip, hCCI])
  have hEls := sC_branchWalk sA_els (by unfold sA_els; decide)
    (by rw [ifValThnRes_eq_default [] [] 8 0 sA_lu []
          (Stack.Lower.collectConstInts sA_body) sA_sm "c" sA_els (by rfl),
        sA_smBranch, sA_ip, hCCI])
  rw [hCCI] at hThn hEls
  -- `ifValThnRes … sA_els = ifValElsRes … sA_els` definitionally (same lowering).
  have hElsConv :
      (RunarVerification.ANF.Eval.evalBindings sC_anf sA_els).toOption.isSome ↔
      (runOps (ifValElsRes [] [] 8 0 sA_lu [] [] sA_sm "c" sA_els).1
          sC_branchStk).toOption.isSome := hEls
  have hIff := successAgrees_ifVal_arith_unconditional [] [] 8 0 sA_lu
    (List.map (fun b => b.name) sA_body) []
    sA_sm "r" "c" sA_thn sA_els none sC_anf sC_stk sC_branchStk (.vBool true) true
    sA_clean hCondRes hCondRun hCondBool hThn hElsConv
  refine ⟨hIff, ?_⟩
  -- ANF side concretely succeeds: THEN branch evaluates `t0=3+4=7; t1=7+5=12`.
  show (RunarVerification.ANF.Eval.evalBindings sC_anf sA_body).toOption.isSome
  unfold sA_body
  simp only [RunarVerification.ANF.Eval.evalBindings]
  have hCondRes2 : sC_anf.resolveRef "c" = some (.vBool true) := rfl
  have hThnEval :
      (RunarVerification.ANF.Eval.evalValue sC_anf (.ifVal "c" sA_thn sA_els)).toOption.isSome := by
    rw [evalValue_ifVal_isSome_iff_activeBranch sC_anf "c" sA_thn sA_els true hCondRes2]
    rw [if_pos (rfl : (true = true))]
    show (RunarVerification.ANF.Eval.evalBindings sC_anf sA_thn).toOption.isSome
    unfold sA_thn
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          sC_anf "t0" "+" "p0" "p1" none none 3 4 _ (Or.inl rfl) rfl rfl]
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          (sC_anf.addBinding "t0" (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint "+" 3 4)))
          "t1" "+" "t0" "p2" none none
          (RunarVerification.ANF.Eval.arithBinResultBigint "+" 3 4) 5 _ (Or.inl rfl) rfl rfl]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  cases h : RunarVerification.ANF.Eval.evalValue sC_anf (.ifVal "c" sA_thn sA_els) with
  | error e =>
      exfalso; rw [h] at hThnEval
      simp only [Except.toOption, Option.isSome, reduceCtorEq] at hThnEval
  | ok p =>
      simp only [bind, Except.bind, RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]

/-! ### C (Wave 44) — the genuinely-entry-level `if_val` walk

`successAgrees_ifVal_arith_unconditional` (wave 41) is the body-level walk,
but it takes FIVE hand-supplied hypotheses the omnibus entry bundle cannot
directly produce: the cond resolving to a `.vBool`, the cond-load, the
`asBool?` coercion, and the two per-branch arith iffs.  Wave 44 closes that
gap: `successAgrees_ifVal_arith_from_entry` takes ONLY the omnibus entry
bundle (`EntryBigintTyped`, `agreesTagged`, `entryTsmArithTyped`,
`tsmCoherent`) + `CondBoolTyped` (Deliverable A, route (i): the cond is a
bool-typed ENTRY value — `ifValArithBody` is a single `.ifVal` binding with
no prior bindings, so the cond cannot be a derived comparison temp) + the
`ifValArithBody` fragment.

The five wave-41 premises are DERIVED inside, not assumed:

* `CondBoolTyped` + the head coherence → the cond resolves to `.vBool b`
  and `lookupAnfByKind initialAnf (cond, k) = some (.vBool b)`;
* `agreesTagged` head alignment → the cond sits on top of `initialStack`
  (`initialStack.stack = .vBool b :: restStk`);
* Deliverable B (`agreesTagged_ifVal_pop_cond`) → the cond-popped branch
  stack `branchStk`, the branch alignment, the branch coherence, the
  cond-load, and the `asBool?` coercion;
* the two per-branch arith iffs → the wave-35
  `successAgrees_arith_consume_unconditional` fired against `branchStk`,
  fed `ifValArithBody`'s `emittableArithChainReadyNoDblNeg` conjuncts (via
  `_imp_ready`) and the branch-slot omnibus typing.

The residual input-side facts (`hUntag`, `hLast`, the two
`ifValInnerProtected = []` rewrites) are decidable STRUCTURAL facts about
the tsm / cond-load shape — not cond/branch correctness hypotheses, and
never restatements of the `.ifOp` conclusion.  They hold for the
self-contained-branch (`ifValCleanShape`) clean path the fragment pins (no
parent-ref carried alive past the single `.ifVal`); the smoke discharges
them concretely by `decide` / `unfold`. -/
theorem successAgrees_ifVal_arith_from_entry
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (localBindings : List String)
    (constInts : List (String × Int))
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (sm : StackMap) (bn cond : String) (k : SlotKind) (thn els : List ANFBinding)
    (src : Option SourceLoc)
    (branchTsm : TaggedStackMap) (initialAnf : State) (initialStack : StackState)
    -- The `ifValArithBody` fragment (input-side; pins the branches + clean shape).
    (hBody : ifValArithBody progMethods props budget 0 lastUses [] constInts sm
      [.mk bn (.ifVal cond thn els) src])
    -- Omnibus entry bundle (parallel to the arith retirement's M2 leg).
    (hAgrees : agreesTagged ((cond, k) :: branchTsm) initialAnf initialStack)
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hTsmTyped : entryTsmArithTyped Γ branchTsm)
    (hCoh : tsmCoherent initialAnf ((cond, k) :: branchTsm))
    -- Cond-bool entry premise (Deliverable A, route (i)).
    (hCondBool : RunarVerification.ANF.WellTyped.CondBoolTyped Γ initialAnf cond)
    -- Structural input-side facts (decidable; the smoke discharges them).
    (hUntag : Agrees.untagSm ((cond, k) :: branchTsm) = sm)
    (hLast : Stack.Lower.isLastUse lastUses cond 0 = true)
    (hIPThn : ifValInnerProtected sm cond 0 lastUses [] = [])
    (hIPEls : ifValInnerProtected sm cond 0 lastUses [] = []) :
    (RunarVerification.ANF.Eval.evalBindings initialAnf
        [.mk bn (.ifVal cond thn els) src]).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses
            [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1
            initialStack).toOption.isSome := by
  -- Destructure the fragment: the two arith branches + the clean shape.
  obtain ⟨hChainThn, hChainEls, hClean⟩ := hBody
  -- Cond resolves to a `.vBool b` (Deliverable A soundness).
  obtain ⟨b, hCondRes⟩ :=
    RunarVerification.ANF.WellTyped.condBool_of_typedEntry Γ initialAnf cond hCondBool
  -- Head coherence: `resolveRef cond = lookupAnfByKind initialAnf (cond, k)`.
  have hHeadCorr : initialAnf.resolveRef cond
      = lookupAnfByKind initialAnf (cond, k) := tsmCoherent_head initialAnf (cond, k) branchTsm hCoh
  have hCondKind : lookupAnfByKind initialAnf (cond, k) = some (.vBool b) := by
    rw [← hHeadCorr]; exact hCondRes
  -- Stack head alignment: the cond sits on top of `initialStack`.
  obtain ⟨hAlign, hProps, hOuts⟩ := hAgrees
  have hStkShape : ∃ restStk, initialStack.stack = (.vBool b) :: restStk := by
    cases hstk : initialStack.stack with
    | nil => rw [hstk] at hAlign; exact absurd hAlign (by simp [taggedStackAligned])
    | cons v rest =>
        rw [hstk] at hAlign
        have hHead : lookupAnfByKind initialAnf (cond, k) = some v := hAlign.1
        rw [hCondKind] at hHead
        have hv : v = .vBool b := (Option.some.inj hHead).symm
        exact ⟨rest, by rw [hv]⟩
  obtain ⟨restStk, hStk⟩ := hStkShape
  -- Re-bundle the entry alignment for Deliverable B.
  have hAgrees' : agreesTagged ((cond, k) :: branchTsm) initialAnf initialStack :=
    ⟨hAlign, hProps, hOuts⟩
  -- Deliverable B: pop the cond → the branch entry alignment + cond-load.
  obtain ⟨branchStk, hBranchStkEq, hBranchAgrees, hBranchCoh, hCondRes2, hCondRun, hCondBoolCoerce⟩ :=
    agreesTagged_ifVal_pop_cond cond k branchTsm initialAnf initialStack restStk b
      lastUses 0 hAgrees' hCondKind hCoh hStk hLast
  -- The cond-load runs through `sm` (= `untagSm ((cond,k)::branchTsm)`).
  rw [hUntag] at hCondRun
  -- `untagSm branchTsm = ifValSmBranch sm cond …` (cond-at-head + consume).
  have hSmBranch : ifValSmBranch sm cond 0 lastUses []
      = Agrees.untagSm branchTsm := by
    rw [← hUntag]
    unfold ifValSmBranch Stack.Lower.loadRefLive Stack.Lower.bringToTop
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and, hLast,
      untagSm, Stack.Lower.StackMap.depth?, List.findIdx?_cons, beq_self_eq_true, if_true,
      Stack.Lower.StackMap.popN]
  -- Fire the per-branch wave-35 arith walks against `branchStk`.
  have hBranchWalk : ∀ (branch : List ANFBinding),
      emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses branch) branch
        (ifValSmBranch sm cond 0 lastUses []) 0 false →
      ifValInnerProtected sm cond 0 lastUses [] = [] →
      ((RunarVerification.ANF.Eval.evalBindings initialAnf branch).toOption.isSome ↔
      (runOps (ifValThnRes progMethods props budget 0 lastUses [] constInts sm cond branch).1
          branchStk).toOption.isSome) := by
    intro branch hChain hIP
    have hRes : ifValThnRes progMethods props budget 0 lastUses [] constInts sm cond branch
        = Stack.Lower.lowerBindingsP progMethods props budget 0 (Stack.Lower.computeLastUses branch) []
            (List.map (fun bnd => bnd.name) branch) constInts
            (ifValSmBranch sm cond 0 lastUses []) branch := by
      rw [ifValThnRes_eq_default progMethods props budget 0 lastUses [] constInts sm cond branch
        (insideBranchFreeBodyB_of_emittableArithChainReadyNoDblNeg _ branch _ 0 false hChain)]
      rw [hIP]
    rw [hRes]
    exact successAgrees_arith_consume_unconditional progMethods props budget
      (Stack.Lower.computeLastUses branch) constInts Γ branch
      (ifValSmBranch sm cond 0 lastUses []) (List.map (fun bnd => bnd.name) branch) 0
      branchTsm initialAnf branchStk hSmBranch.symm hBranchAgrees
      (emittableArithChainReadyNoDblNeg_imp_ready _ branch
        (ifValSmBranch sm cond 0 lastUses []) 0 false hChain)
      hTypedEntry hTsmTyped hBranchCoh
  have hThnIff := hBranchWalk thn hChainThn hIPThn
  have hElsIff := hBranchWalk els hChainEls hIPEls
  -- `ifValThnRes … els = ifValElsRes … els` (same lowering shape).
  have hElsConv :
      (RunarVerification.ANF.Eval.evalBindings initialAnf els).toOption.isSome ↔
      (runOps (ifValElsRes progMethods props budget 0 lastUses [] constInts sm cond els).1
          branchStk).toOption.isSome := hElsIff
  -- Compose via the wave-41 body-level walk.
  exact successAgrees_ifVal_arith_unconditional progMethods props budget 0 lastUses
    localBindings constInts sm bn cond thn els src initialAnf initialStack branchStk
    (.vBool b) b hClean hCondRes2 hCondRun hCondBoolCoerce hThnIff hElsConv

/-! ### C (Wave 44) — MANDATORY smoke: the entry-level walk fires

The same `if (c) { t0=p0+p1; t1=t0+p2 } else { u0=p0-p1; u1=u0-p2 }`
(c a bool) instantiated from ONLY the omnibus entry bundle + `CondBoolTyped`
+ the `ifValArithBody` fragment — NO hand-supplied per-branch iffs, NO
hand-supplied cond/branch hypotheses (those are all DERIVED).  We obtain the
body-level iff and confirm the ANF side concretely succeeds, so the Script
side succeeds — anti-vacuous (the bridge is real). -/
private def sD_env : RunarVerification.ANF.WellTyped.TypeEnv :=
  ((((RunarVerification.ANF.Typed.TypeEnv.empty.extend "c" .bool).extend "p0" .bigint).extend
      "p1" .bigint).extend "p2" .bigint)

private theorem sD_typedEntry :
    RunarVerification.ANF.WellTyped.EntryBigintTyped sD_env sC_anf := by
  intro n hn
  by_cases h0 : n = "p0"
  · subst h0; exact ⟨.vBigint 3, rfl, ⟨3, rfl⟩⟩
  · by_cases h1 : n = "p1"
    · subst h1; exact ⟨.vBigint 4, rfl, ⟨4, rfl⟩⟩
    · by_cases h2 : n = "p2"
      · subst h2; exact ⟨.vBigint 5, rfl, ⟨5, rfl⟩⟩
      · exfalso
        by_cases hc : n = "c"
        · subst hc
          have hcb : sD_env.lookup "c" = some .bool := rfl
          rw [hcb] at hn; exact absurd hn (by decide)
        · have hp2 : ("p2" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h2 h.symm
          have hp1 : ("p1" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h1 h.symm
          have hp0 : ("p0" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h0 h.symm
          have hcc : ("c" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => hc h.symm
          simp only [sD_env, RunarVerification.ANF.Typed.TypeEnv.lookup,
            RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
            List.find?_cons, hp2, hp1, hp0, hcc, List.find?_nil, Option.map_none, reduceCtorEq] at hn

private theorem sD_tsmTyped : entryTsmArithTyped sD_env sC_branchTsm := by
  intro s hs
  unfold RunarVerification.ANF.WellTyped.arithOperandBigint
  simp only [sC_branchTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
  rcases hs with h | h | h <;> (subst h; decide)

private theorem sD_condBool :
    RunarVerification.ANF.WellTyped.CondBoolTyped sD_env sC_anf "c" := by
  refine ⟨rfl, ?_⟩
  intro n hn
  by_cases hc : n = "c"
  · subst hc; exact ⟨true, rfl⟩
  · exfalso
    by_cases h0 : n = "p0"
    · subst h0; have h : sD_env.lookup "p0" = some .bigint := rfl
      rw [h] at hn; exact absurd hn (by decide)
    · by_cases h1 : n = "p1"
      · subst h1; have h : sD_env.lookup "p1" = some .bigint := rfl
        rw [h] at hn; exact absurd hn (by decide)
      · by_cases h2 : n = "p2"
        · subst h2; have h : sD_env.lookup "p2" = some .bigint := rfl
          rw [h] at hn; exact absurd hn (by decide)
        · have hp2 : ("p2" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h2 h.symm
          have hp1 : ("p1" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h1 h.symm
          have hp0 : ("p0" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => h0 h.symm
          have hcc : ("c" == n) = false := by rw [beq_eq_false_iff_ne]; exact fun h => hc h.symm
          simp only [sD_env, RunarVerification.ANF.Typed.TypeEnv.lookup,
            RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
            List.find?_cons, hp2, hp1, hp0, hcc, List.find?_nil, Option.map_none, reduceCtorEq] at hn

/-- **Wave 44 C smoke — the entry-level walk fires from ONLY the bundle.**
The body-level iff holds, and the ANF `if_val` side concretely succeeds
(THEN branch `t0=3+4=7; t1=7+5=12`), so the Script side succeeds. -/
theorem wave44_successAgrees_ifVal_arith_from_entry_smoke :
    ((RunarVerification.ANF.Eval.evalBindings sC_anf sA_body).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 8 0 sA_lu []
            (List.map (fun b => b.name) sA_body) (Stack.Lower.collectConstInts sA_body)
            sA_sm sA_body).1 sC_stk).toOption.isSome)
    ∧ (RunarVerification.ANF.Eval.evalBindings sC_anf sA_body).toOption.isSome := by
  have hCCI : Stack.Lower.collectConstInts sA_body = [] := by
    unfold sA_body sA_thn sA_els
    simp only [Stack.Lower.collectConstInts, List.append_nil]
  rw [hCCI]
  have hCondAgrees : agreesTagged (("c", .param) :: sC_branchTsm) sC_anf sC_stk := by
    refine ⟨?_, rfl, rfl⟩
    show taggedStackAligned (("c", .param) :: sC_branchTsm) sC_anf sC_stk.stack
    refine ⟨rfl, rfl, rfl, rfl, ?_⟩; trivial
  have hCondCoh : tsmCoherent sC_anf (("c", .param) :: sC_branchTsm) := by
    intro s hs
    simp only [sC_branchTsm, List.mem_cons, List.not_mem_nil, or_false] at hs
    rcases hs with h | h | h | h <;> (subst h; rfl)
  -- The fragment (Deliverable A smoke shape) — note `constInts = []`.
  have hBodyFrag : ifValArithBody [] [] 8 0 sA_lu [] [] sA_sm sA_body := wave41_ifValArithBody_smoke
  have hUntagSm : Agrees.untagSm (("c", .param) :: sC_branchTsm) = sA_sm := by
    unfold sC_branchTsm untagSm sA_sm; rfl
  have hIP : ifValInnerProtected sA_sm "c" 0 sA_lu [] = [] := sA_ip
  -- Fire C from ONLY the bundle + cond-bool + fragment.
  have hIff := successAgrees_ifVal_arith_from_entry [] [] 8 sA_lu
    (List.map (fun b => b.name) sA_body) [] sD_env sA_sm "r" "c" .param sA_thn sA_els none
    sC_branchTsm sC_anf sC_stk hBodyFrag hCondAgrees sD_typedEntry sD_tsmTyped hCondCoh
    sD_condBool hUntagSm (by decide) hIP hIP
  refine ⟨hIff, ?_⟩
  -- ANF side concretely succeeds: THEN branch evaluates `t0=3+4=7; t1=7+5=12`.
  show (RunarVerification.ANF.Eval.evalBindings sC_anf sA_body).toOption.isSome
  unfold sA_body
  simp only [RunarVerification.ANF.Eval.evalBindings]
  have hCondRes2 : sC_anf.resolveRef "c" = some (.vBool true) := rfl
  have hThnEval :
      (RunarVerification.ANF.Eval.evalValue sC_anf (.ifVal "c" sA_thn sA_els)).toOption.isSome := by
    rw [evalValue_ifVal_isSome_iff_activeBranch sC_anf "c" sA_thn sA_els true hCondRes2]
    rw [if_pos (rfl : (true = true))]
    show (RunarVerification.ANF.Eval.evalBindings sC_anf sA_thn).toOption.isSome
    unfold sA_thn
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          sC_anf "t0" "+" "p0" "p1" none none 3 4 _ (Or.inl rfl) rfl rfl]
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          (sC_anf.addBinding "t0" (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint "+" 3 4)))
          "t1" "+" "t0" "p2" none none
          (RunarVerification.ANF.Eval.arithBinResultBigint "+" 3 4) 5 _ (Or.inl rfl) rfl rfl]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  cases h : RunarVerification.ANF.Eval.evalValue sC_anf (.ifVal "c" sA_thn sA_els) with
  | error e =>
      exfalso; rw [h] at hThnEval
      simp only [Except.toOption, Option.isSome, reduceCtorEq] at hThnEval
  | ok p =>
      simp only [bind, Except.bind, Except.toOption, Option.isSome]

/-! ### D — the `if_val` op-shape (emittability half)

The `.ifOp`-bearing analogue of `loweredEmittableArithNoDblNeg_opShape`'s
`AreRunarEmittable` conjunct.  Under `ifValCleanShape` the lowering collapses
(via `lowerValueP_ifVal_clean_shape`) to `condOps ++ [.ifOp thnOps (some elsOps)]`,
where the branch op-lists are emittable-arith (wave-38
`loweredEmittableArith_areEmittable` per branch) and the `.ifOp` node is
emittable via `AreRunarEmittableWithIf.if_some_cons`.  `condOps`
(`loadRefLive`) emittability is supplied as an input-side hypothesis
(`hCondEmit`); the smoke discharges it from the empty cond-load.

The peephole-identity conjunct of a full op-shape (`peepholeRollPickFold
(peepholeChainFold (peepholePostFold (peepholePassAll …))) = …`) for an
`.ifOp`-bearing list is NOT included here: it requires per-pass `.ifOp`
identity lemmas (each pass recurses into the branches via `postFoldOp` /
`chainFoldOp` / `rollPickOp` and the branches are `arithEmitNoFuse`-fixed,
but the outer-pass `.ifOp`-arm fixpoint needs dedicated lemmas added inside
`Stack/Peephole.lean` with access to its private mutual recursors).  See the
hand-off note. -/

/-- WithIf-emittability is closed under list append (the `.ifOp`-aware
analogue of `areRunarEmittable_append`). -/
theorem areRunarEmittableWithIf_append (a b : List StackOp)
    (ha : RunarVerification.Script.Parse.AreRunarEmittableWithIf a) (hb : RunarVerification.Script.Parse.AreRunarEmittableWithIf b) :
    RunarVerification.Script.Parse.AreRunarEmittableWithIf (a ++ b) := by
  induction a with
  | nil => simpa using hb
  | cons op rest ih =>
      cases ha with
      | cons _ _ hOp hRest =>
          exact RunarVerification.Script.Parse.AreRunarEmittableWithIf.cons op (rest ++ b) hOp (ih hRest)

/-- **Wave 41 D (emittability half) — `if_val` arith op-shape.**

For an `ifValArithBody` whose cond-load `condOps` is itself WithIf-emittable,
the lowered op-list is `AreRunarEmittableWithIf`: the clean-shape collapse
exposes `condOps ++ [.ifOp thnOps (some elsOps)]`, the branches are
emittable-arith (wave-38), and the `.ifOp` node is WithIf-emittable. -/
theorem loweredIfValArith_areEmittable
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (bn cond : String) (thn els : List ANFBinding) (src : Option SourceLoc)
    (hThnChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses thn) thn
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false)
    (hElsChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses els) els
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                [] constInts sm cond thn els)
    (hInnerEmpty : ifValInnerProtected sm cond currentIndex lastUses [] = [])
    (hCondEmit : RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1) :
    RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1 := by
  -- Script bridge + clean-shape collapse.
  have hScriptBridge :
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1
        = (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1
          ++ [StackOp.ifOp
                (ifValThnRes progMethods props budget currentIndex lastUses
                  [] constInts sm cond thn).1
                (some (ifValElsRes progMethods props budget currentIndex lastUses
                  [] constInts sm cond els).1)] := by
    rw [Stack.Lower.lowerBindingsP.eq_2]
    rcases h : Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm bn (.ifVal cond thn els) with ⟨o, s, l⟩
    simp only [Stack.Lower.lowerBindingsP, List.append_nil]
    have hcs := lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
      [] localBindings constInts sm bn cond thn els hClean
    rw [h] at hcs; exact hcs
  rw [hScriptBridge]
  -- Branch op-lists are emittable-arith.
  have hThnEmit : RunarVerification.Script.Parse.AreRunarEmittable
      (ifValThnRes progMethods props budget currentIndex lastUses [] constInts sm cond thn).1 := by
    rw [ifValThnRes_eq_default progMethods props budget currentIndex lastUses [] constInts
      sm cond thn
      (insideBranchFreeBodyB_of_emittableArithChainReadyNoDblNeg _ thn _ 0 false hThnChain)]
    rw [hInnerEmpty]
    exact loweredEmittableArith_areEmittable progMethods props budget
      (Stack.Lower.computeLastUses thn)
      constInts thn (List.map (fun b => b.name) thn)
      (ifValSmBranch sm cond currentIndex lastUses []) 0
      (emittableArithChainReadyNoDblNeg_imp_ready _ thn
        (ifValSmBranch sm cond currentIndex lastUses []) 0 false hThnChain)
  have hElsEmit : RunarVerification.Script.Parse.AreRunarEmittable
      (ifValElsRes progMethods props budget currentIndex lastUses [] constInts sm cond els).1 := by
    rw [ifValElsRes_eq_default progMethods props budget currentIndex lastUses [] constInts
      sm cond els
      (insideBranchFreeBodyB_of_emittableArithChainReadyNoDblNeg _ els _ 0 false hElsChain)]
    rw [hInnerEmpty]
    exact loweredEmittableArith_areEmittable progMethods props budget
      (Stack.Lower.computeLastUses els)
      constInts els (List.map (fun b => b.name) els)
      (ifValSmBranch sm cond currentIndex lastUses []) 0
      (emittableArithChainReadyNoDblNeg_imp_ready _ els
        (ifValSmBranch sm cond currentIndex lastUses []) 0 false hElsChain)
  -- ELSE op-list non-empty (from clean-shape).
  obtain ⟨_, _, _, _, hElsNE⟩ := hClean
  -- Assemble: condOps emittable ++ [.ifOp node emittable].
  apply areRunarEmittableWithIf_append _ _ hCondEmit
  cases hE : (ifValElsRes progMethods props budget currentIndex lastUses [] constInts sm cond els).1 with
  | nil => exact absurd hE hElsNE
  | cons eh et =>
      refine RunarVerification.Script.Parse.AreRunarEmittableWithIf.cons _ [] ?_ RunarVerification.Script.Parse.AreRunarEmittableWithIf.nil
      exact RunarVerification.Script.Parse.RunarEmittableWithIf.if_some_cons _ eh et
        (RunarVerification.Script.Parse.AreRunarEmittable.toWithIf _ hThnEmit)
        (RunarVerification.Script.Parse.AreRunarEmittable.toWithIf (eh :: et) (hE ▸ hElsEmit))

/-- **Wave 41 D smoke (emittability half) — the `if_val` op-shape fires.**
The lowered op-list of the concrete `sA_body` is `AreRunarEmittableWithIf`
(both branches emittable-arith, the `.ifOp` node WithIf-emittable, the empty
cond-load trivially emittable). -/
theorem wave41_loweredIfValArith_areEmittable_smoke :
    RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.lowerBindingsP [] [] 8 0 sA_lu []
        (List.map (fun b => b.name) sA_body) [] sA_sm sA_body).1 := by
  have hCondEmit : RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.loadRefLive sA_sm "c" 0 sA_lu []).1 := by
    have hEmpty : (Stack.Lower.loadRefLive sA_sm "c" 0 sA_lu []).1 = [] := by
      unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop sA_sm sA_lu sA_body sA_thn sA_els
      decide
    rw [hEmpty]; exact RunarVerification.Script.Parse.AreRunarEmittableWithIf.nil
  have h := loweredIfValArith_areEmittable [] [] 8 0 sA_lu
    (List.map (fun b => b.name) sA_body) [] sA_sm "r" "c" sA_thn sA_els none
    (by rw [sA_smBranch]; unfold sA_thn; decide)
    (by rw [sA_smBranch]; unfold sA_els; decide)
    sA_clean sA_ip hCondEmit
  exact h

/-! ### D (peephole-identity half) — the four-pass identity on the lowered
`ifValArithBody`

Mirror of `loweredEmittableArithNoDblNeg_opShape`'s M3 conjunct for the
`.ifOp`-bearing lowering.  The lowered op-list collapses (clean shape) to
`condOps ++ [.ifOp thnOps (some elsOps)]`; with an empty cond-load
(`hCondEmpty`, supplied by the Deliverable-C cond-load derivation) the list
IS the singleton `[.ifOp thnOps (some elsOps)]`.  Each of the four passes is
the identity on that singleton because each branch op-list is a per-pass
fixpoint (wave-38 arith identities) and the wave-42 `.ifOp` per-pass
identities lift each branch fixpoint to the node. -/

/-- A lowered emittable-arith branch op-list is a fixpoint of all four
peephole passes.  All four facts are discharged from the wave-38 shape
lemmas (`arithEmitNoFuse`, `noIfOp`, `pushFree`, `rollPickFoldFlatNoop`). -/
theorem loweredArithBranch_peephole_fixpoints
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (constInts : List (String × Int))
    (body : List ANFBinding) (localBindings : List String)
    (sm : StackMap) (currentIndex : Nat) (prevWasNeg : Bool)
    (hRef : emittableArithChainReadyNoDblNeg lastUses body sm currentIndex prevWasNeg) :
    Peephole.peepholePassAll
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
      = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
    ∧ Peephole.peepholePostFold
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
      = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
    ∧ Peephole.peepholeChainFold
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
      = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
    ∧ Peephole.peepholeRollPickFold
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1
      = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm body).1 := by
  have hReady : emittableArithChainReady lastUses body sm currentIndex :=
    emittableArithChainReadyNoDblNeg_imp_ready lastUses body sm currentIndex prevWasNeg hRef
  obtain ⟨hNoFuse, _⟩ :=
    loweredEmittableArithNoDblNeg_arithEmitNoFuse progMethods props budget lastUses constInts
      body localBindings sm currentIndex prevWasNeg hRef
  obtain ⟨hNoIf, hPushFree, hRpNoop⟩ :=
    loweredEmittableArith_m3ShapeFacts progMethods props budget lastUses constInts
      body localBindings sm currentIndex hReady
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [Peephole.peepholePassAll_eq_flat_of_noIfOp _ hNoIf]
    exact Peephole.peepholePassAllFlat_eq_self_of_arithEmit _ hNoFuse
  · exact Peephole.peepholePostFold_eq_self_of_arithEmit _ hNoIf hNoFuse
  · exact Peephole.peepholeChainFold_eq_self_of_noIfOp_pushFree _ hNoIf hPushFree
  · exact Peephole.peepholeRollPickFold_eq_self_of_noIfOp_flatNoop _ hNoIf hRpNoop

/-- **Wave 42 D (peephole-identity half) — `if_val` arith op-shape.**

For an `ifValArithBody` whose cond-load `condOps` is empty (`hCondEmpty`),
the four-pass `peepholeMethodOps` is the literal identity on the lowered
op-list: the clean-shape collapse exposes `[] ++ [.ifOp thnOps (some elsOps)]`,
each branch is a per-pass fixpoint (`loweredArithBranch_peephole_fixpoints`),
and the wave-42 `.ifOp` per-pass identities lift those to the singleton. -/
theorem loweredIfValArith_peepholeId
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (bn cond : String) (thn els : List ANFBinding) (src : Option SourceLoc)
    (hThnChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses thn) thn
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false)
    (hElsChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses els) els
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                [] constInts sm cond thn els)
    (hInnerEmpty : ifValInnerProtected sm cond currentIndex lastUses [] = [])
    (hCondEmpty : (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1 = []) :
    Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll
              (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1)))
    = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1 := by
  -- Script bridge + clean-shape collapse, then drop the empty cond prefix.
  have hScriptBridge :
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1
        = [StackOp.ifOp
              (ifValThnRes progMethods props budget currentIndex lastUses
                [] constInts sm cond thn).1
              (some (ifValElsRes progMethods props budget currentIndex lastUses
                [] constInts sm cond els).1)] := by
    rw [Stack.Lower.lowerBindingsP.eq_2]
    rcases h : Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm bn (.ifVal cond thn els) with ⟨o, s, l⟩
    simp only [Stack.Lower.lowerBindingsP, List.append_nil]
    have hcs := lowerValueP_ifVal_clean_shape progMethods props budget currentIndex lastUses
      [] localBindings constInts sm bn cond thn els hClean
    rw [h] at hcs
    simp only [hCondEmpty, List.nil_append] at hcs
    exact hcs
  rw [hScriptBridge]
  -- Both branches are per-pass fixpoints (after rewriting innerProtected → []).
  have hThnEq :
      (ifValThnRes progMethods props budget currentIndex lastUses [] constInts sm cond thn).1
      = (Stack.Lower.lowerBindingsP progMethods props budget 0 (Stack.Lower.computeLastUses thn)
          [] (List.map (fun b => b.name) thn) constInts
          (ifValSmBranch sm cond currentIndex lastUses []) thn).1 := by
    rw [ifValThnRes_eq_default progMethods props budget currentIndex lastUses [] constInts
      sm cond thn
      (insideBranchFreeBodyB_of_emittableArithChainReadyNoDblNeg _ thn _ 0 false hThnChain)]
    rw [hInnerEmpty]
  have hElsEq :
      (ifValElsRes progMethods props budget currentIndex lastUses [] constInts sm cond els).1
      = (Stack.Lower.lowerBindingsP progMethods props budget 0 (Stack.Lower.computeLastUses els)
          [] (List.map (fun b => b.name) els) constInts
          (ifValSmBranch sm cond currentIndex lastUses []) els).1 := by
    rw [ifValElsRes_eq_default progMethods props budget currentIndex lastUses [] constInts
      sm cond els
      (insideBranchFreeBodyB_of_emittableArithChainReadyNoDblNeg _ els _ 0 false hElsChain)]
    rw [hInnerEmpty]
  obtain ⟨hThnPassAll, hThnPostFold, hThnChainF, hThnRollP⟩ :=
    loweredArithBranch_peephole_fixpoints progMethods props budget
      (Stack.Lower.computeLastUses thn) constInts thn (List.map (fun b => b.name) thn)
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false hThnChain
  obtain ⟨hElsPassAll, hElsPostFold, hElsChainF, hElsRollP⟩ :=
    loweredArithBranch_peephole_fixpoints progMethods props budget
      (Stack.Lower.computeLastUses els) constInts els (List.map (fun b => b.name) els)
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false hElsChain
  rw [hThnEq, hElsEq]
  -- Apply the four-pass composition inside-out via the wave-42 `.ifOp` identities.
  rw [Peephole.peepholePassAll_singleton_ifOp_id _ _ hThnPassAll hElsPassAll]
  rw [Peephole.peepholePostFold_singleton_ifOp_id _ _ hThnPostFold hElsPostFold]
  rw [Peephole.peepholeChainFold_singleton_ifOp_id _ _ hThnChainF hElsChainF]
  rw [Peephole.peepholeRollPickFold_singleton_ifOp_id _ _ hThnRollP hElsRollP]

/-- **Wave 42 D — full `if_val` arith op-shape (both conjuncts).**

Combines the wave-41 emittability half (`loweredIfValArith_areEmittable`)
with the wave-42 peephole-identity half (`loweredIfValArith_peepholeId`)
into the `.ifOp`-bearing analogue of `loweredEmittableArithNoDblNeg_opShape`:
the lowered op-list is `AreRunarEmittableWithIf` AND `peepholeMethodOps` is
the literal identity on it — unconditional for the fragment (modulo the
`hCondEmpty` / `hInnerEmpty` derivations supplied by Deliverable C). -/
theorem loweredIfValArith_opShape
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (bn cond : String) (thn els : List ANFBinding) (src : Option SourceLoc)
    (hThnChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses thn) thn
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false)
    (hElsChain : emittableArithChainReadyNoDblNeg (Stack.Lower.computeLastUses els) els
      (ifValSmBranch sm cond currentIndex lastUses []) 0 false)
    (hClean : ifValCleanShape progMethods props budget currentIndex lastUses
                [] constInts sm cond thn els)
    (hInnerEmpty : ifValInnerProtected sm cond currentIndex lastUses [] = [])
    (hCondEmpty : (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1 = []) :
    RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1
    ∧ Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll
              (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1)))
      = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm [.mk bn (.ifVal cond thn els) src]).1 := by
  have hCondEmit : RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1 := by
    rw [hCondEmpty]; exact RunarVerification.Script.Parse.AreRunarEmittableWithIf.nil
  exact ⟨loweredIfValArith_areEmittable progMethods props budget currentIndex lastUses
      localBindings constInts sm bn cond thn els src hThnChain hElsChain hClean hInnerEmpty hCondEmit,
    loweredIfValArith_peepholeId progMethods props budget currentIndex lastUses
      localBindings constInts sm bn cond thn els src hThnChain hElsChain hClean hInnerEmpty hCondEmpty⟩

/-- **Wave 42 D smoke — the full `if_val` op-shape fires (both conjuncts).**
Instantiated on the concrete `sA_body`: the lowered op-list is
`AreRunarEmittableWithIf` and `peepholeMethodOps` is the identity on it. -/
theorem wave42_loweredIfValArith_opShape_smoke :
    RunarVerification.Script.Parse.AreRunarEmittableWithIf
      (Stack.Lower.lowerBindingsP [] [] 8 0 sA_lu []
        (List.map (fun b => b.name) sA_body) [] sA_sm sA_body).1
    ∧ Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll
              (Stack.Lower.lowerBindingsP [] [] 8 0 sA_lu []
                (List.map (fun b => b.name) sA_body) [] sA_sm sA_body).1)))
      = (Stack.Lower.lowerBindingsP [] [] 8 0 sA_lu []
          (List.map (fun b => b.name) sA_body) [] sA_sm sA_body).1 := by
  have hCondEmpty : (Stack.Lower.loadRefLive sA_sm "c" 0 sA_lu []).1 = [] := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop sA_sm sA_lu sA_body sA_thn sA_els
    decide
  exact loweredIfValArith_opShape [] [] 8 0 sA_lu
    (List.map (fun b => b.name) sA_body) [] sA_sm "r" "c" sA_thn sA_els none
    (by rw [sA_smBranch]; unfold sA_thn; decide)
    (by rw [sA_smBranch]; unfold sA_els; decide)
    sA_clean sA_ip hCondEmpty

/-! ### C — method-level `condOps` / `ifValInnerProtected` derivation

The wave-41 / wave-42 op-shape lemmas take `hInnerEmpty` and `hCondEmpty`
as hypotheses.  For the retirement these are DERIVED from the fragment +
single-public-method entry:

* `hCondEmpty` — the `if_val` condition is the **head** slot (`sm.depth?
  cond = some 0`) and its last use is the if itself (`isLastUse` at
  `currentIndex`); the consume path of `bringToTop` at depth 0 emits `[]`.
* `hInnerEmpty` — the branches are self-contained: no ref in the branch
  stackmap is alive after the if (`isLastUse … = true` for every entry),
  and the parent-protected set is empty (top-level entry), so
  `computeBranchProtected` never appends and stays `[]`. -/

/-- **Wave 42 C — empty cond-load derivation.**  When the cond is the head
slot and its last use is the if, `loadRefLive` (consume at depth 0) emits no
ops.  This supplies `hCondEmpty` for `loweredIfValArith_opShape`. -/
theorem ifValCondLoad_empty
    (sm : StackMap) (cond : String) (currentIndex : Nat)
    (lastUses : List (String × Nat))
    (hHead : sm.depth? cond = some 0)
    (hLast : Stack.Lower.isLastUse lastUses cond currentIndex = true) :
    (Stack.Lower.loadRefLive sm cond currentIndex lastUses []).1 = [] := by
  unfold Stack.Lower.loadRefLive
  have hConsume : (!Stack.Lower.listContains [] cond
      && Stack.Lower.isLastUse lastUses cond currentIndex) = true := by
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and, hLast]
  rw [hConsume]
  unfold Stack.Lower.bringToTop
  rw [hHead]
  simp only [if_true]

/-- `computeBranchProtected smBranch lastUses currentIndex []` is `[]` when no
entry is alive after `currentIndex` (every entry's `isLastUse` is `true`) and
the parent-protected set is empty.  The foldl accumulator never grows: at the
empty initial accumulator each step's `aliveAfter` and `parentProtected` are
both false, so the `acc ++ [ref]` arm is never taken. -/
private theorem computeBranchProtected_nil_of_allLastUse
    (smBranch : Stack.Lower.StackMap) (lastUses : List (String × Nat))
    (currentIndex : Nat)
    (hAll : ∀ ref ∈ smBranch, ∀ nm, ref = some nm →
      Stack.Lower.isLastUse lastUses nm currentIndex = true) :
    Stack.Lower.computeBranchProtected smBranch lastUses currentIndex [] = [] := by
  unfold Stack.Lower.computeBranchProtected
  -- The accumulator stays `[]`: prove the foldl-invariant `acc = []`.
  -- An anonymous slot short-circuits to `acc`, so it cannot grow it either.
  suffices h : ∀ (acc : List String), acc = [] →
      List.foldl
        (fun acc slot =>
          match slot with
          | none => acc
          | some ref =>
          if Stack.Lower.listContains acc ref then acc
          else
            let aliveAfter :=
              match Stack.Lower.lastUsesLookup lastUses ref with
              | some idx => decide (idx > currentIndex)
              | none => false
            let parentProtected := Stack.Lower.listContains [] ref
            if aliveAfter || parentProtected then acc ++ [ref] else acc)
        acc smBranch = [] by
    exact h [] rfl
  induction smBranch with
  | nil => intro acc hacc; simp [hacc]
  | cons hd rest ih =>
      intro acc hacc
      subst hacc
      have hTail : ∀ ref ∈ rest, ∀ nm, ref = some nm →
          Stack.Lower.isLastUse lastUses nm currentIndex = true :=
        fun ref hRef => hAll ref (List.mem_cons_of_mem hd hRef)
      cases hd with
      | none => simpa using ih hTail [] rfl
      | some hdName =>
      have hHd : Stack.Lower.isLastUse lastUses hdName currentIndex = true :=
        hAll (some hdName) (List.mem_cons_self) hdName rfl
      have hAlive :
          (match Stack.Lower.lastUsesLookup lastUses hdName with
           | some idx => decide (idx > currentIndex)
           | none => false) = false := by
        unfold Stack.Lower.isLastUse at hHd
        cases hLk : Stack.Lower.lastUsesLookup lastUses hdName with
        | none => rfl
        | some last =>
            rw [hLk] at hHd
            simp only [decide_eq_true_eq] at hHd
            simp only [decide_eq_false_iff_not, Nat.not_lt]
            exact hHd
      simp only [List.foldl_cons, Stack.Lower.listContains, List.any_nil,
        Bool.false_eq_true, if_false, hAlive, Bool.or_self, if_false]
      exact ih hTail [] rfl

/-- **Wave 42 C — empty `ifValInnerProtected` derivation.**  Self-contained
branches (no branch-stackmap entry alive after the if) at a top-level entry
(`outerProtected = []`) yield an empty protected set.  This supplies
`hInnerEmpty` for `loweredIfValArith_opShape`. -/
theorem ifValInnerProtected_empty
    (sm : StackMap) (cond : String) (currentIndex : Nat)
    (lastUses : List (String × Nat))
    (hAll : ∀ ref ∈ ifValSmBranch sm cond currentIndex lastUses [], ∀ nm, ref = some nm →
      Stack.Lower.isLastUse lastUses nm currentIndex = true) :
    ifValInnerProtected sm cond currentIndex lastUses [] = [] := by
  unfold ifValInnerProtected
  exact computeBranchProtected_nil_of_allLastUse
    (ifValSmBranch sm cond currentIndex lastUses []) lastUses currentIndex hAll

/-! ### Wave 42 C smoke — the derivations fire on the concrete `sA_*` method.

The single-public if-cond method `sA_body` has cond `"c"` at the head slot
(`sA_sm = ["c", "p0", "p1", "p2"]`) with its last use at index 0, so the
cond-load is `[]`; and every branch-stackmap entry's last use is ≤ 0, so the
inner-protected set is `[]`. -/

private theorem sA_cond_head : sA_sm.depth? "c" = some 0 := by
  unfold sA_sm; decide

private theorem sA_cond_lastUse :
    Stack.Lower.isLastUse sA_lu "c" 0 = true := by
  unfold sA_lu sA_body sA_thn sA_els
  decide

example : (Stack.Lower.loadRefLive sA_sm "c" 0 sA_lu []).1 = [] :=
  ifValCondLoad_empty sA_sm "c" 0 sA_lu sA_cond_head sA_cond_lastUse

example : ifValInnerProtected sA_sm "c" 0 sA_lu [] = [] := by
  apply ifValInnerProtected_empty
  rw [sA_smBranch]
  intro ref hRef
  unfold sA_lu sA_body sA_thn sA_els
  rcases List.mem_cons.mp hRef with h | h
  · subst h; decide
  rcases List.mem_cons.mp h with h | h
  · subst h; decide
  · rw [List.mem_singleton] at h; subst h; decide

end -- attribute [local irreducible] section

end Agrees
end RunarVerification.Stack

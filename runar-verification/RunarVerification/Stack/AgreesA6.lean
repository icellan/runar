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

* No `sorry` / `admit` / `partial def` / `axiom`.
* No `hRunOk` shortcut: the cond-load witness mentions only
  `loadRef sm cond` (the prefix of the lowered ops), not the full
  ifVal-bearing op list, and never `runMethod` itself.

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

end Agrees
end RunarVerification.Stack

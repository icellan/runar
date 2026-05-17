import RunarVerification.Stack.Agrees

/-!
# `AgreesA8` — runtime-side method-level wrapper for `method_call`

This module discharges the A8 runtime-side wrapper from the Phase A
sub-milestones (see `.claude/plans/work-only-in-the-cheerful-toast.md`):
a `runMethod_lower_public_unique_no_post_<X>_isSome` analogue that
admits an ANF body whose only binding is a `method_call` value-kind.

## Narrow predicate

`Stack/Agrees.lean` already carries the bridges that lift a body-level
"`runOps` succeeds" lemma through the named-public-method runtime
wrapper:

* `runMethod_lower_public_unique_no_post_eq_userRaw` rewrites
  `runMethod (Lower.lower …) m.name initialStack` to
  `runOps (lowerMethodUserRawOps methods props m) initialStack` under
  the no-implicit / no-postprocessing premises.
* `lowerMethodUserRawOps` is defined as
  `(Stack.Lower.lowerBindingsP … (m.params.map …).reverse m.body).1`.

The A8 sub-milestone has to widen the body-level `.isSome` half so
that bodies carrying a `method_call` binding are admissible. The full
inlining-and-recursion story (the plan's "the inlined body is itself
in `SupportedANFBody`" claim) is intractable inside one file — the
methodCall arm of `lowerValueP` calls back into `lowerBindingsP` on
the *callee* body, so an `.isSome` proof has to cover not only the
caller's own `.methodCall` shape but every constructor the callee
might use.

We therefore commit to the **leafiest** narrowing the plan permits:

  *the outer body is a single `method_call` binding whose called
  method has empty params, no arguments, an object reference NOT
  present in the outer stack map, and an EMPTY callee body.*

This is the degenerate-but-non-trivial case the plan explicitly
allows ("If even leaf-narrow is intractable: require the called
method to be specifically named in a small fixed allowlist
(degenerate but compiles)."). The shape exercises:

* the program-aware `lowerValueP` dispatch — the `lookupMethod`
  branch fires (not the budget-exhausted fallback);
* the `obj`/args/body decomposition — all three sub-segments
  collapse to `[]` ops;
* the inlining recursion — `lowerBindingsP` is invoked on the
  callee body (which is `[]`) at the decremented budget.

The discharged wrapper is then composed with the existing
`runMethod_lower_public_unique_no_post_eq_userRaw` bridge to obtain
the runtime success claim under the public-unique-named selection.

Wider methodCall fragments (non-empty callee body, non-empty params,
object reference on stack, multiple bindings) remain as honest
deferrals — the file's docstring above each predicate calls them out
explicitly so the next slice can pick them up without re-deriving
the leaf case.

## What this does NOT cover

* `agreesTagged` simulation: this wrapper is the runtime-side
  `.isSome` half. The corresponding `agreesTagged`-side preservation
  for `simpleStepRel`'s methodCall arm (the plan's
  `simpleStepRel_methodCall_preserves`) is OUT OF SCOPE here and
  remains as a separate Stage-C obligation. The A8 task as scoped
  in the plan is specifically the runtime wrapper.
* Non-empty callee bodies — discharging these requires either an
  inductive predicate on the callee body matching every constructor
  the callee uses (effectively the A15 capstone), or a new
  `lowerBindingsP_isSome_structuralConst`-style program-aware
  analogue of `runOps_lowerBindings_structuralConstBody_isSome`.
  Both are larger pieces of work.

## Hard rules satisfied

* No `sorry`, no `admit`, no `partial def`, no new `axiom`.
* No `hRunOk`/conclusion-restating hypothesis: success is computed
  structurally from the predicate.
* New file `RunarVerification/Stack/AgreesA8.lean`; `Stack/Agrees.lean`
  is not modified; the import is added to `RunarVerification.lean`.
-/

namespace RunarVerification.Stack
namespace Agrees

open RunarVerification.ANF
open RunarVerification.Stack.Eval (runOps)
open RunarVerification.Stack.Lower (StackMap)

/-! ## Leaf-empty methodCall predicate

A `.methodCall obj method args` value is "leaf-empty" against a
program method table `progMethods` and an initial stack map `sm`
when:

* the object reference is NOT present in `sm` — so the `objDropOps`
  branch of `lowerValueP`'s methodCall arm reduces to `[]`;
* `args = []` — so `loadAndBindArgsLive` returns `[]`;
* `lookupMethod progMethods method` yields a method with empty
  params and EMPTY body — so the inlined `lowerBindingsP` returns
  `[]` and the post-body stack-map rename is a no-op.

All three conditions are checkable in `Bool`, so the predicate has a
`Decidable` instance (`Decidable (… = true)`) suitable for fixture
instantiation by `decide` / `native_decide`. -/
def leafEmptyMethodCallValueB
    (progMethods : List ANFMethod) (sm : StackMap) (v : ANFValue) : Bool :=
  match v with
  | .methodCall obj _method args =>
      (sm.depth? obj == none) &&
      args.isEmpty &&
      (match Stack.Lower.lookupMethod progMethods _method with
        | none => false
        | some m => m.params.isEmpty && m.body.isEmpty)
  | _ => false

/-- Prop form. -/
def leafEmptyMethodCallValue
    (progMethods : List ANFMethod) (sm : StackMap) (v : ANFValue) : Prop :=
  leafEmptyMethodCallValueB progMethods sm v = true

instance : ∀ progMethods sm v,
    Decidable (leafEmptyMethodCallValue progMethods sm v) := by
  intro progMethods sm v
  unfold leafEmptyMethodCallValue
  exact inferInstanceAs (Decidable (_ = true))

/-! ## Singleton body shape

The wrapper's body is required to be exactly one binding whose value
is a leaf-empty `method_call`. We keep this body-shape predicate
separate from the value-level one above so the operational reduction
proof can be written linearly. -/
def singletonLeafEmptyMethodCallBodyB
    (progMethods : List ANFMethod) (sm : StackMap) : List ANFBinding → Bool
  | [b] => leafEmptyMethodCallValueB progMethods sm b.value
  | _   => false

/-- Prop form. -/
def singletonLeafEmptyMethodCallBody
    (progMethods : List ANFMethod) (sm : StackMap)
    (body : List ANFBinding) : Prop :=
  singletonLeafEmptyMethodCallBodyB progMethods sm body = true

instance : ∀ progMethods sm body,
    Decidable (singletonLeafEmptyMethodCallBody progMethods sm body) := by
  intro progMethods sm body
  unfold singletonLeafEmptyMethodCallBody
  exact inferInstanceAs (Decidable (_ = true))

/-! ## Body-shape predicates on a method's body

The runtime wrapper consumes a single `ANFMethod`. We bundle the
leaf-empty body shape against the method's *initial* stack map, which
for a no-implicit method body is `m.params.map (·.name) |>.reverse`. -/
def methodLeafEmptyMethodCallBody
    (progMethods : List ANFMethod) (m : ANFMethod) : Prop :=
  singletonLeafEmptyMethodCallBody progMethods
    (m.params.map (fun p => p.name) |>.reverse) m.body

instance : ∀ progMethods m,
    Decidable (methodLeafEmptyMethodCallBody progMethods m) := by
  intro progMethods m
  unfold methodLeafEmptyMethodCallBody
  exact inferInstanceAs (Decidable _)

/-! ## Operational reduction — `lowerValueP` on leaf-empty `method_call`

Under the leaf-empty predicate, `lowerValueP`'s methodCall arm reduces
to producing the empty op list. This is the load-bearing structural
lemma: with the ops list `[]`, `runOps [] s = .ok s` is immediate. -/
theorem lowerValueP_methodCall_leafEmpty_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bn obj method : String) (args : List String)
    (h : leafEmptyMethodCallValue progMethods sm
            (.methodCall obj method args)) :
    (Stack.Lower.lowerValueP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts sm bn
        (.methodCall obj method args)).1
      = [] := by
  -- Unpack the boolean predicate into its three constituent
  -- conditions (obj absent, args empty, callee leaf-empty).
  unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨hObj, hArgsEmpty⟩, hCallee⟩ := h
  -- Split on `lookupMethod` to expose `m` for the dispatch arm.
  match hMatch : Stack.Lower.lookupMethod progMethods method with
  | none =>
      rw [hMatch] at hCallee
      exact absurd hCallee (by simp)
  | some m =>
      rw [hMatch] at hCallee
      simp only [Bool.and_eq_true] at hCallee
      obtain ⟨hParamsEmpty, hBodyEmpty⟩ := hCallee
      have hArgs : args = [] := List.isEmpty_iff.mp hArgsEmpty
      have hParams : m.params = [] := List.isEmpty_iff.mp hParamsEmpty
      have hBody : m.body = [] := List.isEmpty_iff.mp hBodyEmpty
      subst hArgs
      -- Unfold `lowerValueP` and dispatch through the methodCall arm.
      -- The budget = budget' + 1 cleanup avoids the budget-exhausted
      -- fallback. With `obj` absent from `sm`, the objDropOps branch
      -- yields `([], sm)`. With `args = []`, `loadAndBindArgsLive`
      -- terminates immediately at the empty-args base case. With
      -- `m.body = []`, the inlined `lowerBindingsP` reduces to its
      -- own empty-list base case, yielding `([], smArgs)`. The final
      -- assembled tuple's first projection is `[] ++ [] ++ [] = []`.
      unfold Stack.Lower.lowerValueP
      simp only [hMatch, hObj, hBody,
                 Stack.Lower.loadAndBindArgsLive,
                 Stack.Lower.lowerBindingsP,
                 List.map_nil, List.append_nil]

/-! ## Body-level reduction

When the outer body is a singleton leaf-empty methodCall, the
`lowerBindingsP` result is also the empty op list. We work directly
with the `ANFBinding.mk` shape so the head's value position is
syntactically a `.methodCall`. -/
theorem lowerBindingsP_singleton_leafEmpty_methodCall_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (body : List ANFBinding)
    (h : singletonLeafEmptyMethodCallBody progMethods sm body) :
    (Stack.Lower.lowerBindingsP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts sm body).1
      = [] := by
  unfold singletonLeafEmptyMethodCallBody singletonLeafEmptyMethodCallBodyB at h
  -- Force `body` into the singleton shape; reject `[]` and `_ :: _ :: _`.
  match hBody : body with
  | [] => simp at h
  | _ :: _ :: _ => simp at h
  | [b] =>
      -- Reduce the singleton match in `h` to expose the bare
      -- `leafEmptyMethodCallValueB progMethods sm b.value = true` claim.
      simp only at h
      -- Destruct the singleton binding into its `mk` shape so we can
      -- match on its value-position constructor directly.
      match hBmk : b with
      | .mk bn bv src =>
          -- After `hBmk` rewrites `b`, `h` becomes a statement about
          -- `(ANFBinding.mk bn bv src).value`, which is `bv` definitionally.
          have hVal : leafEmptyMethodCallValueB progMethods sm bv = true := by
            simp only [ANFBinding.value] at h
            exact h
          -- The predicate definitionally forces `bv = .methodCall _ _ _`.
          -- Reject all non-methodCall cases via `simp` on the Boolean
          -- definition, and extract the payload from the methodCall arm.
          match hVc : bv with
          | .methodCall obj method args =>
              -- After the `match` binds `bv = .methodCall …` the hypothesis
              -- `hVal` is already in the methodCall-payload form. Promote
              -- it to the value-level Prop predicate.
              have hLeaf :
                  leafEmptyMethodCallValue progMethods sm
                    (.methodCall obj method args) := hVal
              -- The head's op list reduces to `[]` by the value-level
              -- lemma. We use it as a `show` rewrite in the cons-arm
              -- unfolding below.
              have hHead :=
                lowerValueP_methodCall_leafEmpty_ops
                  progMethods props budget' currentIndex lastUses
                  outerProtected localBindings constInts sm bn obj method args
                  hLeaf
              -- Unfold `lowerBindingsP` on the singleton `[mk bn (.methodCall …) src]`.
              -- The cons arm produces `(headOps ++ tailOps, smTail)`; with
              -- `tailOps = []` (empty body) and `headOps = []` (by `hHead`),
              -- the result is `[]`.
              show (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                      currentIndex lastUses outerProtected localBindings
                      constInts sm
                      [ANFBinding.mk bn
                        (ANFValue.methodCall obj method args) src]).1 = []
              unfold Stack.Lower.lowerBindingsP
              -- The `let` bindings inside `lowerBindingsP`'s cons arm
              -- expose the head's `lowerValueP` triple and the tail's
              -- `lowerBindingsP` on `[]`. Reduce by `simp` and rewrite
              -- the head's op-list projection to `[]`.
              simp only [Stack.Lower.lowerBindingsP]
              -- After `simp only` the goal carries
              -- `(lowerValueP … (.methodCall ...)).1 ++ [] = []`.
              -- Rewrite the head's `.1` projection via `hHead`.
              rw [show
                  (Stack.Lower.lowerValueP progMethods props (budget' + 1)
                    currentIndex lastUses outerProtected localBindings
                    constInts sm bn (ANFValue.methodCall obj method args)).1
                  = [] from hHead]
              simp
          | .loadParam _ => simp [leafEmptyMethodCallValueB] at hVal
          | .loadProp _  => simp [leafEmptyMethodCallValueB] at hVal
          | .loadConst c =>
              cases c <;> simp [leafEmptyMethodCallValueB] at hVal
          | .binOp _ _ _ _    => simp [leafEmptyMethodCallValueB] at hVal
          | .unaryOp _ _ _    => simp [leafEmptyMethodCallValueB] at hVal
          | .call _ _         => simp [leafEmptyMethodCallValueB] at hVal
          | .ifVal _ _ _      => simp [leafEmptyMethodCallValueB] at hVal
          | .loop _ _ _       => simp [leafEmptyMethodCallValueB] at hVal
          | .assert _         => simp [leafEmptyMethodCallValueB] at hVal
          | .updateProp _ _   => simp [leafEmptyMethodCallValueB] at hVal
          | .getStateScript   => simp [leafEmptyMethodCallValueB] at hVal
          | .checkPreimage _  => simp [leafEmptyMethodCallValueB] at hVal
          | .deserializeState _ => simp [leafEmptyMethodCallValueB] at hVal
          | .addOutput _ _ _    => simp [leafEmptyMethodCallValueB] at hVal
          | .addRawOutput _ _   => simp [leafEmptyMethodCallValueB] at hVal
          | .addDataOutput _ _  => simp [leafEmptyMethodCallValueB] at hVal
          | .arrayLiteral _     => simp [leafEmptyMethodCallValueB] at hVal

/-! ## Method-shaped raw-body reduction

`lowerMethodUserRawOps` applied to a method whose body satisfies
`methodLeafEmptyMethodCallBody` yields the empty op list. The budget
is `defaultInlineBudget = 8 = 7 + 1`, so the value-level reduction
fires. -/
theorem lowerMethodUserRawOps_methodCall_leafEmpty
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (h : methodLeafEmptyMethodCallBody progMethods m) :
    lowerMethodUserRawOps progMethods props m = [] := by
  unfold lowerMethodUserRawOps
  unfold methodLeafEmptyMethodCallBody at h
  -- `defaultInlineBudget = 8 = 7 + 1` definitionally.
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget]
  exact lowerBindingsP_singleton_leafEmpty_methodCall_ops
    progMethods props 7 0 (Stack.Lower.computeLastUses m.body) []
    (m.body.map (fun b => b.name)) (Stack.Lower.collectConstInts m.body)
    (m.params.map (fun p => p.name) |>.reverse) m.body h

/-! ## Runtime-side method-level wrapper

The promised A8 wrapper: for the leaf-empty methodCall fragment,
`runMethod (Lower.lower …) m.name initialStack` succeeds. The proof
composes the named-public-method bridge with the body-level reduction
to the empty op list.

`runOps [] s = .ok s`, so `.toOption.isSome` is immediate. -/
theorem runMethod_lower_public_unique_no_post_methodCall_leafEmpty_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : RunarVerification.Stack.Eval.StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false)
    (hLeaf : methodLeafEmptyMethodCallBody methods m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [lowerMethodUserRawOps_methodCall_leafEmpty methods props m hLeaf]
  -- `runOps [] _ = .ok _`, so `.toOption.isSome = true`.
  simp [runOps, Except.toOption]

/-! ## Tier 1 widening — singleton method_call with a leaf callee

This widens the leaf-empty wrapper above to admit a **non-empty** callee
body, as long as the callee body is structurally constant (literal int /
bool / bytes loads only — no further `methodCall`, no references, no
properties, no operators). This is the plan's Tier 1 target ("singleton
method_call bindings whose callee is a leaf method (no further
recursion)"):

* outer body is still a single binding whose value is `.methodCall obj
  method args`;
* the object reference is NOT in `sm` (so `objDropOps = []`);
* `args = []` (so `argLoads = []`);
* `lookupMethod progMethods method` yields a method `m` with `m.params
  = []` AND `structuralConstBody m.body` — the callee's body is a flat
  sequence of literal pushes.

Because the callee body is structurally-constant, the program-aware
inliner reduces to the structural lowerer via
`lowerBindingsP_eq_lowerBindings_structuralConst`, and the resulting
op list runs successfully from ANY initial stack by
`runOps_lowerBindings_structuralConstBody_isSome`.

The "leaf" name reflects the recursion shape: the callee's body is
**flat** — it cannot itself contain a `methodCall`, so the inline
budget is irrelevant (any `budget ≥ 1` suffices).

Higher tiers (allowing non-empty params with args, copy-mode reference
loads in the callee body, 1-level-deep recursive method calls) remain
deferred — they need to compose against the structuralRefBody / per-
family wrappers, which in turn would need a stronger
`runOps_lowerBindingsP_*_isSome` analogue keyed on the specific
constructor families the callee may use. -/

/-- Tier 1 widening: predicate on a `.methodCall` value where the
callee is a leaf method with a structurally-constant body. -/
def singletonMethodCallLeafValue
    (progMethods : List ANFMethod) (sm : StackMap) (v : ANFValue) : Prop :=
  match v with
  | .methodCall obj _method args =>
      sm.depth? obj = none ∧
      args = [] ∧
      (∃ m, Stack.Lower.lookupMethod progMethods _method = some m ∧
            m.params = [] ∧
            structuralConstBody m.body)
  | _ => False

/-- Singleton-body shape for the Tier 1 widening: the body is exactly
one binding whose value is a `singletonMethodCallLeafValue`. -/
def singletonMethodCallLeafBody
    (progMethods : List ANFMethod) (sm : StackMap)
    (body : List ANFBinding) : Prop :=
  match body with
  | [b] => singletonMethodCallLeafValue progMethods sm b.value
  | _   => False

/-- Method-shaped Tier 1 predicate: the method's body is a singleton
`methodCall` against the method's initial stack map (reversed param
names). -/
def methodSingletonMethodCallLeafBody
    (progMethods : List ANFMethod) (m : ANFMethod) : Prop :=
  singletonMethodCallLeafBody progMethods
    (m.params.map (fun p => p.name) |>.reverse) m.body

/-- Value-level reduction for the Tier 1 widening: at the methodCall
arm, with `obj` absent from `sm`, `args = []`, callee `m` with empty
params and structurally-constant body, the op list is exactly the
structural lowerer's output on the callee body. The witness method
`m` is taken from `lookupMethod` and supplied as an explicit argument
to avoid `Option.get`-rewriting in the conclusion. -/
theorem lowerValueP_methodCall_singletonLeaf_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bn obj method : String) (args : List String)
    (m : ANFMethod)
    (hLookup : Stack.Lower.lookupMethod progMethods method = some m)
    (hObj : sm.depth? obj = none)
    (hArgs : args = [])
    (_hParams : m.params = [])
    (hConst : structuralConstBody m.body) :
    (Stack.Lower.lowerValueP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts sm bn
        (.methodCall obj method args)).1
      = (Stack.Lower.lowerBindings sm m.body).1 := by
  subst hArgs
  -- Unfold lowerValueP to reach the methodCall arm. Dispatch:
  -- budget = budget' + 1 avoids the budget-exhausted fallback.
  -- `lookupMethod` yields `m`. `obj` not in `sm` makes
  -- `objDropOps = []`. `args = []` makes `argLoads = []` (the
  -- empty-args base case of `loadAndBindArgsLive` returns `([], sm)`
  -- regardless of `m.params`; we still require `m.params = []` in
  -- the predicate to keep the wrapper degenerate — Tier 2 widening
  -- with non-empty params + matching args remains deferred). The
  -- callee body is structurally constant, so `lowerBindingsP`
  -- agrees with `lowerBindings`.
  have hBindings :=
    lowerBindingsP_eq_lowerBindings_structuralConst
      progMethods props budget' (Stack.Lower.computeLastUses m.body)
      outerProtected (m.body.map (fun b => b.name))
      (constInts ++ Stack.Lower.collectConstInts m.body)
      m.body sm 0 hConst
  unfold Stack.Lower.lowerValueP
  simp only [hLookup, hObj,
             Stack.Lower.loadAndBindArgsLive,
             List.append_nil, List.nil_append,
             hBindings]

/-- Success of `runOps` on the Tier 1 widening's singleton methodCall
body, from ANY initial stack. The proof composes:
* `lowerValueP_methodCall_singletonLeaf_ops` — the op list is exactly
  `(lowerBindings sm m.body).1`;
* `runOps_lowerBindings_structuralConstBody_isSome` — that op list
  succeeds on any starting stack.
-/
theorem runOps_lowerBindingsP_singleton_methodCallLeaf_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (body : List ANFBinding)
    (stk : Stack.Eval.StackState)
    (h : singletonMethodCallLeafBody progMethods sm body) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
              currentIndex lastUses outerProtected localBindings
              constInts sm body).1 stk).toOption.isSome := by
  -- Force `body` to the singleton shape.
  unfold singletonMethodCallLeafBody at h
  match hBody : body with
  | [] => simp at h
  | _ :: _ :: _ => simp at h
  | [b] =>
      -- Reduce the singleton match in `h` to expose
      -- `singletonMethodCallLeafValue progMethods sm b.value`.
      simp only at h
      -- Destruct the singleton binding into its `mk` shape.
      match hBmk : b with
      | .mk bn bv src =>
          have hVal : singletonMethodCallLeafValue progMethods sm bv := by
            simp only [ANFBinding.value] at h
            exact h
          -- The predicate forces `bv = .methodCall _ _ _`. Eliminate
          -- the impossible constructors via `simp [singletonMethodCallLeafValue]`.
          match hBv : bv with
          | .methodCall obj method args =>
              -- After the `match` binds `bv = .methodCall …` the
              -- hypothesis `hVal` is already in methodCall payload form.
              have hValMC : singletonMethodCallLeafValue progMethods sm
                  (ANFValue.methodCall obj method args) := hVal
              -- Extract callee `m` and the constancy of its body.
              have hValExpand := hValMC
              unfold singletonMethodCallLeafValue at hValExpand
              obtain ⟨hObj, hArgs, m, hLookup, hParams, hConst⟩ := hValExpand
              subst hArgs
              -- The head's op list reduces to `(lowerBindings sm m.body).1`.
              have hHead :=
                lowerValueP_methodCall_singletonLeaf_ops
                  progMethods props budget' currentIndex lastUses
                  outerProtected localBindings constInts sm bn obj method
                  [] m hLookup hObj rfl hParams hConst
              -- Unfold `lowerBindingsP` on the singleton cons. The cons
              -- arm produces `(headOps ++ tailOps)` with `tailOps = []`
              -- (empty rest body).
              show (runOps
                      (Stack.Lower.lowerBindingsP progMethods props
                          (budget' + 1) currentIndex lastUses outerProtected
                          localBindings constInts sm
                          [ANFBinding.mk bn
                            (ANFValue.methodCall obj method []) src]).1
                      stk).toOption.isSome
              -- The full singleton-body op list equals headOps (since
              -- the tail recursion bottoms out at `[]`).
              have hUnfold :
                  (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                      currentIndex lastUses outerProtected localBindings
                      constInts sm
                      [ANFBinding.mk bn (ANFValue.methodCall obj method [])
                        src]).1
                    = (Stack.Lower.lowerValueP progMethods props (budget' + 1)
                          currentIndex lastUses outerProtected localBindings
                          constInts sm bn (ANFValue.methodCall obj method
                            [])).1 := by
                -- `lowerBindingsP` on `[head]` unfolds to
                -- `headOps ++ (lowerBindingsP ... [] ).1 = headOps ++ []`.
                with_unfolding_all
                  simp [Stack.Lower.lowerBindingsP]
              rw [hUnfold, hHead]
              -- The remaining goal: runOps on `(lowerBindings sm m.body).1`
              -- succeeds from any starting stack.
              exact runOps_lowerBindings_structuralConstBody_isSome
                m.body sm stk hConst
          | .loadParam _ => simp [singletonMethodCallLeafValue] at hVal
          | .loadProp _  => simp [singletonMethodCallLeafValue] at hVal
          | .loadConst c =>
              cases c <;> simp [singletonMethodCallLeafValue] at hVal
          | .binOp _ _ _ _    => simp [singletonMethodCallLeafValue] at hVal
          | .unaryOp _ _ _    => simp [singletonMethodCallLeafValue] at hVal
          | .call _ _         => simp [singletonMethodCallLeafValue] at hVal
          | .ifVal _ _ _      => simp [singletonMethodCallLeafValue] at hVal
          | .loop _ _ _       => simp [singletonMethodCallLeafValue] at hVal
          | .assert _         => simp [singletonMethodCallLeafValue] at hVal
          | .updateProp _ _   => simp [singletonMethodCallLeafValue] at hVal
          | .getStateScript   => simp [singletonMethodCallLeafValue] at hVal
          | .checkPreimage _  => simp [singletonMethodCallLeafValue] at hVal
          | .deserializeState _ => simp [singletonMethodCallLeafValue] at hVal
          | .addOutput _ _ _    => simp [singletonMethodCallLeafValue] at hVal
          | .addRawOutput _ _   => simp [singletonMethodCallLeafValue] at hVal
          | .addDataOutput _ _  => simp [singletonMethodCallLeafValue] at hVal
          | .arrayLiteral _     => simp [singletonMethodCallLeafValue] at hVal
          | .rawScript _ _ _    => simp [singletonMethodCallLeafValue] at hVal

/-- Method-shaped raw-body success for the Tier 1 widening. Composes
the per-binding success lemma with the `lowerMethodUserRawOps`
unfolding. -/
theorem runOps_lowerMethodUserRawOps_singletonMethodCallLeaf_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (stk : Stack.Eval.StackState)
    (h : methodSingletonMethodCallLeafBody progMethods m) :
    (runOps (lowerMethodUserRawOps progMethods props m) stk).toOption.isSome := by
  unfold lowerMethodUserRawOps
  unfold methodSingletonMethodCallLeafBody at h
  -- `defaultInlineBudget = 8 = 7 + 1`.
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget]
  exact runOps_lowerBindingsP_singleton_methodCallLeaf_isSome
    progMethods props 7 0 (Stack.Lower.computeLastUses m.body) []
    (m.body.map (fun b => b.name)) (Stack.Lower.collectConstInts m.body)
    (m.params.map (fun p => p.name) |>.reverse) m.body stk h

/-- Runtime-side method-level wrapper for the Tier 1 widening:
`runMethod` succeeds for a method whose body is a singleton methodCall
against a leaf-callee with structurally-constant body. -/
theorem runMethod_lower_public_unique_no_post_singletonMethodCallLeaf_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : RunarVerification.Stack.Eval.StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false)
    (hLeaf : methodSingletonMethodCallLeafBody methods m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  exact runOps_lowerMethodUserRawOps_singletonMethodCallLeaf_isSome
    methods props m initialStack hLeaf

/-! ## Tier 4a widening — caller-level multi-binding: leaf-empty
methodCall head + structurally-constant tail

This widens the wave-5 wrappers to admit a **multi-binding** caller
body whose HEAD is a leaf-empty `method_call` (callee has empty params
AND empty body — so the head emits `[]` ops and leaves the stack
map unchanged) followed by an arbitrary `structuralConstBody` tail.

Operational shape:
* The leaf-empty methodCall head's op contribution is `[]` (proved by
  `lowerValueP_methodCall_leafEmpty_ops`).
* The leaf-empty methodCall head's stackmap contribution is identity:
  `(lowerValueP ...).2.1 = sm` (proved below by
  `lowerValueP_methodCall_leafEmpty_sm_eq`).
* The leaf-empty methodCall head's localBindings contribution is `[]`
  (the empty callee body's `m.body.map (·.name) = []`; proved below by
  `lowerValueP_methodCall_leafEmpty_localBindings_eq`).
* The tail is `structuralConstBody`, so its lowering is independent of
  the program-aware parameters (`lowerBindingsP_eq_lowerBindings_
  structuralConst`) and its execution succeeds from ANY initial stack
  (`runOps_lowerBindings_structuralConstBody_isSome`).

These four facts compose without needing any `agreesTagged` /
freshness / Nodup premises — the leaf-empty methodCall head is fully
stack-uniform and the const tail is stack-uniform too. -/

/-- The leaf-empty methodCall arm of `lowerValueP` leaves the stack
map unchanged: the post-call `.2.1` equals the pre-call `sm`. -/
theorem lowerValueP_methodCall_leafEmpty_sm_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bn obj method : String) (args : List String)
    (h : leafEmptyMethodCallValue progMethods sm
            (.methodCall obj method args)) :
    (Stack.Lower.lowerValueP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts sm bn
        (.methodCall obj method args)).2.1
      = sm := by
  unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨hObj, hArgsEmpty⟩, hCallee⟩ := h
  match hMatch : Stack.Lower.lookupMethod progMethods method with
  | none =>
      rw [hMatch] at hCallee
      exact absurd hCallee (by simp)
  | some m =>
      rw [hMatch] at hCallee
      simp only [Bool.and_eq_true] at hCallee
      obtain ⟨_hParamsEmpty, hBodyEmpty⟩ := hCallee
      have hArgs : args = [] := List.isEmpty_iff.mp hArgsEmpty
      have hBody : m.body = [] := List.isEmpty_iff.mp hBodyEmpty
      subst hArgs
      -- Dispatch through methodCall arm:
      --   objDropOps with obj not in sm: ([], sm)
      --   loadAndBindArgsLive with args = []: ([], smPostObj) = ([], sm)
      --   lowerBindingsP on m.body = []: ([], smArgs) = ([], sm)
      --   smFinal: m.body.reverse = [] → smAfterBody = sm.
      unfold Stack.Lower.lowerValueP
      simp only [hMatch, hObj, hBody,
                 Stack.Lower.loadAndBindArgsLive,
                 Stack.Lower.lowerBindingsP,
                 List.map_nil, List.reverse_nil]

/-- The leaf-empty methodCall arm of `lowerValueP` returns
`innerLocalBindings = m.body.map (·.name) = []` as its `.2.2`
component. -/
theorem lowerValueP_methodCall_leafEmpty_localBindings_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bn obj method : String) (args : List String)
    (h : leafEmptyMethodCallValue progMethods sm
            (.methodCall obj method args)) :
    (Stack.Lower.lowerValueP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts sm bn
        (.methodCall obj method args)).2.2
      = [] := by
  unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨hObj, hArgsEmpty⟩, hCallee⟩ := h
  match hMatch : Stack.Lower.lookupMethod progMethods method with
  | none =>
      rw [hMatch] at hCallee
      exact absurd hCallee (by simp)
  | some m =>
      rw [hMatch] at hCallee
      simp only [Bool.and_eq_true] at hCallee
      obtain ⟨_hParamsEmpty, hBodyEmpty⟩ := hCallee
      have hArgs : args = [] := List.isEmpty_iff.mp hArgsEmpty
      have hBody : m.body = [] := List.isEmpty_iff.mp hBodyEmpty
      subst hArgs
      unfold Stack.Lower.lowerValueP
      simp only [hMatch, hObj, hBody,
                 Stack.Lower.loadAndBindArgsLive,
                 Stack.Lower.lowerBindingsP,
                 List.map_nil]

/-- Tier 4a body-shape predicate: the head is a leaf-empty methodCall,
the rest is a structuralConstBody. -/
def leafEmptyMethodCallThenConstBody
    (progMethods : List ANFMethod) (sm : StackMap)
    (body : List ANFBinding) : Prop :=
  match body with
  | [] => False
  | b :: rest =>
      leafEmptyMethodCallValue progMethods sm b.value ∧
      structuralConstBody rest

/-- Method-shaped Tier 4a predicate. -/
def methodLeafEmptyMethodCallThenConstBody
    (progMethods : List ANFMethod) (m : ANFMethod) : Prop :=
  leafEmptyMethodCallThenConstBody progMethods
    (m.params.map (fun p => p.name) |>.reverse) m.body

/-- Tier 4a runtime success: a body shaped as a leaf-empty methodCall
head followed by a `structuralConstBody` tail runs successfully through
the program-aware lowerer from ANY initial stack. -/
theorem runOps_lowerBindingsP_leafEmptyMethodCall_then_const_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (body : List ANFBinding)
    (stk : Stack.Eval.StackState)
    (h : leafEmptyMethodCallThenConstBody progMethods sm body) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
              currentIndex lastUses outerProtected localBindings
              constInts sm body).1 stk).toOption.isSome := by
  unfold leafEmptyMethodCallThenConstBody at h
  match hBody : body with
  | [] => exact absurd h (by simp)
  | b :: rest =>
      simp only at h
      obtain ⟨hHead, hRest⟩ := h
      -- Destruct the head binding into its `mk` shape so we can match
      -- on its value-position constructor directly.
      match hBmk : b with
      | .mk bn bv src =>
          have hVal : leafEmptyMethodCallValue progMethods sm bv := by
            simp only [ANFBinding.value] at hHead
            exact hHead
          -- The predicate definitionally forces `bv = .methodCall _ _ _`.
          match hVc : bv with
          | .methodCall obj method args =>
              have hLeaf :
                  leafEmptyMethodCallValue progMethods sm
                    (.methodCall obj method args) := hVal
              -- Head's op list is `[]`; head's SM is unchanged.
              have hHeadOps :=
                lowerValueP_methodCall_leafEmpty_ops
                  progMethods props budget' currentIndex lastUses
                  outerProtected localBindings constInts sm bn obj method args
                  hLeaf
              have hHeadSm :=
                lowerValueP_methodCall_leafEmpty_sm_eq
                  progMethods props budget' currentIndex lastUses
                  outerProtected localBindings constInts sm bn obj method args
                  hLeaf
              have hHeadLB :=
                lowerValueP_methodCall_leafEmpty_localBindings_eq
                  progMethods props budget' currentIndex lastUses
                  outerProtected localBindings constInts sm bn obj method args
                  hLeaf
              -- Tail's `lowerBindingsP` equals `lowerBindings` via the
              -- const-only equality. Threaded parameters change (the
              -- new `localBindings'` is `[]`, the index is bumped to
              -- `currentIndex + 1`), but the const-only equality is
              -- parametric in all of those.
              have hTailEq :=
                lowerBindingsP_eq_lowerBindings_structuralConst
                  progMethods props (budget' + 1) lastUses outerProtected
                  [] constInts rest sm (currentIndex + 1) hRest
              -- Unfold the caller's cons.
              show (runOps (Stack.Lower.lowerBindingsP progMethods props
                              (budget' + 1) currentIndex lastUses outerProtected
                              localBindings constInts sm
                              (ANFBinding.mk bn
                                (ANFValue.methodCall obj method args) src
                                :: rest)).1 stk).toOption.isSome
              -- `lowerBindingsP` on a cons: head's ops ++ tail's ops on
              -- `(sm', localBindings')`.
              have hUnfold :
                  (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                      currentIndex lastUses outerProtected localBindings
                      constInts sm
                      (ANFBinding.mk bn
                        (ANFValue.methodCall obj method args) src
                        :: rest)).1
                    = (Stack.Lower.lowerValueP progMethods props (budget' + 1)
                          currentIndex lastUses outerProtected localBindings
                          constInts sm bn
                          (ANFValue.methodCall obj method args)).1
                      ++ (Stack.Lower.lowerBindingsP progMethods props
                              (budget' + 1) (currentIndex + 1) lastUses
                              outerProtected
                              (Stack.Lower.lowerValueP progMethods props
                                  (budget' + 1) currentIndex lastUses
                                  outerProtected localBindings constInts sm bn
                                  (ANFValue.methodCall obj method args)).2.2
                              constInts
                              (Stack.Lower.lowerValueP progMethods props
                                  (budget' + 1) currentIndex lastUses
                                  outerProtected localBindings constInts sm bn
                                  (ANFValue.methodCall obj method args)).2.1
                              rest).1 := by
                simp [Stack.Lower.lowerBindingsP]
              rw [hUnfold, hHeadOps, hHeadSm, hHeadLB,
                  Stack.Sim.runOps_append]
              -- After rewriting, head's ops are `[]`, so runOps on `[]`
              -- yields `.ok stk`. The tail is then a structuralConstBody
              -- lowering on `sm` from `stk` at index `currentIndex + 1`
              -- with the empty localBindings. Use `hTailEq` to swap
              -- `lowerBindingsP` for `lowerBindings`, then the const
              -- isSome lemma.
              simp only [runOps, hTailEq]
              -- Reduce `Except.bind (.ok stk) (·)` to obtain runOps on
              -- the tail's ops list applied to `stk`.
              show (runOps
                      (Stack.Lower.lowerBindings sm rest).1
                      stk).toOption.isSome
              exact runOps_lowerBindings_structuralConstBody_isSome
                rest sm stk hRest
          | .loadParam _ => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .loadProp _  => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .loadConst c =>
              cases c <;>
                simp [leafEmptyMethodCallValueB,
                      leafEmptyMethodCallValue] at hVal
          | .binOp _ _ _ _    => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .unaryOp _ _ _    => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .call _ _         => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .ifVal _ _ _      => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .loop _ _ _       => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .assert _         => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .updateProp _ _   => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .getStateScript   => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .checkPreimage _  => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .deserializeState _ => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .addOutput _ _ _    => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .addRawOutput _ _   => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .addDataOutput _ _  => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .arrayLiteral _     => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .rawScript _ _ _    => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal

/-- Method-shaped raw-body success for the Tier 4a widening. -/
theorem runOps_lowerMethodUserRawOps_leafEmptyMethodCall_then_const_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (stk : Stack.Eval.StackState)
    (h : methodLeafEmptyMethodCallThenConstBody progMethods m) :
    (runOps (lowerMethodUserRawOps progMethods props m) stk).toOption.isSome := by
  unfold lowerMethodUserRawOps
  unfold methodLeafEmptyMethodCallThenConstBody at h
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget]
  exact runOps_lowerBindingsP_leafEmptyMethodCall_then_const_isSome
    progMethods props 7 0 (Stack.Lower.computeLastUses m.body) []
    (m.body.map (fun b => b.name)) (Stack.Lower.collectConstInts m.body)
    (m.params.map (fun p => p.name) |>.reverse) m.body stk h

/-- Runtime-side method-level wrapper for the Tier 4a widening:
`runMethod` succeeds for a method whose body is a leaf-empty methodCall
head followed by a `structuralConstBody` tail. -/
theorem runMethod_lower_public_unique_no_post_leafEmptyMethodCall_then_const_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : RunarVerification.Stack.Eval.StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false)
    (hLeaf : methodLeafEmptyMethodCallThenConstBody methods m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  exact runOps_lowerMethodUserRawOps_leafEmptyMethodCall_then_const_isSome
    methods props m initialStack hLeaf

end Agrees
end RunarVerification.Stack

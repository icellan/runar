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
open RunarVerification.ANF.Eval (State)
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
          | .ifVal _ _ _ _      => simp [leafEmptyMethodCallValueB] at hVal
          | .loop _ _ _ _ _ => simp [leafEmptyMethodCallValueB] at hVal
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

/-- NEW-004: a singleton `.methodCall` body marks no raw slot. Stated on
the concrete shape the singleton wrappers below carry. -/
theorem collectRawSlots_singleton_methodCall
    (bn obj method : String) (args : List String) (src : Option SourceLoc) :
    Stack.Lower.collectRawSlots
      [ANFBinding.mk bn (.methodCall obj method args) src] = [] := by
  simp [Stack.Lower.collectRawSlots, Stack.Lower.collectRawSlotsGo,
        Stack.Lower.rawResultValue]

/-- `arrayElems` peer: a singleton `.methodCall` body binds no
`array_literal` (`arrayElemsOf` does not descend through `methodCall` —
the callee's own entries are merged at the inline site instead). -/
theorem arrayElemsOf_singleton_methodCall
    (bn obj method : String) (args : List String) (src : Option SourceLoc) :
    Stack.Lower.arrayElemsOf
      [ANFBinding.mk bn (.methodCall obj method args) src] = [] := by
  simp [Stack.Lower.arrayElemsOf]

/-- NEW-004: `.methodCall` is not a byte-array producer, so a body whose
single binding is one marks nothing raw. -/
theorem collectRawSlots_nil_of_leafEmptyMethodCallValue
    (progMethods : List ANFMethod) (sm : StackMap) (b : ANFBinding)
    (h : leafEmptyMethodCallValue progMethods sm b.value) :
    Stack.Lower.collectRawSlotsGo [] [b] = [] := by
  obtain ⟨name, v, src⟩ := b
  unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at h
  simp only [ANFBinding.value] at h
  cases v <;>
    simp_all [Stack.Lower.collectRawSlotsGo, Stack.Lower.rawResultValue]

/-- Tier 1' body-level: the leaf-empty methodCall fragment has an empty
raw-slot set, so the method-level wrappers below need no extra
hypothesis. -/
theorem collectRawSlots_nil_of_methodLeafEmptyMethodCallBody
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodLeafEmptyMethodCallBody progMethods m) :
    Stack.Lower.collectRawSlots m.body = [] := by
  unfold methodLeafEmptyMethodCallBody singletonLeafEmptyMethodCallBody
    singletonLeafEmptyMethodCallBodyB at h
  match hb : m.body, h with
  | [b], hbv =>
      unfold Stack.Lower.collectRawSlots
      exact collectRawSlots_nil_of_leafEmptyMethodCallValue progMethods _ b hbv

/-- `arrayElems` peer of `collectRawSlots_nil_of_leafEmptyMethodCallValue`. -/
theorem arrayElemsOf_nil_of_leafEmptyMethodCallValue
    (progMethods : List ANFMethod) (sm : StackMap) (b : ANFBinding)
    (h : leafEmptyMethodCallValue progMethods sm b.value) :
    Stack.Lower.arrayElemsOf [b] = [] := by
  obtain ⟨name, v, src⟩ := b
  unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at h
  simp only [ANFBinding.value] at h
  cases v <;> simp_all [Stack.Lower.arrayElemsOf]

/-- `arrayElems` peer of `collectRawSlots_nil_of_methodLeafEmptyMethodCallBody`. -/
theorem arrayElemsOf_nil_of_methodLeafEmptyMethodCallBody
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodLeafEmptyMethodCallBody progMethods m) :
    Stack.Lower.arrayElemsOf m.body = [] := by
  unfold methodLeafEmptyMethodCallBody singletonLeafEmptyMethodCallBody
    singletonLeafEmptyMethodCallBodyB at h
  match hb : m.body, h with
  | [b], hbv =>
      exact arrayElemsOf_nil_of_leafEmptyMethodCallValue progMethods _ b hbv

theorem lowerMethodUserRawOps_methodCall_leafEmpty
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (h : methodLeafEmptyMethodCallBody progMethods m) :
    lowerMethodUserRawOps progMethods props m = [] := by
  unfold lowerMethodUserRawOps
  unfold methodLeafEmptyMethodCallBody at h
  -- `defaultInlineBudget = 8 = 7 + 1` definitionally.
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget, collectRawSlots_nil_of_methodLeafEmptyMethodCallBody progMethods m h,
      arrayElemsOf_nil_of_methodLeafEmptyMethodCallBody progMethods m h]
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
  have hRaw := Agrees.collectRawSlots_nil_of_structuralConstBody m.body hConst
  have hArrElems := Agrees.arrayElemsOf_nil_of_structuralConstBody m.body hConst
  unfold Stack.Lower.lowerValueP
  simp only [hLookup, hObj,
             Stack.Lower.loadAndBindArgsLive,
             List.append_nil, List.nil_append,
             hRaw, hArrElems, hBindings]

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
          | .ifVal _ _ _ _      => simp [singletonMethodCallLeafValue] at hVal
          | .loop _ _ _ _ _ => simp [singletonMethodCallLeafValue] at hVal
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


/-- NEW-004 peer for the Tier 1 `singletonMethodCallLeafValue` shape. -/
theorem collectRawSlots_nil_of_methodSingletonMethodCallLeafBody
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodSingletonMethodCallLeafBody progMethods m) :
    Stack.Lower.collectRawSlots m.body = [] := by
  unfold methodSingletonMethodCallLeafBody singletonMethodCallLeafBody at h
  match hb : m.body, h with
  | [b], hbv =>
      obtain ⟨name, v, src⟩ := b
      unfold singletonMethodCallLeafValue at hbv
      simp only [ANFBinding.value] at hbv
      unfold Stack.Lower.collectRawSlots
      cases v <;>
        simp_all [Stack.Lower.collectRawSlotsGo, Stack.Lower.rawResultValue]

/-- `arrayElems` peer of
`collectRawSlots_nil_of_methodSingletonMethodCallLeafBody`. -/
theorem arrayElemsOf_nil_of_methodSingletonMethodCallLeafBody
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodSingletonMethodCallLeafBody progMethods m) :
    Stack.Lower.arrayElemsOf m.body = [] := by
  unfold methodSingletonMethodCallLeafBody singletonMethodCallLeafBody at h
  match hb : m.body, h with
  | [b], hbv =>
      obtain ⟨name, v, src⟩ := b
      unfold singletonMethodCallLeafValue at hbv
      simp only [ANFBinding.value] at hbv
      cases v <;> simp_all [Stack.Lower.arrayElemsOf]

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
  rw [hBudget, collectRawSlots_nil_of_methodSingletonMethodCallLeafBody progMethods m h,
      arrayElemsOf_nil_of_methodSingletonMethodCallLeafBody progMethods m h]
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
          | .ifVal _ _ _ _      => simp [leafEmptyMethodCallValueB,
              leafEmptyMethodCallValue] at hVal
          | .loop _ _ _ _ _ => simp [leafEmptyMethodCallValueB,
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


/-- NEW-004 peer for the Tier 4a shape: a methodCall head plus a
structurally-constant tail marks nothing raw either. -/
theorem collectRawSlots_nil_of_methodLeafEmptyMethodCallThenConstBody
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodLeafEmptyMethodCallThenConstBody progMethods m) :
    Stack.Lower.collectRawSlots m.body = [] := by
  unfold methodLeafEmptyMethodCallThenConstBody leafEmptyMethodCallThenConstBody at h
  match hb : m.body, h with
  | b :: rest, ⟨hHead, hTail⟩ =>
      have hRest : Stack.Lower.collectRawSlotsGo [] rest = [] := by
        have := Agrees.collectRawSlots_nil_of_structuralConstBody rest hTail
        simpa [Stack.Lower.collectRawSlots] using this
      obtain ⟨name, v, src⟩ := b
      unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at hHead
      simp only [ANFBinding.value] at hHead
      unfold Stack.Lower.collectRawSlots
      cases v <;>
        simp_all [Stack.Lower.collectRawSlotsGo, Stack.Lower.rawResultValue]

/-- `arrayElems` peer of
`collectRawSlots_nil_of_methodLeafEmptyMethodCallThenConstBody`. -/
theorem arrayElemsOf_nil_of_methodLeafEmptyMethodCallThenConstBody
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodLeafEmptyMethodCallThenConstBody progMethods m) :
    Stack.Lower.arrayElemsOf m.body = [] := by
  unfold methodLeafEmptyMethodCallThenConstBody leafEmptyMethodCallThenConstBody at h
  match hb : m.body, h with
  | b :: rest, ⟨hHead, hTail⟩ =>
      have hRest : Stack.Lower.arrayElemsOf rest = [] :=
        Agrees.arrayElemsOf_nil_of_structuralConstBody rest hTail
      obtain ⟨name, v, src⟩ := b
      unfold leafEmptyMethodCallValue leafEmptyMethodCallValueB at hHead
      simp only [ANFBinding.value] at hHead
      cases v <;> simp_all [Stack.Lower.arrayElemsOf]

/-- Method-shaped raw-body success for the Tier 4a widening. -/
theorem runOps_lowerMethodUserRawOps_leafEmptyMethodCall_then_const_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (stk : Stack.Eval.StackState)
    (h : methodLeafEmptyMethodCallThenConstBody progMethods m) :
    (runOps (lowerMethodUserRawOps progMethods props m) stk).toOption.isSome := by
  unfold lowerMethodUserRawOps
  unfold methodLeafEmptyMethodCallThenConstBody at h
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget,
      collectRawSlots_nil_of_methodLeafEmptyMethodCallThenConstBody progMethods m h,
      arrayElemsOf_nil_of_methodLeafEmptyMethodCallThenConstBody progMethods m h]
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

/-! ## Wave 10 — Tier 3a/3b/3c: singleton methodCall with non-const callee body

This block widens the wave-5 Tier 1 singleton-methodCall wrapper to admit
callee bodies that are NOT structurally constant. The outer caller body
is still exactly one `.methodCall obj method args` binding with `obj`
absent from `sm`, `args = []`, and `m.params = []`. The callee body is
no longer required to be `structuralConstBody`; instead the wrapper
takes an explicit structural-family premise on the callee body and
composes it against the wave-9-exposed substrate

* `runOps_lowerBindingsP_structuralRefBody_isSome`   (already public)
* `runOps_lowerBindingsP_structuralArithBody_isSome` (wave 9, exposed)
* `runOps_lowerBindingsP_structuralCallBody_isSome`  (wave 9, exposed)

The wave-5 Tier 1 proof reduced the methodCall's op contribution to
`(lowerBindings sm m.body).1` via
`lowerBindingsP_eq_lowerBindings_structuralConst`. Wave 9 clarified
that this equality DOES NOT hold for ref / arith / call callee
bodies (consume-mode bindings make `lowerBindingsP ≠ lowerBindings`
by design). Wave 10 therefore composes against the `_isSome`
witnesses directly, leaving the callee body lowered through
`lowerBindingsP` end-to-end.

### Generic op-list reduction

The methodCall arm of `lowerValueP`, restricted to the singleton
shape (`obj` absent, `args = []`, callee `m` with `m.params = []`),
produces an op list that is exactly the callee body's
`lowerBindingsP` output. The lemma is callee-body-family-agnostic —
it makes no assumption about the callee body shape. -/
theorem lowerValueP_methodCall_singleton_calleeBodyP_ops
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
    (_hParams : m.params = []) :
    (Stack.Lower.lowerValueP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts sm bn
        (.methodCall obj method args)).1
      = (Stack.Lower.lowerBindingsP progMethods props budget' 0
            (Stack.Lower.computeLastUses m.body)
            outerProtected (m.body.map (fun b => b.name))
            (constInts ++ Stack.Lower.collectConstInts m.body)
            sm m.body
            -- NEW-004: the inlined callee body is lowered against the
            -- caller's raw-slot set merged with its own. The caller's is
            -- the `[]` default here, so what remains is the callee's.
            (Stack.Lower.collectRawSlots m.body)
            false
            -- Same merge shape for the `array_literal` element table.
            (Stack.Lower.arrayElemsOf m.body)).1 := by
  subst hArgs
  -- Dispatch through methodCall arm:
  --   budget = budget' + 1 avoids the budget-exhausted fallback.
  --   `lookupMethod` yields `m`.
  --   `obj` not in `sm`  →  `objDropOps = ([], sm)`.
  --   `args = []`        →  `loadAndBindArgsLive` returns `([], sm)`.
  --   The callee body's `lowerBindingsP` projection is the bodyOps.
  unfold Stack.Lower.lowerValueP
  simp only [hLookup, hObj,
             Stack.Lower.loadAndBindArgsLive,
             List.append_nil, List.nil_append]

/-! ### Tier 3a — singleton methodCall with `structuralRefBody` callee

`runMethod` succeeds for an outer method whose body is a singleton
`.methodCall obj method args` binding whose callee `callee` has empty
params and whose body inhabits `structuralRefBody` against the
methodCall-arm's threaded parameters. The substrate witness is
`runOps_lowerBindingsP_structuralRefBody_isSome` (already public in
`Stack/Agrees.lean`).

The callee-body substrate is threaded with:
* `budget = 7`               (outer is `defaultInlineBudget = 8 = 7+1`),
* `currentIndex = 0`         (callee body's fresh local index),
* `lastUses = computeLastUses callee.body`,
* `outerProtected = []`      (outer method's outerProtected),
* `localBindings = callee.body.map (·.name)` (inner reset),
* `constInts = collectConstInts callee.body` (outer's `[]` ++ inner's),
* `sm = m.params.reverse`    (outer method's initial stack map; with
  `obj` absent + `args = []` + `callee.params = []` this is unchanged
  through `objDropOps` and `loadAndBindArgsLive`).

The freshness / Nodup / `agreesTagged` premises are input-side
invariants (PATH2_PLAN §2.1) that the caller must supply. -/
theorem runMethod_lower_public_unique_no_post_singletonMethodCall_refCallee_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (tsm : TaggedStackMap) (anfSt : State)
    (initialStack : Stack.Eval.StackState)
    (bn obj method : String) (args : List String) (src : Option SourceLoc)
    (callee : ANFMethod)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
    (hLookup : Stack.Lower.lookupMethod methods method = some callee)
    (hObj :
      StackMap.depth? (List.reverse (m.params.map (fun p => some p.name))) obj
        = none)
    (hArgs : args = [])
    (hCalleeParams : callee.params = [])
    (hCalleeBody :
      structuralRefBody methods props 7
        (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0)
    (hUntagSm : untagSm tsm = List.reverse (m.params.map (fun p => some p.name)))
    (hAgrees : agreesTagged tsm anfSt initialStack)
    (hCalleeBodyFresh :
      ∀ b ∈ callee.body,
        some b.name ∉ List.reverse (m.params.map (fun p => some p.name)))
    (hCalleeBodyNodup : (callee.body.map (fun b => b.name)).Nodup) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- Unfold `lowerMethodUserRawOps`, rewrite the outer body to the
  -- singleton-methodCall shape, then reduce `lowerBindingsP` of that
  -- singleton to the methodCall arm's `lowerValueP.1`, which the
  -- generic op-list lemma rewrites to the callee body's
  -- `lowerBindingsP.1`.
  unfold lowerMethodUserRawOps
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget, hBodyShape]
  -- Reduce singleton `lowerBindingsP` to head's `lowerValueP.1`.
  have hUnfold :
      (Stack.Lower.lowerBindingsP methods props (7 + 1) 0
          (Stack.Lower.computeLastUses
            [ANFBinding.mk bn (ANFValue.methodCall obj method args) src]) []
          ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
            (fun b => b.name))
          (Stack.Lower.collectConstInts
            [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
          (List.reverse (m.params.map (fun p => some p.name)))
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src]).1
        = (Stack.Lower.lowerValueP methods props (7 + 1) 0
              (Stack.Lower.computeLastUses
                [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
              []
              ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
                (fun b => b.name))
              (Stack.Lower.collectConstInts
                [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
              (List.reverse (m.params.map (fun p => some p.name))) bn
              (ANFValue.methodCall obj method args)).1 := by
    with_unfolding_all
      simp [Stack.Lower.lowerBindingsP]
  -- NEW-004: the OUTER body is a singleton methodCall, which marks nothing
  -- raw, so the method-wide set it is lowered against is empty.
  rw [collectRawSlots_singleton_methodCall bn obj method args src]
  rw [arrayElemsOf_singleton_methodCall bn obj method args src]
  rw [hUnfold]
  -- Rewrite the methodCall's op list to the callee body's `lowerBindingsP.1`.
  rw [lowerValueP_methodCall_singleton_calleeBodyP_ops
        methods props 7 0
        (Stack.Lower.computeLastUses
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
        []
        ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
          (fun b => b.name))
        (Stack.Lower.collectConstInts
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
        (List.reverse (m.params.map (fun p => some p.name))) bn obj method args
        callee hLookup hObj hArgs hCalleeParams]
  -- The outer body's `collectConstInts` is `[]` (singleton methodCall has
  -- no `loadConst (.int _)`). Rewrite `[] ++ collectConstInts callee.body`
  -- to `collectConstInts callee.body` to match the substrate's `constInts`.
  simp only [Stack.Lower.collectConstInts, List.nil_append]
  -- Apply the wave-9-exposed structuralRefBody substrate.
  -- NEW-004: the ref fragment marks nothing raw, so the callee body is
  -- lowered against the empty set.
  rw [Agrees.collectRawSlots_nil_of_structuralRefBody
        methods props 7 (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0 hCalleeBody]
  rw [Agrees.arrayElemsOf_nil_of_structuralRefBody
        methods props 7 (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0 hCalleeBody]
  exact runOps_lowerBindingsP_structuralRefBody_isSome
    methods props 7
    (Stack.Lower.computeLastUses callee.body) []
    (callee.body.map (fun b => b.name))
    (Stack.Lower.collectConstInts callee.body)
    callee.body
    (List.reverse (m.params.map (fun p => some p.name))) 0
    tsm anfSt initialStack hUntagSm hAgrees hCalleeBody
    hCalleeBodyFresh hCalleeBodyNodup

/-! ### Tier 3b — singleton methodCall with `structuralArithBody` callee

Mirrors Tier 3a, swapping the callee-body substrate for the wave-9-
exposed `runOps_lowerBindingsP_structuralArithBody_isSome`. The arith
substrate additionally requires a per-binding runtime-success witness
`hCalleeBodyRunOk` — see the substrate's docstring for the reason
(arith opcodes have value-dependent failure modes; the substrate
delegates per-opcode operational discharge to its caller). The
`hCalleeBodyRunOk` premise is NOT conclusion-restating against THIS
wrapper's conclusion: it witnesses success on individual callee-body
bindings, whereas the wrapper's conclusion is about the OUTER
method's `runMethod` (a strictly larger op set). -/
theorem runMethod_lower_public_unique_no_post_singletonMethodCall_arithCallee_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : Stack.Eval.StackState)
    (bn obj method : String) (args : List String) (src : Option SourceLoc)
    (callee : ANFMethod)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
    (hLookup : Stack.Lower.lookupMethod methods method = some callee)
    (hObj :
      StackMap.depth? (List.reverse (m.params.map (fun p => some p.name))) obj
        = none)
    (hArgs : args = [])
    (hCalleeParams : callee.params = [])
    (hCalleeBody :
      structuralArithBody methods props 7
        (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0)
    -- NEW-004: unlike the ref fragment, the arith / builtin-call fragments
    -- ADMIT the byte-array producers (`<< >> & | ^ ~`), so an empty
    -- raw-slot set does not follow from the fragment and is assumed. It is
    -- decidable, so a concrete callee discharges it by `decide`. What it
    -- excludes is exactly a callee whose byte-array result is read in
    -- numeric context — there the inlined body carries `OP_BIN2NUM`s the
    -- substrate lemma (stated at the default) does not describe.
    (hCalleeRaw : Stack.Lower.collectRawSlots callee.body = [])
    (hCalleeBodyFresh :
      ∀ b ∈ callee.body,
        some b.name ∉ List.reverse (m.params.map (fun p => some p.name)))
    (hCalleeBodyNodup : (callee.body.map (fun b => b.name)).Nodup)
    (hCalleeBodyRunOk :
      ∀ b ∈ callee.body, ∀ idx : Nat, ∀ sm_acc : StackMap,
        ∀ stkPre : Stack.Eval.StackState,
        (Stack.Eval.runOps
          (Stack.Lower.lowerValueP methods props 7 idx
              (Stack.Lower.computeLastUses callee.body) []
              (callee.body.map (fun b => b.name))
              (Stack.Lower.collectConstInts callee.body)
              sm_acc b.name b.value).1
          stkPre).toOption.isSome = true) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  unfold lowerMethodUserRawOps
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget, hBodyShape]
  -- Reduce singleton `lowerBindingsP` to head's `lowerValueP.1`.
  have hUnfold :
      (Stack.Lower.lowerBindingsP methods props (7 + 1) 0
          (Stack.Lower.computeLastUses
            [ANFBinding.mk bn (ANFValue.methodCall obj method args) src]) []
          ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
            (fun b => b.name))
          (Stack.Lower.collectConstInts
            [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
          (List.reverse (m.params.map (fun p => some p.name)))
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src]).1
        = (Stack.Lower.lowerValueP methods props (7 + 1) 0
              (Stack.Lower.computeLastUses
                [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
              []
              ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
                (fun b => b.name))
              (Stack.Lower.collectConstInts
                [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
              (List.reverse (m.params.map (fun p => some p.name))) bn
              (ANFValue.methodCall obj method args)).1 := by
    with_unfolding_all
      simp [Stack.Lower.lowerBindingsP]
  -- NEW-004: the OUTER body is a singleton methodCall, which marks nothing
  -- raw, so the method-wide set it is lowered against is empty.
  rw [collectRawSlots_singleton_methodCall bn obj method args src]
  rw [arrayElemsOf_singleton_methodCall bn obj method args src]
  rw [hUnfold]
  rw [lowerValueP_methodCall_singleton_calleeBodyP_ops
        methods props 7 0
        (Stack.Lower.computeLastUses
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
        []
        ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
          (fun b => b.name))
        (Stack.Lower.collectConstInts
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
        (List.reverse (m.params.map (fun p => some p.name))) bn obj method args
        callee hLookup hObj hArgs hCalleeParams]
  simp only [Stack.Lower.collectConstInts, List.nil_append]
  -- Apply the wave-9-exposed structuralArithBody substrate.
  rw [hCalleeRaw]
  rw [Agrees.arrayElemsOf_nil_of_structuralArithBody
        methods props 7 (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0 hCalleeBody]
  exact runOps_lowerBindingsP_structuralArithBody_isSome
    methods props 7
    (Stack.Lower.computeLastUses callee.body) []
    (callee.body.map (fun b => b.name))
    (Stack.Lower.collectConstInts callee.body)
    callee.body
    (List.reverse (m.params.map (fun p => some p.name))) 0 initialStack
    hCalleeBody hCalleeBodyFresh hCalleeBodyNodup hCalleeBodyRunOk

/-! ### Tier 3c — singleton methodCall with `structuralCallBody` callee

Mirrors Tier 3a, swapping the callee-body substrate for the wave-9-
exposed `runOps_lowerBindingsP_structuralCallBody_isSome`. The call
substrate, like arith, requires a per-binding runtime-success
witness (`OP_SHA256` / `OP_CAT` / etc. each have type-dependent
failure modes; per-builtin operational discharge is delegated to the
caller). -/
theorem runMethod_lower_public_unique_no_post_singletonMethodCall_callCallee_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialStack : Stack.Eval.StackState)
    (bn obj method : String) (args : List String) (src : Option SourceLoc)
    (callee : ANFMethod)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false)
    (hBodyShape :
      m.body = [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
    (hLookup : Stack.Lower.lookupMethod methods method = some callee)
    (hObj :
      StackMap.depth? (List.reverse (m.params.map (fun p => some p.name))) obj
        = none)
    (hArgs : args = [])
    (hCalleeParams : callee.params = [])
    (hCalleeBody :
      structuralCallBody methods props 7
        (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0)
    -- NEW-004: unlike the ref fragment, the arith / builtin-call fragments
    -- ADMIT the byte-array producers (`<< >> & | ^ ~`), so an empty
    -- raw-slot set does not follow from the fragment and is assumed. It is
    -- decidable, so a concrete callee discharges it by `decide`. What it
    -- excludes is exactly a callee whose byte-array result is read in
    -- numeric context — there the inlined body carries `OP_BIN2NUM`s the
    -- substrate lemma (stated at the default) does not describe.
    (hCalleeRaw : Stack.Lower.collectRawSlots callee.body = [])
    (hCalleeBodyFresh :
      ∀ b ∈ callee.body,
        some b.name ∉ List.reverse (m.params.map (fun p => some p.name)))
    (hCalleeBodyNodup : (callee.body.map (fun b => b.name)).Nodup)
    (hCalleeBodyRunOk :
      ∀ b ∈ callee.body, ∀ idx : Nat, ∀ sm_acc : StackMap,
        ∀ stkPre : Stack.Eval.StackState,
        (Stack.Eval.runOps
          (Stack.Lower.lowerValueP methods props 7 idx
              (Stack.Lower.computeLastUses callee.body) []
              (callee.body.map (fun b => b.name))
              (Stack.Lower.collectConstInts callee.body)
              sm_acc b.name b.value).1
          stkPre).toOption.isSome = true) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  unfold lowerMethodUserRawOps
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget, hBodyShape]
  have hUnfold :
      (Stack.Lower.lowerBindingsP methods props (7 + 1) 0
          (Stack.Lower.computeLastUses
            [ANFBinding.mk bn (ANFValue.methodCall obj method args) src]) []
          ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
            (fun b => b.name))
          (Stack.Lower.collectConstInts
            [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
          (List.reverse (m.params.map (fun p => some p.name)))
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src]).1
        = (Stack.Lower.lowerValueP methods props (7 + 1) 0
              (Stack.Lower.computeLastUses
                [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
              []
              ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
                (fun b => b.name))
              (Stack.Lower.collectConstInts
                [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
              (List.reverse (m.params.map (fun p => some p.name))) bn
              (ANFValue.methodCall obj method args)).1 := by
    with_unfolding_all
      simp [Stack.Lower.lowerBindingsP]
  -- NEW-004: the OUTER body is a singleton methodCall, which marks nothing
  -- raw, so the method-wide set it is lowered against is empty.
  rw [collectRawSlots_singleton_methodCall bn obj method args src]
  rw [arrayElemsOf_singleton_methodCall bn obj method args src]
  rw [hUnfold]
  rw [lowerValueP_methodCall_singleton_calleeBodyP_ops
        methods props 7 0
        (Stack.Lower.computeLastUses
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
        []
        ([ANFBinding.mk bn (ANFValue.methodCall obj method args) src].map
          (fun b => b.name))
        (Stack.Lower.collectConstInts
          [ANFBinding.mk bn (ANFValue.methodCall obj method args) src])
        (List.reverse (m.params.map (fun p => some p.name))) bn obj method args
        callee hLookup hObj hArgs hCalleeParams]
  simp only [Stack.Lower.collectConstInts, List.nil_append]
  -- Apply the wave-9-exposed structuralCallBody substrate.
  rw [hCalleeRaw]
  rw [Agrees.arrayElemsOf_nil_of_structuralCallBody
        methods props 7 (Stack.Lower.computeLastUses callee.body) []
        (callee.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts callee.body)
        callee.body (List.reverse (m.params.map (fun p => some p.name))) 0 hCalleeBody]
  exact runOps_lowerBindingsP_structuralCallBody_isSome
    methods props 7
    (Stack.Lower.computeLastUses callee.body) []
    (callee.body.map (fun b => b.name))
    (Stack.Lower.collectConstInts callee.body)
    callee.body
    (List.reverse (m.params.map (fun p => some p.name))) 0 initialStack
    hCalleeBody hCalleeBodyFresh hCalleeBodyNodup hCalleeBodyRunOk

/-! ## ANF-side `method_call` success — the missing half of A8

Every A8 wrapper above proves only the **Stack** `runOps … .isSome`
direction for a leaf / leaf-callee `method_call`. The matching
`successAgrees` direction (`evalBindings.isSome ↔ runOps.isSome`) was
structurally false: `evalValue`'s `.methodCall` arm returns
`.error .unsupported`, so the ANF side is always `isSome = false` while
the Stack side is `isSome = true` (`False ↔ True`). No A8 lemma could
ever bridge that gap because the core evaluator never inlined.

`ANF.Eval.evalMethodCall` (added additively in `ANF/Eval.lean`, no
signature change to `evalValue`) supplies the missing arm: it resolves
the callee, evaluates its body via the unchanged `evalBindings`, and
returns the last-binding value. The lemmas below establish the ANF
`.isSome` direction for the same Tier-1 leaf shape the Stack side
already covers (`singletonMethodCallLeafValue`), so both halves are
finally `.isSome` on a common fragment.

The remaining work to RETIRE `method_call` is to thread `evalMethodCall`
into a `successAgrees`-shaped statement at the Pipeline level — which
needs `evalValue`'s `.methodCall` arm to actually call `evalMethodCall`
(the cascading core-signature change documented in the hand-off), or a
program-aware `evalBindings` variant. This file lands only the additive
ANF success direction; the Pipeline retirement is the follow-up. -/

/-- After `evalBindings s body = .ok s'` on a NON-empty `body`, the last
binding's name resolves in `s'`. `evalBindings` ends by
`addBinding lastName lastVal`, placing `lastName` at the head of
`s'.bindings`, where `lookupBinding` (most-recent-wins) always finds it.

Proved by induction on `body`, generalizing `s`: the inductive step
threads through the recursive `evalBindings` call, and the base
(singleton) case exposes the final `addBinding`. -/
theorem evalBindings_getLast_lookupBinding_isSome :
    ∀ (body : List ANFBinding) (s s' : State),
      body ≠ [] →
      RunarVerification.ANF.Eval.evalBindings s body = .ok s' →
      ∀ (lastB : ANFBinding), body.getLast? = some lastB →
        (s'.lookupBinding lastB.name).isSome = true := by
  intro body
  induction body with
  | nil => intro _ _ hNe _; exact absurd rfl hNe
  | cons hd rest ih =>
      intro s s' _ hEval lastB hLast
      obtain ⟨name, v, src⟩ := hd
      -- Case on `evalValue s v`: error makes `evalBindings` an error,
      -- contradicting `hEval = .ok`.
      cases hVal : RunarVerification.ANF.Eval.evalValue s v with
      | error e =>
          rw [RunarVerification.ANF.Eval.evalBindings] at hEval
          simp only [hVal, bind, Except.bind] at hEval
          exact absurd hEval (by simp)
      | ok p =>
          obtain ⟨val, s2⟩ := p
          -- Unfold the cons step: `evalBindings s (hd::rest)` reduces to
          -- `evalBindings (s2.addBinding name val) rest`.
          have hStep :
              RunarVerification.ANF.Eval.evalBindings
                (s2.addBinding name val) rest = .ok s' := by
            rw [RunarVerification.ANF.Eval.evalBindings] at hEval
            simpa only [hVal, bind, Except.bind] using hEval
          cases hRest : rest with
          | nil =>
              -- Singleton: last binding is this head; `rest = []` makes
              -- `evalBindings = .ok (s2.addBinding name val)`, and the
              -- head's name sits at the top of bindings.
              subst hRest
              have hLastEq : lastB = ANFBinding.mk name v src := by
                rw [List.getLast?_singleton] at hLast
                exact (Option.some.injEq _ _ |>.mp hLast).symm
              subst hLastEq
              rw [RunarVerification.ANF.Eval.evalBindings] at hStep
              simp only [Except.ok.injEq] at hStep
              subst hStep
              simp only [ANFBinding.name,
                         RunarVerification.ANF.Eval.State.lookupBinding,
                         RunarVerification.ANF.Eval.State.addBinding,
                         List.find?, beq_self_eq_true, Option.map_some,
                         Option.isSome_some]
          | cons h2 t2 =>
              -- Non-singleton: `getLast?` of the cons equals `getLast?`
              -- of `rest`; recurse on `rest` after the head step.
              have hRestNe : rest ≠ [] := by rw [hRest]; simp
              have hLastRest : rest.getLast? = some lastB := by
                rw [hRest] at hLast ⊢
                rw [List.getLast?_cons_cons] at hLast
                exact hLast
              exact ih (s2.addBinding name val) s' hRestNe hStep lastB hLastRest

/-- ANF-side success for the Tier-1 leaf `method_call`: when the callee
`m` resolves, has empty params, a NON-empty structurally-constant body,
`evalMethodCall` succeeds. The proof composes:
* `evalBindings_structuralConstBody_isSome` — the callee body evaluates
  to `.ok` from the (empty-param) callee state;
* `evalBindings_getLast_lookupBinding_isSome` — the last binding's value
  is then found, so the return-value lookup succeeds.

The non-empty-body premise is strictly tighter than the Stack-side
`singletonMethodCallLeafValue` (which also admits an empty callee body);
an empty callee body has no return value, so `evalMethodCall` reports
`unsupported` there. Tier-1 conformance callees are never empty. -/
theorem evalMethodCall_leaf_const_isSome
    (progMethods : List ANFMethod) (s : State)
    (obj method : String) (m : ANFMethod)
    (hLookup : RunarVerification.ANF.Eval.lookupMethod progMethods method = some m)
    (_hParams : m.params = [])
    (hBodyNe : m.body ≠ [])
    (hConst : structuralConstBody m.body) :
    (RunarVerification.ANF.Eval.evalMethodCall progMethods s obj method []).toOption.isSome
      = true := by
  -- Unfold `evalMethodCall`: lookup yields `m`, `bindCallArgs s [] _ = .ok []`,
  -- so the callee state is `{ params := [], props := s.props }`.
  unfold RunarVerification.ANF.Eval.evalMethodCall
  rw [hLookup]
  simp only [RunarVerification.ANF.Eval.bindCallArgs, bind, Except.bind]
  -- The callee body evaluates to `.ok s'` (structural-const success).
  have hBodySome :
      (RunarVerification.ANF.Eval.evalBindings
        { params := [], props := s.props } m.body).toOption.isSome = true :=
    evalBindings_structuralConstBody_isSome m.body
      { params := [], props := s.props } hConst
  obtain ⟨s', hEval⟩ :
      ∃ s', RunarVerification.ANF.Eval.evalBindings
        { params := [], props := s.props } m.body = .ok s' := by
    cases hE : RunarVerification.ANF.Eval.evalBindings
        { params := [], props := s.props } m.body with
    | error e => rw [hE] at hBodySome; simp [Except.toOption] at hBodySome
    | ok s' => exact ⟨s', rfl⟩
  rw [hEval]
  -- The return value is the last binding's value, which is found.
  obtain ⟨lastB, hLast⟩ : ∃ lastB, m.body.getLast? = some lastB := by
    cases hB : m.body with
    | nil => exact absurd hB hBodyNe
    | cons h t => exact ⟨(h :: t).getLast (by simp), by simp [List.getLast?_eq_some_getLast]⟩
  have hFound : (s'.lookupBinding lastB.name).isSome = true :=
    evalBindings_getLast_lookupBinding_isSome m.body
      { params := [], props := s.props } s' hBodyNe hEval lastB hLast
  rw [hLast]
  -- `lookupBinding lastB.name = some v`; the helper returns `.ok (v, s)`.
  obtain ⟨v, hv⟩ := Option.isSome_iff_exists.mp hFound
  simp only [hv, pure, Except.pure, Except.toOption, Option.isSome_some]

/-- The leaf `method_call` bridge: BOTH the ANF `evalMethodCall` half and
the Stack `runOps` half are `.isSome` on the common Tier-1 leaf shape, so
the `successAgrees`-style biconditional between them holds trivially
(`True ↔ True`).

This is the first concrete instance where the two evaluators agree on the
success bit for a `method_call` — the exact obligation that was
structurally impossible while `evalValue`'s `.methodCall` arm returned
`.error`. The hypotheses bundle the Stack-side leaf predicate
(`singletonMethodCallLeafBody`, satisfied by the same `obj`/`args = []`/
empty-param/const-body shape) with the ANF-side resolution facts.

It composes:
* `evalMethodCall_leaf_const_isSome` — ANF `.isSome` (added here);
* `runOps_lowerBindingsP_singleton_methodCallLeaf_isSome` — Stack
  `.isSome` (existing A8 substrate). -/
theorem methodCall_leaf_const_successAgrees
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (body : List ANFBinding)
    (s : State) (stk : Stack.Eval.StackState)
    (obj method : String) (m : ANFMethod)
    (hStackLeaf : singletonMethodCallLeafBody progMethods sm body)
    (hLookup : RunarVerification.ANF.Eval.lookupMethod progMethods method = some m)
    (hParams : m.params = [])
    (hBodyNe : m.body ≠ [])
    (hConst : structuralConstBody m.body) :
    ((RunarVerification.ANF.Eval.evalMethodCall progMethods s obj method []).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                currentIndex lastUses outerProtected localBindings
                constInts sm body).1 stk).toOption.isSome) := by
  have hAnf :
      (RunarVerification.ANF.Eval.evalMethodCall progMethods s obj method []).toOption.isSome
        = true :=
    evalMethodCall_leaf_const_isSome progMethods s obj method m
      hLookup hParams hBodyNe hConst
  have hStack :
      (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                currentIndex lastUses outerProtected localBindings
                constInts sm body).1 stk).toOption.isSome = true :=
    runOps_lowerBindingsP_singleton_methodCallLeaf_isSome
      progMethods props budget' currentIndex lastUses outerProtected
      localBindings constInts sm body stk hStackLeaf
  rw [hAnf, hStack]

/-! ## Wave 53 — the `method_call` M2 walk against `evalBindingsP`

`methodCall_leaf_const_successAgrees` (above) is the wave-52 LEAF-CONST
bridge: it pins the ANF success bit through the standalone
`evalMethodCall` helper. The M2 walk needs the **body-level** iff stated
against the program-aware whole-body evaluator `evalBindingsP` (added in
`ANF/Eval.lean` this wave), so it slots into the next-wave omnibus
re-statement (`evalBindings → evalBindingsP`) exactly like the
arith/if_val/math_byte walks slot into the standard `evalBindings`
omnibus.

The connector is purely operational: on a SINGLETON body whose one
binding is a `.methodCall`, `evalBindingsP` reduces to `evalValueP` on
that value (then the trivial empty-tail `evalBindingsP _ [] = .ok`), and
`evalValueP`'s `.methodCall` arm IS `evalMethodCall`. So the body-level
`isSome` equals the `evalMethodCall` `isSome`, and the wave-52 leaf-const
ANF half transfers verbatim. The Stack half is unchanged
(`runOps_lowerBindingsP_singleton_methodCallLeaf_isSome`). -/

/-- Connector: on a singleton `.methodCall` body, `evalBindingsP`'s
success bit equals `evalMethodCall`'s. `evalBindingsP` on the singleton
unfolds to `evalValueP methods s (.methodCall …)` (whose result it
threads into the empty tail), and `evalValueP`'s `.methodCall` arm is
definitionally `evalMethodCall`. -/
theorem evalBindingsP_singleton_methodCall_isSome_eq
    (methods : List ANFMethod) (s : State)
    (bn obj method : String) (args : List String) (src : Option SourceLoc) :
    (RunarVerification.ANF.Eval.evalBindingsP methods s
        [ANFBinding.mk bn (.methodCall obj method args) src]).toOption.isSome
      = (RunarVerification.ANF.Eval.evalMethodCall methods s obj method args).toOption.isSome := by
  rw [RunarVerification.ANF.Eval.evalBindingsP,
      RunarVerification.ANF.Eval.evalValueP]
  cases hMc : RunarVerification.ANF.Eval.evalMethodCall methods s obj method args with
  | error e => simp [bind, Except.bind, Except.toOption]
  | ok p =>
      obtain ⟨val, s'⟩ := p
      simp only [bind, Except.bind, RunarVerification.ANF.Eval.evalBindingsP,
                 Except.toOption, Option.isSome_some]

/-- **Wave 53 DELIVERABLE — the `method_call` M2 walk.**

For a singleton-`method_call` body whose callee is a leaf method (empty
params, non-empty structurally-constant body) absent from the stack map
with no call-site args, the program-aware whole-body evaluator
`evalBindingsP`'s success bit matches the lowered Bitcoin-Script
program's success bit. This is the body-level `successAgrees`-shaped iff
the next-wave omnibus re-statement consumes.

Both sides are `.isSome = true` (anti-vacuous):
* ANF — the singleton connector
  (`evalBindingsP_singleton_methodCall_isSome_eq`) reduces
  `evalBindingsP` to `evalMethodCall`, then wave-52's
  `evalMethodCall_leaf_const_isSome` fires;
* Stack — `runOps_lowerBindingsP_singleton_methodCallLeaf_isSome`
  (the A8 substrate).

All hypotheses are input-side (no conclusion-restating): `hStackLeaf` is
the Stack-side leaf predicate; `hLookup` / `hParams` / `hBodyNe` /
`hConst` are the ANF-side callee-resolution facts; `hBodyEq` pins the
outer body to the singleton shape so the connector applies. -/
theorem successAgrees_methodCall_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (body : List ANFBinding)
    (s : State) (stk : Stack.Eval.StackState)
    (bn obj method : String) (src : Option SourceLoc) (m : ANFMethod)
    (hBodyEq : body = [ANFBinding.mk bn (.methodCall obj method []) src])
    (hStackLeaf : singletonMethodCallLeafBody progMethods sm body)
    (hLookup : RunarVerification.ANF.Eval.lookupMethod progMethods method = some m)
    (hParams : m.params = [])
    (hBodyNe : m.body ≠ [])
    (hConst : structuralConstBody m.body) :
    ((RunarVerification.ANF.Eval.evalBindingsP progMethods s body).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                currentIndex lastUses outerProtected localBindings
                constInts sm body).1 stk).toOption.isSome) := by
  -- ANF half: reduce `evalBindingsP` on the singleton to `evalMethodCall`,
  -- then fire the wave-52 leaf-const `.isSome`.
  have hAnf :
      (RunarVerification.ANF.Eval.evalBindingsP progMethods s body).toOption.isSome
        = true := by
    rw [hBodyEq, evalBindingsP_singleton_methodCall_isSome_eq]
    exact evalMethodCall_leaf_const_isSome progMethods s obj method m
      hLookup hParams hBodyNe hConst
  -- Stack half: the A8 substrate's leaf success.
  have hStack :
      (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                currentIndex lastUses outerProtected localBindings
                constInts sm body).1 stk).toOption.isSome = true :=
    runOps_lowerBindingsP_singleton_methodCallLeaf_isSome
      progMethods props budget' currentIndex lastUses outerProtected
      localBindings constInts sm body stk hStackLeaf
  rw [hAnf, hStack]

/-! ### Wave 53 MANDATORY smoke — concrete `method_call` body, both sides
`.isSome` via `evalBindingsP` (anti-vacuous). -/

/-- Smoke program method: leaf callee `h` with empty params and a single
const binding (structurally constant, non-empty). -/
private def wave53SmokeCallee : ANFMethod :=
  { name := "h", params := [],
    body := [ANFBinding.mk "r0" (.loadConst (.int 7)) none],
    isPublic := false }

private def wave53SmokeMethods : List ANFMethod := [wave53SmokeCallee]

/-- Smoke outer body: a single `.methodCall` of `h` (no args, `obj`
absent from the empty stack map). -/
private def wave53SmokeBody : List ANFBinding :=
  [ANFBinding.mk "c0" (.methodCall "this" "h" []) none]

/-- The smoke body satisfies the Stack-side leaf predicate against the
empty stack map. -/
theorem wave53_smoke_stackLeaf :
    singletonMethodCallLeafBody wave53SmokeMethods [] wave53SmokeBody := by
  refine ⟨rfl, rfl, ?_⟩
  exact ⟨wave53SmokeCallee, rfl, rfl, by native_decide⟩

/-- Wave-53 smoke: the M2 walk fires on the concrete `method_call` body —
both sides `.isSome` through `evalBindingsP`, so the iff is `True ↔ True`
(anti-vacuous; the standard `evalBindings` would error on this body). -/
theorem wave53_smoke_methodCall_unconditional :
    ((RunarVerification.ANF.Eval.evalBindingsP wave53SmokeMethods
        (default : State) wave53SmokeBody).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP wave53SmokeMethods [] (0 + 1)
                0 [] [] [] [] [] wave53SmokeBody).1
        (default : Stack.Eval.StackState)).toOption.isSome) :=
  successAgrees_methodCall_unconditional
    wave53SmokeMethods [] 0 0 [] [] [] [] []
    wave53SmokeBody (default : State) (default : Stack.Eval.StackState)
    "c0" "this" "h" none wave53SmokeCallee
    rfl wave53_smoke_stackLeaf rfl rfl (by decide) (by native_decide)

/-- Anti-vacuity confirmation: on the smoke body the program-aware
`evalBindingsP` succeeds (`isSome = true`) where the standard
`evalBindings` errors (`isSome = false`). -/
theorem wave53_smoke_evalBindingsP_isSome :
    (RunarVerification.ANF.Eval.evalBindingsP wave53SmokeMethods
        (default : State) wave53SmokeBody).toOption.isSome = true := by
  native_decide

theorem wave53_smoke_evalBindings_isNone :
    (RunarVerification.ANF.Eval.evalBindings
        (default : State) wave53SmokeBody).toOption.isSome = false := by
  native_decide

/-! ## Wave 65 — Tier 2 widening: single-param PASSTHROUGH `method_call`

This is the W55-flagged *param-passing* fragment — the one the existing
leaf-const substrate could NOT provide. The wave-55 finding: the const
callee hits the M4 wall and the arith callee suffered a caller/callee
**frame mismatch**, because the existing substrate kept `args = []` and
`m.params = []`, so the callee never referenced its own params. To
genuinely advance retirement we need a fragment where the callee
references ITS OWN param, bound from an explicit call-site arg.

The simplest non-vacuous such shape is the *identity passthrough helper*:

  `helper(p) { return p }`  called as  `helper(a)`

* outer body is a single binding `r := methodCall obj method [a]`;
* `obj` is absent from the outer stack map (`objDropOps = []`);
* the callee `m` has exactly one param `p` and body `[r' := loadParam p]`;
* the call-site arg `a` is at depth 0 in the outer stack map AND is on
  its last use there (so `loadAndBindArgsLive` emits NO op — `bringToTop`
  at depth 0 consume is `[]` — and renames the top slot `a → p`);
* `p` is not in `outerProtected` (so the callee's `loadParam p`, itself a
  depth-0 last-use, also emits NO op — it renames the renamed slot
  `p → r'`).

So the WHOLE methodCall lowers to the EMPTY op list: the arg value already
sits on the runtime stack (the outer method placed it there), and the
inlined identity body leaves it in place. On the ANF side, `evalMethodCall`
binds `a`'s value to the callee param `p`, evaluates `loadParam p`, and
returns that value — exactly the same value. Caller and callee frames now
**agree**: the value the callee sees under name `p` is the value the
arg `a` denotes in the caller. This is the model-level reconciliation
W55 asked for, on the feasible fragment.

The value-level reduction is hypothesis-driven (no `agreesTagged` /
freshness / Nodup premises): the EMPTY op list runs successfully from ANY
initial stack, so `runOps … |>.isSome` is unconditional.

Higher tiers (arg at depth > 0, multi-param callees, callee bodies that
combine the param with operators) remain deferred — they need the
operational `loadAndBindArgsLive` reductions for the swap/rot/roll shapes
plus a `structuralRefBody` callee-body composition. -/

/-- Value-level reduction for the Tier-2 passthrough: at the methodCall
arm, with `obj` absent from `sm`, the single arg `a` at depth 0 and on
its last use (consume), the callee `m` with one param `p` and body
`[r' := loadParam p]`, and `p ∉ outerProtected`, the methodCall op list
is EMPTY. Both the arg load and the callee body's param load reduce to
`[]` (depth-0 consume `bringToTop`). -/
theorem lowerValueP_methodCall_passthrough_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (rest : StackMap) (bn obj method a p r' : String)
    (psrc : Option SourceLoc) (ptype : RunarVerification.ANF.ANFType)
    (m : ANFMethod)
    (hLookup : Stack.Lower.lookupMethod progMethods method = some m)
    (hObj : Stack.Lower.StackMap.depth? (a :: rest) obj = none)
    (hParams : m.params = [{ name := p, type := ptype }])
    (hBody : m.body = [ANFBinding.mk r' (.loadParam p) psrc])
    (hArgLast : Stack.Lower.isLastUse lastUses a currentIndex = true)
    (hArgUnprot : Stack.Lower.listContains outerProtected a = false)
    (hParamUnprot : Stack.Lower.listContains outerProtected p = false) :
    (Stack.Lower.lowerValueP progMethods props (budget' + 1) currentIndex
        lastUses outerProtected localBindings constInts (a :: rest) bn
        (.methodCall obj method [a])).1
      = [] := by
  -- Step 1: the callee-body lowering reduces to `[]`.
  -- `smArgs = p :: rest` (top renamed a → p), callee `loadParam p` at
  -- depth 0 with consume = true ⇒ `bringToTop (p::rest) p true = ([], …)`.
  have hPDepth : Stack.Lower.StackMap.depth? (p :: rest) p = some 0 := by
    unfold Stack.Lower.StackMap.depth? List.findIdx?
    simp [List.findIdx?.go]
  have hBodyLU : Stack.Lower.isLastUse
      (Stack.Lower.computeLastUses (m.body)) p 0 = true := by
    rw [hBody]
    unfold Stack.Lower.computeLastUses Stack.Lower.isLastUse
    simp [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
      Stack.Lower.lastUsesUpdate, List.foldl, Stack.Lower.lastUsesLookup]
  have hBodyOps :
      (Stack.Lower.lowerBindingsP progMethods props budget' 0
          (Stack.Lower.computeLastUses m.body) outerProtected
          (m.body.map (fun b => b.name))
          (constInts ++ Stack.Lower.collectConstInts m.body)
          (p :: rest) m.body).1 = [] := by
    rw [hBody]
    unfold Stack.Lower.lowerBindingsP Stack.Lower.lowerValueP
      Stack.Lower.loadRefLiveParam
    rw [hBody] at hBodyLU
    simp only [Stack.Lower.bringToTop, hPDepth, hParamUnprot, hBodyLU,
      Bool.not_false, Bool.true_and, if_true,
      Stack.Lower.lowerBindingsP, List.append_nil]
  -- The single arg `a` at depth 0 consume loads with NO op and (with the
  -- rename step) produces the arg stack map `p :: rest`.
  have hADepth : Stack.Lower.StackMap.depth? (a :: rest) a = some 0 := by
    unfold Stack.Lower.StackMap.depth? List.findIdx?
    simp [List.findIdx?.go]
  have hArgLoad :
      Stack.Lower.loadAndBindArgsLive currentIndex lastUses outerProtected [a]
          (a :: rest) [a] [p]
        = ([], some p :: rest) := by
    unfold Stack.Lower.loadAndBindArgsLive
    simp only [Stack.Lower.loadRefOperand_singleton]
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    simp only [hADepth, hArgUnprot, hArgLast, Bool.not_false, Bool.true_and,
      if_true, Stack.Lower.loadAndBindArgsLive, List.append_nil]
  -- Step 2: dispatch the methodCall arm with the above facts.
  unfold Stack.Lower.lowerValueP
  rw [hLookup]
  -- objDropOps: obj absent ⇒ ([], a :: rest). args = [a], params = [p].
  simp only [hObj, hParams, List.map_cons, List.map_nil, hArgLoad]
  -- NEW-004: the callee body is a single `loadParam`, which marks nothing
  -- raw, so the merged set the inlined body sees is empty.
  have hRaw : Stack.Lower.collectRawSlots m.body = [] := by
    rw [hBody]
    simp [Stack.Lower.collectRawSlots, Stack.Lower.collectRawSlotsGo,
          Stack.Lower.rawResultValue]
  have hArrElems : Stack.Lower.arrayElemsOf m.body = [] := by
    rw [hBody]; simp [Stack.Lower.arrayElemsOf]
  simp only [hRaw, hArrElems, List.nil_append, List.append_nil, hBodyOps]

/-- Stack-side success of the Tier-2 passthrough fragment, from ANY
initial stack: the singleton body `[bn := methodCall obj method [a]]`
lowers to the EMPTY op list (by `lowerValueP_methodCall_passthrough_ops`),
and `runOps [] stk = .ok stk` succeeds unconditionally. -/
theorem runOps_lowerBindingsP_passthrough_methodCall_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (rest : StackMap) (bn obj method a p r' : String)
    (src psrc : Option SourceLoc) (ptype : RunarVerification.ANF.ANFType)
    (m : ANFMethod) (stk : Stack.Eval.StackState)
    (hLookup : Stack.Lower.lookupMethod progMethods method = some m)
    (hObj : Stack.Lower.StackMap.depth? (a :: rest) obj = none)
    (hParams : m.params = [{ name := p, type := ptype }])
    (hBody : m.body = [ANFBinding.mk r' (.loadParam p) psrc])
    (hArgLast : Stack.Lower.isLastUse lastUses a currentIndex = true)
    (hArgUnprot : Stack.Lower.listContains outerProtected a = false)
    (hParamUnprot : Stack.Lower.listContains outerProtected p = false) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
              currentIndex lastUses outerProtected localBindings
              constInts (a :: rest)
              [ANFBinding.mk bn (.methodCall obj method [a]) src]).1 stk).toOption.isSome := by
  -- The head's op contribution is the methodCall ops; the tail (empty
  -- rest body) contributes `[]`. So the singleton-body op list equals the
  -- head's, which the value-level lemma proves is `[]`.
  have hHead :=
    lowerValueP_methodCall_passthrough_ops progMethods props budget'
      currentIndex lastUses outerProtected localBindings constInts rest
      bn obj method a p r' psrc ptype m hLookup hObj hParams hBody
      hArgLast hArgUnprot hParamUnprot
  have hUnfold :
      (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
          currentIndex lastUses outerProtected localBindings constInts
          (a :: rest)
          [ANFBinding.mk bn (.methodCall obj method [a]) src]).1
        = (Stack.Lower.lowerValueP progMethods props (budget' + 1)
              currentIndex lastUses outerProtected localBindings constInts
              (a :: rest) bn (.methodCall obj method [a])).1 := by
    with_unfolding_all
      simp [Stack.Lower.lowerBindingsP]
  rw [hUnfold, hHead]
  simp [Stack.Eval.runOps_nil, Except.toOption]

/-- ANF-side success of the Tier-2 passthrough fragment: when the callee
`m` resolves with one param `p` and body `[r' := loadParam p]`, and the
call-site arg `a` resolves in the caller state, `evalMethodCall` binds
`a`'s value to `p`, evaluates the identity body, and returns that value —
so `.isSome = true`. This is the ANF half whose FRAME now MATCHES the
Stack inliner: the value the callee body sees under name `p` is exactly
the value the arg `a` denotes in the caller. -/
theorem evalMethodCall_passthrough_isSome
    (progMethods : List ANFMethod) (s : State)
    (obj method a p r' : String) (psrc : Option SourceLoc)
    (ptype : RunarVerification.ANF.ANFType) (m : ANFMethod)
    (av : RunarVerification.ANF.Eval.Value)
    (hLookup : RunarVerification.ANF.Eval.lookupMethod progMethods method = some m)
    (hParams : m.params = [{ name := p, type := ptype }])
    (hBody : m.body = [ANFBinding.mk r' (.loadParam p) psrc])
    (hArg : s.resolveRef a = some av) :
    (RunarVerification.ANF.Eval.evalMethodCall progMethods s obj method [a]).toOption.isSome
      = true := by
  -- `bindCallArgs s [a] [p] = .ok [(p, av)]` (lookupRef s a = .ok av via hArg).
  have hBind : RunarVerification.ANF.Eval.bindCallArgs s [a] [p] = .ok [(p, av)] := by
    unfold RunarVerification.ANF.Eval.bindCallArgs RunarVerification.ANF.Eval.lookupRef
    rw [hArg]
    simp only [RunarVerification.ANF.Eval.bindCallArgs, bind, Except.bind, pure, Except.pure]
  unfold RunarVerification.ANF.Eval.evalMethodCall
  simp only [hLookup, hParams, hBody, List.map_cons, List.map_nil, hBind, bind, Except.bind]
  -- Callee state `{ params := [(p, av)], props := s.props }`; body
  -- `[r' := loadParam p]` evaluates `loadParam p` ⇒ lookupParam p = some av,
  -- then the last-binding `r'` lookup returns `av`. The residual term is a
  -- concrete chain of `find?` / `getLast` reductions on singleton lists.
  simp [RunarVerification.ANF.Eval.evalBindings, RunarVerification.ANF.Eval.evalValue,
    RunarVerification.ANF.Eval.State.lookupParam, RunarVerification.ANF.Eval.State.lookupBinding,
    RunarVerification.ANF.Eval.State.addBinding, ANFBinding.name, bind, Except.bind, pure,
    Except.pure, Except.toOption]

/-- **Wave 65 DELIVERABLE — the Tier-2 passthrough `method_call` M2 walk.**

The body-level `successAgrees`-shaped iff for the *param-passing* fragment,
stated against the program-aware whole-body evaluator `evalBindingsP`
(the form the omnibus re-statement consumes). For the singleton body
`[bn := methodCall obj method [a]]` whose callee is an identity-passthrough
helper (`helper(p) { return p }`) called with the depth-0 last-use arg `a`:

* ANF — the singleton connector
  (`evalBindingsP_singleton_methodCall_isSome_eq`) reduces `evalBindingsP`
  to `evalMethodCall`, then `evalMethodCall_passthrough_isSome` fires
  (the arg resolves, binds to the callee param, identity body returns it);
* Stack — `runOps_lowerBindingsP_passthrough_methodCall_isSome` (the
  whole methodCall lowers to the EMPTY op list).

Both sides `.isSome = true`, so the iff is `True ↔ True` — anti-vacuous,
and the FIRST `method_call` instance where the callee references its OWN
param bound from an explicit arg. The caller / callee frames agree: the
value the callee sees under `p` is the value the caller's arg `a` denotes.
This is the W55 frame reconciliation, on the feasible fragment.

All hypotheses are input-side (no conclusion-restating): `hLookup` /
`hParams` / `hBody` resolve the callee shape; `hArg` is the caller-frame
arg resolution; `hArgLast` / `hArgUnprot` / `hParamUnprot` are the
liveness/protection facts that make both arg- and param-loads consume
in place; `hObj` keeps the object reference off the outer stack map. -/
theorem successAgrees_methodCall_passthrough_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (rest : StackMap) (bn obj method a p r' : String)
    (src psrc : Option SourceLoc) (ptype : RunarVerification.ANF.ANFType)
    (m : ANFMethod) (s : State) (stk : Stack.Eval.StackState)
    (av : RunarVerification.ANF.Eval.Value)
    (hLookupStack : Stack.Lower.lookupMethod progMethods method = some m)
    (hLookupAnf : RunarVerification.ANF.Eval.lookupMethod progMethods method = some m)
    (hObj : Stack.Lower.StackMap.depth? (a :: rest) obj = none)
    (hParams : m.params = [{ name := p, type := ptype }])
    (hBody : m.body = [ANFBinding.mk r' (.loadParam p) psrc])
    (hArg : s.resolveRef a = some av)
    (hArgLast : Stack.Lower.isLastUse lastUses a currentIndex = true)
    (hArgUnprot : Stack.Lower.listContains outerProtected a = false)
    (hParamUnprot : Stack.Lower.listContains outerProtected p = false) :
    ((RunarVerification.ANF.Eval.evalBindingsP progMethods s
        [ANFBinding.mk bn (.methodCall obj method [a]) src]).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                currentIndex lastUses outerProtected localBindings
                constInts (a :: rest)
                [ANFBinding.mk bn (.methodCall obj method [a]) src]).1 stk).toOption.isSome) := by
  have hAnf :
      (RunarVerification.ANF.Eval.evalBindingsP progMethods s
        [ANFBinding.mk bn (.methodCall obj method [a]) src]).toOption.isSome = true := by
    rw [evalBindingsP_singleton_methodCall_isSome_eq]
    exact evalMethodCall_passthrough_isSome progMethods s obj method a p r' psrc ptype m av
      hLookupAnf hParams hBody hArg
  have hStack :
      (runOps (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
                currentIndex lastUses outerProtected localBindings
                constInts (a :: rest)
                [ANFBinding.mk bn (.methodCall obj method [a]) src]).1 stk).toOption.isSome = true :=
    runOps_lowerBindingsP_passthrough_methodCall_isSome
      progMethods props budget' currentIndex lastUses outerProtected
      localBindings constInts rest bn obj method a p r' src psrc ptype m stk
      hLookupStack hObj hParams hBody hArgLast hArgUnprot hParamUnprot
  rw [hAnf, hStack]

/-! ### Wave 65 MANDATORY smoke — concrete passthrough `method_call`, both
sides `.isSome` via `evalBindingsP` (anti-vacuous, param-passing). -/

/-- Smoke program method: identity-passthrough callee `idfn(x) { return x }`. -/
private def wave65SmokeCallee : ANFMethod :=
  { name := "idfn", params := [{ name := "x", type := .bigint }],
    body := [ANFBinding.mk "r0" (.loadParam "x") none],
    isPublic := false }

private def wave65SmokeMethods : List ANFMethod := [wave65SmokeCallee]

/-- Smoke outer body: `c0 := idfn(a)`. `a` is the (sole) outer stack-map
entry at depth 0; the object `this` is absent from `[a]`. -/
private def wave65SmokeBody : List ANFBinding :=
  [ANFBinding.mk "c0" (.methodCall "this" "idfn" ["a"]) none]

/-- Smoke caller ANF state: the arg `a` resolves (bound as a param). -/
private def wave65SmokeState : State :=
  { (default : State) with params := [("a", .vBigint 99)] }

/-- The smoke arg load lemma facts hold concretely. -/
theorem wave65_smoke_arg_resolves :
    wave65SmokeState.resolveRef "a" = some (.vBigint 99) := by
  unfold wave65SmokeState RunarVerification.ANF.Eval.State.resolveRef
    RunarVerification.ANF.Eval.State.lookupBinding RunarVerification.ANF.Eval.State.lookupParam
    RunarVerification.ANF.Eval.State.lookupProp
  rfl

/-- Wave-65 smoke: the passthrough M2 walk fires on the concrete
param-passing `method_call` body — both sides `.isSome` through
`evalBindingsP`, so the iff is `True ↔ True` (anti-vacuous; the standard
`evalBindings` would error on this body, and the callee references its OWN
param `x` bound from the caller's arg `a`). -/
theorem wave65_smoke_methodCall_passthrough_unconditional :
    ((RunarVerification.ANF.Eval.evalBindingsP wave65SmokeMethods
        wave65SmokeState wave65SmokeBody).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP wave65SmokeMethods [] (0 + 1)
                0 [("a", 0)] [] [] [] ["a"] wave65SmokeBody).1
        (default : Stack.Eval.StackState)).toOption.isSome) :=
  successAgrees_methodCall_passthrough_unconditional
    wave65SmokeMethods [] 0 0 [("a", 0)] [] [] [] [] "c0" "this" "idfn" "a" "x" "r0"
    none none .bigint wave65SmokeCallee wave65SmokeState
    (default : Stack.Eval.StackState) (.vBigint 99)
    rfl rfl (by decide) rfl rfl wave65_smoke_arg_resolves
    (by decide) rfl rfl

/-- Anti-vacuity confirmation: on the passthrough smoke body the
program-aware `evalBindingsP` succeeds (`isSome = true`) where the
standard `evalBindings` errors (`isSome = false`). -/
theorem wave65_smoke_evalBindingsP_isSome :
    (RunarVerification.ANF.Eval.evalBindingsP wave65SmokeMethods
        wave65SmokeState wave65SmokeBody).toOption.isSome = true := by
  native_decide

theorem wave65_smoke_evalBindings_isNone :
    (RunarVerification.ANF.Eval.evalBindings
        wave65SmokeState wave65SmokeBody).toOption.isSome = false := by
  native_decide

/-! ## Wave 66 — the decidable method-level `method_call` consume classifier

Step 1 of 2 toward retiring the `method_call` sub-omnibus axiom
(`Pipeline.compileSafe_observational_correct_modulo_method_call_codegen`,
since REMOVED in wave 66 step 2, 2026-05-24).
This wave is ADD-ONLY: the classifier + its extraction + a method-level
passthrough wrapper are introduced here, and the consume theorem + smoke
land in `Pipeline.lean`. The gated dispatch + axiom removal landed in
step 2 (the omnibus now classifies on `methodCallConsumeShapeBool` and
discharges the TRUE case with the consume theorem; see its docstring in
`Pipeline.lean`).

### The retirable fragment

The classifier recognises the **param-passthrough** `method_call`
fragment — the genuinely RAW = `[]` shape the wave-65 M2 walk
(`successAgrees_methodCall_passthrough_unconditional`) already covers at
the body level. A method `m` is in the fragment when:

* `m` has exactly one param `a` (so the method's initial stack map
  `(m.params.map name).reverse = [a]`);
* `m.body` is a single binding `[bn := methodCall obj method [a]]`;
* the object reference `obj ≠ a` (so `obj` is absent from `[a]` and the
  `objDropOps` branch reduces to `[]`);
* the call-site arg `a` is on its last use at index `0`
  (`isLastUse (computeLastUses m.body) a 0`), so the arg load consumes
  in place with NO op;
* the callee `method` resolves to a one-param identity helper
  `helper(p) { return p }` (`m'.params = [{p,_}]`, `m'.body =
  [r' := loadParam p]`).

The whole methodCall then lowers to the EMPTY op list, so the M3 / M4
legs of the consume theorem are TRIVIAL (`peephole [] = []`,
`AreRunarEmittablePush []`). The classifier is BODY-only in the sense
the omnibus needs (no tsm), but — like the leaf predicates already in
this file (`methodSingletonMethodCallLeafBody`) and unlike the
methodCall-free `update_prop` classifier — it must carry `progMethods`
to resolve the callee shape.

VACUOUS for every non-passthrough method (the `_ => false` arms), so a
keyed omnibus premise on it stays jointly satisfiable.

The wider const-leaf shape (`successAgrees_methodCall_unconditional`,
non-empty `structuralConstBody` callee) is a DEFERRED widening: it does
NOT lower to `[]` (the callee's const pushes survive), so its M4 leg
needs the non-trivial push-emittability argument for const pushes rather
than the empty-ops identity. That widening is left for a follow-up. -/

/-- Identity-callee check: the resolved callee `m'` is a one-param
identity helper `helper(p) { return p }`. Factored out so the
classifier's outer `split` stays shallow. -/
def methodCallConsumeCalleeBool (m' : ANFMethod) : Bool :=
  match m'.params, m'.body with
  | [pp], [ANFBinding.mk _r' (.loadParam q) _psrc] => pp.name == q
  | _, _ => false

/-- Bool checker for the method-level passthrough `method_call` consume
fragment. `decide`-able on closed terms. -/
def methodCallConsumeShapeBool
    (progMethods : List ANFMethod) (m : ANFMethod) : Bool :=
  match m.params, m.body with
  | [pa], [ANFBinding.mk _bn (.methodCall obj method [arg]) _src] =>
      (arg == pa.name)
        && (obj != pa.name)
        && (Stack.Lower.isLastUse (Stack.Lower.computeLastUses m.body) pa.name 0)
        && (match Stack.Lower.lookupMethod progMethods method with
            | none => false
            | some m' => methodCallConsumeCalleeBool m')
  | _, _ => false

/-- NEW-004: the methodCall-consume shape is a singleton `.methodCall`
body, which marks no raw slot. -/
theorem collectRawSlots_nil_of_methodCallConsumeShapeBool
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodCallConsumeShapeBool progMethods m = true) :
    Stack.Lower.collectRawSlots m.body = [] := by
  unfold methodCallConsumeShapeBool at h
  match hp : m.params, hb : m.body, h with
  | [pa], [ANFBinding.mk bn (.methodCall obj method [arg]) src], _ =>
      exact collectRawSlots_singleton_methodCall bn obj method [arg] src

/-- `arrayElems` peer of `collectRawSlots_nil_of_methodCallConsumeShapeBool`. -/
theorem arrayElemsOf_nil_of_methodCallConsumeShapeBool
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodCallConsumeShapeBool progMethods m = true) :
    Stack.Lower.arrayElemsOf m.body = [] := by
  unfold methodCallConsumeShapeBool at h
  match hp : m.params, hb : m.body, h with
  | [pa], [ANFBinding.mk bn (.methodCall obj method [arg]) src], _ =>
      exact arrayElemsOf_singleton_methodCall bn obj method [arg] src

/-- Callee extraction: a `methodCallConsumeCalleeBool`-true callee is
EXACTLY a one-param identity helper. -/
theorem methodCallConsumeCalleeBool_extract (m' : ANFMethod)
    (h : methodCallConsumeCalleeBool m' = true) :
    ∃ (p r' : String) (psrc : Option SourceLoc)
      (ptype : RunarVerification.ANF.ANFType),
      m'.params = [{ name := p, type := ptype }] ∧
      m'.body = [ANFBinding.mk r' (.loadParam p) psrc] := by
  unfold methodCallConsumeCalleeBool at h
  -- Destructure the param list and body via `cases` on the spine so the
  -- callee match in `h` reduces; non-matching shapes contradict `h = true`.
  cases hP : m'.params with
  | nil => rw [hP] at h; simp at h
  | cons pp ptl =>
      cases ptl with
      | cons _ _ => rw [hP] at h; simp at h
      | nil =>
          cases hB : m'.body with
          | nil => rw [hP, hB] at h; simp at h
          | cons b btl =>
              cases btl with
              | cons _ _ => rw [hP, hB] at h; simp at h
              | nil =>
                  obtain ⟨r', bv, bsrc⟩ := b
                  cases bv with
                  | loadParam q =>
                      rw [hP, hB] at h
                      simp only [beq_iff_eq] at h
                      exact ⟨pp.name, r', bsrc, pp.type, rfl, by rw [h]⟩
                  | _ => rw [hP, hB] at h; simp at h

/-- **Wave 66 extraction.**  A `methodCallConsumeShapeBool`-true method
yields ALL the witnesses + facts the wave-65 passthrough M2 walk
(`successAgrees_methodCall_passthrough_unconditional`) and the
method-level passthrough wrapper consume: the outer-method shape
(single param `a`, singleton methodCall body), the object disjointness,
the arg last-use, and the callee identity shape — together with the
derived facts (`obj` absent from `[a]`, the param-name equality). -/
theorem methodCallConsumeShapeBool_extract
    (progMethods : List ANFMethod) (m : ANFMethod)
    (h : methodCallConsumeShapeBool progMethods m = true) :
    ∃ (a bn obj method p r' : String)
      (src psrc : Option SourceLoc) (atype ptype : RunarVerification.ANF.ANFType)
      (m' : ANFMethod),
      m.params = [{ name := a, type := atype }] ∧
      m.body = [ANFBinding.mk bn (.methodCall obj method [a]) src] ∧
      obj ≠ a ∧
      Stack.Lower.isLastUse (Stack.Lower.computeLastUses m.body) a 0 = true ∧
      Stack.Lower.lookupMethod progMethods method = some m' ∧
      m'.params = [{ name := p, type := ptype }] ∧
      m'.body = [ANFBinding.mk r' (.loadParam p) psrc] := by
  unfold methodCallConsumeShapeBool at h
  cases hPa : m.params with
  | nil => rw [hPa] at h; simp at h
  | cons pa ptl =>
      cases ptl with
      | cons _ _ => rw [hPa] at h; simp at h
      | nil =>
          cases hBd : m.body with
          | nil => rw [hPa, hBd] at h; simp at h
          | cons b btl =>
              cases btl with
              | cons _ _ => rw [hPa, hBd] at h; simp at h
              | nil =>
                  obtain ⟨bn, bv, bsrc⟩ := b
                  cases bv with
                  | methodCall obj method args =>
                      cases args with
                      | nil => rw [hPa, hBd] at h; simp at h
                      | cons arg atl =>
                          cases atl with
                          | cons _ _ => rw [hPa, hBd] at h; simp at h
                          | nil =>
                              rw [hPa, hBd] at h
                              simp only [Bool.and_eq_true, beq_iff_eq,
                                bne_iff_ne, ne_eq] at h
                              obtain ⟨⟨⟨hArgEq, hObjNe⟩, hLast⟩, hCallee⟩ := h
                              subst hArgEq
                              match hLk : Stack.Lower.lookupMethod progMethods method with
                              | none =>
                                  rw [hLk] at hCallee; exact absurd hCallee (by simp)
                              | some m' =>
                                  rw [hLk] at hCallee
                                  obtain ⟨p, r', psrc, ptype, hP, hB⟩ :=
                                    methodCallConsumeCalleeBool_extract m' hCallee
                                  exact ⟨pa.name, bn, obj, method, p, r', bsrc,
                                    psrc, pa.type, ptype, m',
                                    by cases pa; rfl, rfl,
                                    hObjNe, hLast, hLk, hP, hB⟩
                  | loadParam _   => rw [hPa, hBd] at h; simp at h
                  | loadProp _    => rw [hPa, hBd] at h; simp at h
                  | loadConst _   => rw [hPa, hBd] at h; simp at h
                  | binOp _ _ _ _ => rw [hPa, hBd] at h; simp at h
                  | unaryOp _ _ _ => rw [hPa, hBd] at h; simp at h
                  | call _ _      => rw [hPa, hBd] at h; simp at h
                  | ifVal _ _ _ _   => rw [hPa, hBd] at h; simp at h
                  | loop _ _ _ _ _    => rw [hPa, hBd] at h; simp at h
                  | assert _      => rw [hPa, hBd] at h; simp at h
                  | updateProp _ _ => rw [hPa, hBd] at h; simp at h
                  | getStateScript => rw [hPa, hBd] at h; simp at h
                  | checkPreimage _ => rw [hPa, hBd] at h; simp at h
                  | deserializeState _ => rw [hPa, hBd] at h; simp at h
                  | addOutput _ _ _ => rw [hPa, hBd] at h; simp at h
                  | addRawOutput _ _ => rw [hPa, hBd] at h; simp at h
                  | addDataOutput _ _ => rw [hPa, hBd] at h; simp at h
                  | arrayLiteral _ => rw [hPa, hBd] at h; simp at h
                  | rawScript _ _ _ => rw [hPa, hBd] at h; simp at h

/-! ## Wave 66 — method-level passthrough wrapper: `lowerMethodUserRawOps = []`

The missing peer of `lowerMethodUserRawOps_methodCall_leafEmpty`: for a
method `m` satisfying `methodCallConsumeShapeBool`, the whole method
lowers to the EMPTY op list. This is the method-level lift that makes the
M3 / M4 legs of the `Pipeline.lean` consume theorem trivial. -/

/-- Bindings-level passthrough op reduction: the singleton passthrough
body lowers to `[]` (lifts `lowerValueP_methodCall_passthrough_ops` to the
`lowerBindingsP` singleton). -/
theorem lowerBindingsP_singleton_passthrough_methodCall_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget' currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (rest : StackMap) (bn obj method a p r' : String)
    (src psrc : Option SourceLoc) (ptype : RunarVerification.ANF.ANFType)
    (m' : ANFMethod)
    (hLookup : Stack.Lower.lookupMethod progMethods method = some m')
    (hObj : Stack.Lower.StackMap.depth? (a :: rest) obj = none)
    (hParams : m'.params = [{ name := p, type := ptype }])
    (hBody : m'.body = [ANFBinding.mk r' (.loadParam p) psrc])
    (hArgLast : Stack.Lower.isLastUse lastUses a currentIndex = true)
    (hArgUnprot : Stack.Lower.listContains outerProtected a = false)
    (hParamUnprot : Stack.Lower.listContains outerProtected p = false) :
    (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
        currentIndex lastUses outerProtected localBindings constInts
        (a :: rest)
        [ANFBinding.mk bn (.methodCall obj method [a]) src]).1 = [] := by
  have hHead :=
    lowerValueP_methodCall_passthrough_ops progMethods props budget'
      currentIndex lastUses outerProtected localBindings constInts rest
      bn obj method a p r' psrc ptype m' hLookup hObj hParams hBody
      hArgLast hArgUnprot hParamUnprot
  have hUnfold :
      (Stack.Lower.lowerBindingsP progMethods props (budget' + 1)
          currentIndex lastUses outerProtected localBindings constInts
          (a :: rest)
          [ANFBinding.mk bn (.methodCall obj method [a]) src]).1
        = (Stack.Lower.lowerValueP progMethods props (budget' + 1)
              currentIndex lastUses outerProtected localBindings constInts
              (a :: rest) bn (.methodCall obj method [a])).1 := by
    with_unfolding_all
      simp [Stack.Lower.lowerBindingsP]
  rw [hUnfold, hHead]

/-- Method-level passthrough wrapper: `lowerMethodUserRawOps` of a method
satisfying `methodCallConsumeShapeBool` is the EMPTY op list. The
extraction pins the outer method to the single-param passthrough shape,
so the method's initial stack map is `[a]` (`rest = []`), `currentIndex`
is `0`, `outerProtected` is `[]` (both `listContains` checks vacuous), and
the arg last-use comes straight from the classifier. -/
theorem lowerMethodUserRawOps_methodCall_passthrough
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (h : methodCallConsumeShapeBool progMethods m = true) :
    lowerMethodUserRawOps progMethods props m = [] := by
  obtain ⟨a, bn, obj, method, p, r', src, psrc, atype, ptype, m',
    hPa, hBd, hObjNe, hLast, hLk, hP, hB⟩ :=
    methodCallConsumeShapeBool_extract progMethods m h
  unfold lowerMethodUserRawOps
  -- `defaultInlineBudget = 8 = 7 + 1`.
  have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
  rw [hBudget]
  -- The method's reversed param-name stack map is `[a]`.
  have hSm : (m.params.map (fun pp => some pp.name) |>.reverse)
      = ([a] : Stack.Lower.StackMap) := by
    rw [hPa]; rfl
  rw [hSm, hBd]
  -- `obj` is absent from `[a]` (since `obj ≠ a`).
  have hObj : Stack.Lower.StackMap.depth? (some a :: []) obj = none := by
    unfold Stack.Lower.StackMap.depth? List.findIdx?
    have hne : ((some a : Option String) == some obj) = false :=
      beq_eq_false_iff_ne.mpr (fun hh => hObjNe (Option.some.inj hh).symm)
    simp [List.findIdx?.go, hne]
  -- The arg last-use, retargeted onto the body shape pinned by `hBd`.
  have hArgLast :
      Stack.Lower.isLastUse
        (Stack.Lower.computeLastUses
          [ANFBinding.mk bn (.methodCall obj method [a]) src]) a 0 = true := by
    rw [← hBd]; exact hLast
  rw [collectRawSlots_singleton_methodCall bn obj method [a] src,
      arrayElemsOf_singleton_methodCall bn obj method [a] src]
  exact lowerBindingsP_singleton_passthrough_methodCall_ops
    progMethods props 7 0
    (Stack.Lower.computeLastUses [ANFBinding.mk bn (.methodCall obj method [a]) src])
    [] ([ANFBinding.mk bn (.methodCall obj method [a]) src].map (fun b => b.name))
    (Stack.Lower.collectConstInts [ANFBinding.mk bn (.methodCall obj method [a]) src])
    [] bn obj method a p r' src psrc ptype m'
    hLk hObj hP hB hArgLast rfl rfl

end Agrees
end RunarVerification.Stack

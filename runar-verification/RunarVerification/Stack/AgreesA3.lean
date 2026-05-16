import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees

/-!
# Stack IR — A3 runtime wrapper for the arith fragment (narrowed)

This file lands the A3 method-level runtime-success wrapper for the
arithmetic fragment of ANF (assert / unaryOp / binOp).

## Honest narrowing

The A3 capstone in the plan calls for a wrapper
`runMethod_lower_public_unique_no_post_structuralArith_isSome` that
guarantees Stack-VM success of a method whose body is built only out
of `assert`, `unaryOp`, and `binOp` value-kinds (plus the const
literals consumed by their operands).

Building that capstone in full requires a *stack-shape invariant* at
the entry of every binding: every referenced TempRef must already sit
at the depth `Stack.Lower.bringToTop` expects, with a value of the
correct dynamic type (a `bigint`/`bool`/`bytes`) for `OP_ADD` / `OP_SUB`
/ `OP_VERIFY` etc. to fire without trapping. The existing landed
substrate covers per-binding Stage C witnesses at specific depth pairs
(`(0,1)`, `(1,0)`, `(>=2,0)`, `(0,>=2)` for binOps, plus depth 0/1/>=2
for assert and unary), but does not yet expose a *whole-body* runtime
`isSome` predicate that does not premise on either:

* `hRunOk` — the conclusion ("runOps … = .ok _") restated as a
  hypothesis, which is the forbidden form, or
* a `taggedStackAligned` / `agreesTagged` chain witness reaching the
  body's end, which is itself stronger than runtime success.

Per the A3 plan's "Path 1 — Honest narrowing" route, this file lands a
*tighter* predicate `structuralArithBodyNarrow` that ALREADY composes
unconditionally with the existing const-only runtime-success theorem
(`runMethod_lower_public_unique_no_post_structuralConst_isSome`).
The narrowing is explicit: every binding in the body must be a literal
load (int / bool / bytes). The decidability instance lets fixtures opt
into the wrapper by `decide` at the Pipeline level, and the ANF-side
companion `evalBindings_structuralArithBodyNarrow_isSome` matches the
existing const fragment for a clean `successAgrees` pairing.

Wider widenings (real `assert` / `unaryOp` / `binOp` bindings) are
**deferred**, with the explicit blocking obligation documented at the
bottom of this file: the missing piece is the body-wide stack-shape
invariant — not the per-binding witness, which Stage C already has.

This file ships NO new axioms and NO `sorry` / `admit`. It is a
strictly proof-bearing scaffold for the A3 wrapper that will compose
with future arithmetic widenings without touching the runtime-success
proof contract.
-/

namespace RunarVerification.Stack
namespace Agrees

open RunarVerification.ANF
open RunarVerification.ANF.Eval (State)
open RunarVerification.Stack.Eval (StackState runOps)
open RunarVerification.Stack.Lower (StackMap bodyEndsInAssert bindingsUseCheckPreimage
                  bindingsUseCodePart bindingsUseDeserializeState)

/-! ## A3 — Narrowed structural-arith fragment

The narrowed fragment is exactly the const fragment under a
distinct name, so that A3 callsites have a stable predicate they can
keep referencing as the wider widenings land. When the broader
`structuralArithBody` (with real `assert` / `unaryOp` / `binOp`
support) is fully discharged in a follow-up, the narrowed predicate
will become a corollary instance of the wider one. -/

/-- Constructor fragment that the **narrowed** arith wrapper accepts.

A value is in the narrowed arith fragment iff it is a literal load
(int / bool / bytes). Real arithmetic constructors (`assert`,
`unaryOp`, `binOp`) require a stack-shape invariant that is not yet
exposed at this layer — see the deferred-widening note at the end of
this file. -/
def structuralArithValueNarrow : ANFValue → Prop
  | .loadConst (.int _) => True
  | .loadConst (.bool _) => True
  | .loadConst (.bytes _) => True
  | _ => False

/-- Every binding in the body lies in the narrowed arith fragment. -/
def structuralArithBodyNarrow : List ANFBinding → Prop
  | [] => True
  | (.mk _ v _) :: rest =>
      structuralArithValueNarrow v ∧ structuralArithBodyNarrow rest

/-- The narrowed arith fragment coincides with the const fragment.

This identity is the single bridge by which every A3 wrapper below
delegates to the corresponding `structuralConst*` theorem in
`Stack/Agrees.lean`. As wider arithmetic widenings land, this lemma
will be replaced by a strict-implication corollary instead of a
mutual equivalence. -/
theorem structuralArithValueNarrow_iff_structuralConstValue
    (v : ANFValue) :
    structuralArithValueNarrow v ↔ structuralConstValue v := by
  cases v with
  | loadConst c =>
      cases c with
      | int _ =>
          constructor
          · intro _; simp [structuralConstValue]
          · intro _; simp [structuralArithValueNarrow]
      | bool _ =>
          constructor
          · intro _; simp [structuralConstValue]
          · intro _; simp [structuralArithValueNarrow]
      | bytes _ =>
          constructor
          · intro _; simp [structuralConstValue]
          · intro _; simp [structuralArithValueNarrow]
      | refAlias _ =>
          constructor
          · intro h; simp [structuralArithValueNarrow] at h
          · intro h; simp [structuralConstValue] at h
      | thisRef =>
          constructor
          · intro h; simp [structuralArithValueNarrow] at h
          · intro h; simp [structuralConstValue] at h
  | loadParam _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | loadProp _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | binOp _ _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | unaryOp _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | call _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | methodCall _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | ifVal _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | loop _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | assert _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | updateProp _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | getStateScript =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | checkPreimage _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | deserializeState _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | addOutput _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | addRawOutput _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | addDataOutput _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | arrayLiteral _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h
  | rawScript _ _ _ =>
      constructor
      · intro h; simp [structuralArithValueNarrow] at h
      · intro h; simp [structuralConstValue] at h

/-- Body-level equivalence between the narrowed arith body and the
const body. Composes pointwise with the per-value identity above. -/
theorem structuralArithBodyNarrow_iff_structuralConstBody :
    ∀ body : List ANFBinding,
      structuralArithBodyNarrow body ↔ structuralConstBody body
  | [] => by
      constructor
      · intro _; simp [structuralConstBody]
      · intro _; simp [structuralArithBodyNarrow]
  | (.mk _ v _) :: rest => by
      have ihRest := structuralArithBodyNarrow_iff_structuralConstBody rest
      have ihHead := structuralArithValueNarrow_iff_structuralConstValue v
      constructor
      · intro h
        simp [structuralArithBodyNarrow] at h
        obtain ⟨hHead, hRest⟩ := h
        refine ⟨?_, ?_⟩
        · exact ihHead.mp hHead
        · exact ihRest.mp hRest
      · intro h
        simp [structuralConstBody] at h
        obtain ⟨hHead, hRest⟩ := h
        refine ⟨?_, ?_⟩
        · exact ihHead.mpr hHead
        · exact ihRest.mpr hRest

/-! ## A3 — Decidability of the narrowed predicate

Pipeline-level callsites discharge the structural precondition with
`decide`, which requires a `Decidable` instance on
`structuralArithBodyNarrow`. We build it via a `Bool` checker, mirroring
the `programIsWF` pattern in `ANF/WF.lean`. -/

/-- Bool-valued checker for the narrowed arith fragment on a single
value. Decidable by `rfl`. -/
def structuralArithValueNarrowB : ANFValue → Bool
  | .loadConst (.int _) => true
  | .loadConst (.bool _) => true
  | .loadConst (.bytes _) => true
  | _ => false

/-- The boolean checker matches the propositional predicate. -/
theorem structuralArithValueNarrowB_iff (v : ANFValue) :
    structuralArithValueNarrowB v = true ↔ structuralArithValueNarrow v := by
  cases v with
  | loadConst c =>
      cases c with
      | int _ =>
          simp [structuralArithValueNarrowB, structuralArithValueNarrow]
      | bool _ =>
          simp [structuralArithValueNarrowB, structuralArithValueNarrow]
      | bytes _ =>
          simp [structuralArithValueNarrowB, structuralArithValueNarrow]
      | refAlias _ =>
          simp [structuralArithValueNarrowB, structuralArithValueNarrow]
      | thisRef =>
          simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | loadParam _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | loadProp _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | binOp _ _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | unaryOp _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | call _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | methodCall _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | ifVal _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | loop _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | assert _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | updateProp _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | getStateScript =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | checkPreimage _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | deserializeState _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | addOutput _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | addRawOutput _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | addDataOutput _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | arrayLiteral _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]
  | rawScript _ _ _ =>
      simp [structuralArithValueNarrowB, structuralArithValueNarrow]

/-- Bool-valued checker for the narrowed arith fragment on a binding
list. List-level decidability follows from the per-value boolean
predicate. -/
def structuralArithBodyNarrowB : List ANFBinding → Bool
  | [] => true
  | (.mk _ v _) :: rest =>
      structuralArithValueNarrowB v && structuralArithBodyNarrowB rest

/-- The boolean body checker matches the propositional body predicate. -/
theorem structuralArithBodyNarrowB_iff :
    ∀ body : List ANFBinding,
      structuralArithBodyNarrowB body = true ↔ structuralArithBodyNarrow body
  | [] => by
      simp [structuralArithBodyNarrowB, structuralArithBodyNarrow]
  | (.mk _ v _) :: rest => by
      have ihTail := structuralArithBodyNarrowB_iff rest
      have ihHead := structuralArithValueNarrowB_iff v
      simp [structuralArithBodyNarrowB, structuralArithBodyNarrow,
            Bool.and_eq_true, ihHead, ihTail]

instance instDecidableStructuralArithValueNarrow (v : ANFValue) :
    Decidable (structuralArithValueNarrow v) :=
  decidable_of_iff (structuralArithValueNarrowB v = true)
    (structuralArithValueNarrowB_iff v)

instance instDecidableStructuralArithBodyNarrow (body : List ANFBinding) :
    Decidable (structuralArithBodyNarrow body) :=
  decidable_of_iff (structuralArithBodyNarrowB body = true)
    (structuralArithBodyNarrowB_iff body)

/-! ## A3 — ANF-side success for the narrowed arith fragment

`evalBindings` on a narrowed-arith body always succeeds, because the
narrowed fragment is exactly the const fragment by
`structuralArithBodyNarrow_iff_structuralConstBody`. -/

/-- `evalBindings` always succeeds on a narrowed arith body. -/
theorem evalBindings_structuralArithBodyNarrow_isSome
    (body : List ANFBinding) (s : State)
    (h : structuralArithBodyNarrow body) :
    (RunarVerification.ANF.Eval.evalBindings s body).toOption.isSome :=
  evalBindings_structuralConstBody_isSome body s
    ((structuralArithBodyNarrow_iff_structuralConstBody body).mp h)

/-! ## A3 — Runtime-side success for the narrowed arith fragment

`runOps` on the lowered op list of a narrowed-arith body always
succeeds from any starting stack — the same statement the const
fragment carries. -/

/-- `runOps` of a narrowed-arith body's lowered op list succeeds from
any starting stack. -/
theorem runOps_lowerBindings_structuralArithBodyNarrow_isSome
    (body : List ANFBinding) (sm : StackMap) (stk : StackState)
    (h : structuralArithBodyNarrow body) :
    (runOps (Stack.Lower.lowerBindings sm body).1 stk).toOption.isSome :=
  runOps_lowerBindings_structuralConstBody_isSome body sm stk
    ((structuralArithBodyNarrow_iff_structuralConstBody body).mp h)

/-! ## A3 — Method-level runtime-success wrapper

The capstone the plan calls for. Predicates: every binding is in the
narrowed arith fragment, plus the standard method-shape side
conditions used by `runMethod_lower_public_unique_no_post_eq_userRaw`
(public, unique, no `checkPreimage`, no `codePart`, no terminal
`assert`, no `deserializeState`). No `hRunOk` / `hSimulates` / chain
witness / agreesTagged hypotheses — the wrapper composes only
structural predicates and the existing const-fragment runtime-success
theorem. -/

/-- Method-level runtime-success wrapper for the **narrowed** arith
fragment. The conclusion matches
`runMethod_lower_public_unique_no_post_structuralConst_isSome`: the
Stack VM never gets stuck running the lowered body of a narrowed-arith
method. -/
theorem runMethod_lower_public_unique_no_post_structuralArith_narrow_isSome
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
    (hArith : structuralArithBodyNarrow m.body) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome :=
  runMethod_lower_public_unique_no_post_structuralConst_isSome
    contractName props methods m initialStack
    hMem hPublic hUnique hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize
    ((structuralArithBodyNarrow_iff_structuralConstBody m.body).mp hArith)

/-! ## What is NOT proved here (honest deferral)

The narrowed wrapper above covers literal-load bodies under a distinct
predicate name (`structuralArithBodyNarrow`). It does **not** cover
real `assert` / `unaryOp` / `binOp` bindings.

What blocks the wider discharge in a single session:

* **Body-wide stack-shape invariant.** The Stage C operational
  witnesses landed in `Stack/Agrees.lean` (for `OP_ADD` / `OP_SUB` /
  `OP_VERIFY` / `OP_NEGATE` / `OP_NOT` / `OP_INVERT` etc.) require
  a specific *depth pair* (`(0,1)`, `(1,0)`, `(0,>=2)`, `(>=2,0)`)
  between the binding's two operands. Promoting that to a body-wide
  `isSome` statement needs a precondition that every binding's
  referenced operands sit at one of the supported depth pairs after
  the lowerer threads the preceding bindings. This precondition is
  *not* one of the project's lookup-readiness predicates today.

* **Dynamic-type invariant.** Even with the right depth pair, Stack VM
  primitives like `OP_ADD` trap unless the two operands are
  `bigint`-shaped at runtime. The narrowed wrapper sidesteps this by
  restricting to const-only bodies; the wider wrapper needs a
  "stack values match ANF types" invariant that survives across
  bindings, which is exactly what `agreesTagged` provides but is
  forbidden here as a hypothesis (it implies runtime success).

* **No new axioms.** Adding the body-wide invariant would have to
  derive runtime success from structural data alone; that derivation
  is multi-binding and depends on Stage C's per-binding operational
  witnesses being lifted through the same chain composition that
  `agreesTagged_chain_preserves` already abstracts. The full lift
  for the arith fragment is the open obligation; this file's
  narrowed wrapper is the proof-bearing scaffold the wider lift
  will compose with.

When the wider obligation is discharged (in a future session that
adds the body-wide depth/type invariant), the wider predicate will
strict-imply `structuralArithBodyNarrow`, so existing callsites
keep working unchanged. -/

end Agrees
end RunarVerification.Stack

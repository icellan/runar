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

/-! ## A3 — `structuralArithBodyReal`: widened real-arith body predicate

The narrowed `structuralArithBodyNarrow` predicate above is a const-only
alias. The **real** A3 fragment admits `binOp` / `unaryOp` / `assert`
bindings (in copy-mode against the liveness state). The substrate for
the real predicate already lives in `Stack/Agrees.lean` as the public
`Stack.Agrees.structuralArithBody`, together with its Decidable
instance (`decidableStructuralArithBody`) and ANF-side success theorem
(`evalBindings_structuralArithBody_isSome`).

We expose the real fragment from this file under the `…Real` suffix so
A3-aware callsites can branch on `structuralArithBodyReal` (decidable)
without reaching into `Stack/Agrees.lean` directly.

### What is widened, what is held

The runtime-side `isSome` wrapper for a *fully general* arith body
hits the same wall the deferred-note at `Stack/Agrees.lean:16711-16716`
documents: opcodes emitted for `binOp` / `unaryOp` / `assert` have
value-dependent failure modes (e.g. `OP_VERIFY` fails on `vBool false`,
`OP_ADD` fails on non-int operands). Discharging the body-level
`runOps … isSome` therefore needs *concrete runtime values* on the
stack — facts only `agreesTagged` + per-slot type witnesses can
deliver.

`agreesTagged` is allowed by the §2.1 workflow rule (it is an
input-side state invariant, **not** a conclusion-restating
hypothesis). The remaining gap is the per-slot dynamic-type fact:
"the depth-0 stack value really is a `.vBool true`" for the assert
case, "really is a `.vBigint`" for binOp/unaryOp etc. These are
input-side `lookupAnfByKind = some v` hypotheses, also permitted.

### Tier-1 deliverable (this file)

This file lands:

1. `structuralArithBodyReal` — public Prop alias of
   `Stack.Agrees.structuralArithBody` over the same parameter pack.
   Real binOp / unaryOp / assert bodies satisfy it; the narrowed
   const-only predicate is *not* a subset (the parameter packs
   differ), but every const-only body satisfies the real predicate
   structurally.
2. `Decidable (structuralArithBodyReal …)` — inherited via
   `decidable_of_iff` from the underlying real predicate.
3. `runMethod_lower_public_unique_no_post_structuralArith_real_isSome`
   — method-level runtime-success wrapper for the narrowed
   **singleton-assert at depth 0** sub-fragment. The hypotheses are
   purely structural / input-side (no `hRunOk` / `hSimulates`):
   * `hSingleAssert : m.body = [⟨bn, .assert n, _⟩]` with `n` the
     depth-0 parameter — a structural body shape.
   * `hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack`
     — input-side state invariant.
   * `hLookup : anfSt.lookupParam n = some (.vBool true)` — input-side
     ANF-state domain fact.
   * `hBodyFresh : bn ≠ n ∧ ¬ bn ∈ tsm_rest` — SSA freshness.
   * `hParamsRev : (m.params.map (·.name)).reverse = n :: tail` and
     `untagSm tsm_rest = tail` — initial stack-map shape.

   Conclusion: `runMethod (lower …) m.name initialStack |>.toOption.isSome`.

   The proof:
   * Routes through the existing `runMethod_lower_public_unique_no_post_eq_userRaw`
     bridge.
   * Reduces `lowerMethodUserRawOps` to `[.opcode "OP_VERIFY"]` by
     unfolding `lowerBindingsP` over the singleton body and
     consume-mode `loadRefLive` at depth 0 (which produces `[]`).
   * Discharges `runOps [.opcode "OP_VERIFY"] initialStack = .ok _`
     via direct unfolding using `hAgrees` + `hLookup` to expose the
     top-of-stack `vBool true`.

### Why broader Tier 1+ targets are deferred

Extending to `binOp` / `unaryOp` singleton wrappers requires:

* A `loadRefLive_copy_eq_loadRef`-style bridge usable from this file
  (the existing one is `private` in `Stack/Agrees.lean`, and §2.4
  forbids touching `Stack/Agrees.lean` from per-family wrapper files).
* Re-deriving the bridge inline here against the program-aware
  `lowerBindingsP` machinery, which is a multi-hundred-line proof
  per arm.

The singleton-assert wrapper landed here is the minimum widening
that exercises the `agreesTagged` + lookup precondition pattern, and
serves as the template for follow-up sessions that re-prove the
`lowerValueP_*_eq` bridges inline for binOp/unaryOp. -/

/-- Real-arith body predicate.  Public alias of the substrate in
`Stack/Agrees.lean`. Covers `binOp` / `unaryOp` / `assert` bindings
in copy-mode, in addition to all ref-load fragments.

This is the predicate the SupportedANFBody widening will compose
against once the per-family runtime-success wrappers land. -/
def structuralArithBodyReal
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (body : List ANFBinding) (sm : StackMap) (currentIndex : Nat) : Prop :=
  Stack.Agrees.structuralArithBody progMethods props budget lastUses
    outerProtected localBindings constInts body sm currentIndex

instance instDecidableStructuralArithBodyReal
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (body : List ANFBinding) (sm : StackMap) (currentIndex : Nat) :
    Decidable (structuralArithBodyReal progMethods props budget lastUses
        outerProtected localBindings constInts body sm currentIndex) :=
  inferInstanceAs
    (Decidable (Stack.Agrees.structuralArithBody progMethods props budget lastUses
        outerProtected localBindings constInts body sm currentIndex))

/-! ## A3 — Tier-1 method-level wrapper: singleton-`assert` at depth 0

Tightly-narrowed runtime-success wrapper for the simplest real-arith
body shape: a single `assert n` binding where `n` is a depth-0
parameter and the ANF state has `n = .vBool true`.

The body-shape side-condition `singletonAssertAtDepth0 m n bn` packages
the structural facts in one Prop, decoupling the predicate from the
ANF state. -/

/-- Structural predicate: `m` has body `[⟨bn, .assert n, src⟩]` and
the reversed parameter list starts with `n`. The remainder of the
parameter list (`tail`) is exposed for the alignment hypothesis. -/
def singletonAssertAtDepth0 (m : ANFMethod) (n bn : String)
    (tail : List String) (src : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .assert n, src⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n :: tail

/-! ### Auxiliary lemmas about the singleton-assert body's lowering -/

/-- `collectRefs (.assert n) = [n]`. -/
private theorem collectRefs_assert (n : String) :
    Stack.Lower.collectRefs (.assert n) = [n] := by
  unfold Stack.Lower.collectRefs
  rfl

/-- `lastUsesUpdate [] n 0 = [(n, 0)]`. -/
private theorem lastUsesUpdate_empty (n : String) (idx : Nat) :
    Stack.Lower.lastUsesUpdate [] n idx = [(n, idx)] := by
  unfold Stack.Lower.lastUsesUpdate
  simp

/-- `computeLastUses` on a singleton-assert body records `[(n, 0)]`. -/
private theorem computeLastUses_singleton_assert
    (bn n : String) (src : Option SourceLoc) :
    Stack.Lower.computeLastUses [⟨bn, .assert n, src⟩] = [(n, 0)] := by
  unfold Stack.Lower.computeLastUses
  simp [Stack.Lower.computeLastUses.go, collectRefs_assert n,
        lastUsesUpdate_empty]

/-- `collectConstInts` on a singleton-assert body is `[]`. -/
private theorem collectConstInts_singleton_assert
    (bn n : String) (src : Option SourceLoc) :
    Stack.Lower.collectConstInts [⟨bn, .assert n, src⟩] = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

/-- `bindingsUseCheckPreimage` on a singleton-assert body is `false`. -/
private theorem bindingsUseCheckPreimage_singleton_assert
    (bn n : String) (src : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage [⟨bn, .assert n, src⟩] = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

/-- `bindingsUseCodePart` on a singleton-assert body is `false`. -/
private theorem bindingsUseCodePart_singleton_assert
    (bn n : String) (src : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart [⟨bn, .assert n, src⟩] = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

/-- `bindingsUseDeserializeState` on a singleton-assert body is `false`. -/
private theorem bindingsUseDeserializeState_singleton_assert
    (bn n : String) (src : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState [⟨bn, .assert n, src⟩] = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

/-- `bodyEndsInAssert` on a singleton-assert body — note this is `true`,
which means the terminal-assert elision would normally fire. The wrapper
below requires the caller to pass `hNoTerminalAssert = false` instead
(i.e. the assert is the last binding so elision DOES apply). We handle
this by routing the proof through the post-elision path. -/
private theorem bodyEndsInAssert_singleton_assert
    (bn n : String) (src : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert [⟨bn, .assert n, src⟩] = true := by
  rfl

/-! ### `lastUsesLookup` / `isLastUse` reductions on the singleton record -/

/-- `lastUsesLookup [(n, 0)] n = some 0`. -/
private theorem lastUsesLookup_singleton (n : String) :
    Stack.Lower.lastUsesLookup [(n, 0)] n = some 0 := by
  unfold Stack.Lower.lastUsesLookup
  simp

/-- `isLastUse [(n, 0)] n 0 = true`. -/
private theorem isLastUse_singleton (n : String) :
    Stack.Lower.isLastUse [(n, 0)] n 0 = true := by
  unfold Stack.Lower.isLastUse
  rw [lastUsesLookup_singleton n]
  simp

/-- `listContains [] _ = false`. -/
private theorem listContains_nil_local (n : String) :
    Stack.Lower.listContains [] n = false := by
  unfold Stack.Lower.listContains
  simp

/-! ### Core operational reduction: singleton-assert lowers to `[OP_VERIFY]`

Under singleton-assert with `n` at the head of the initial stack map,
the program-aware lowerer's `loadRefLive` chooses consume-mode at
depth 0 (returns `[]`), so the assert binding's lowered ops collapse
to `[.opcode "OP_VERIFY"]`. -/

private theorem lowerMethodUserRawOps_singleton_assert
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (n bn : String) (tail : List String)
    (src : Option SourceLoc)
    (hSingle : singletonAssertAtDepth0 m n bn tail src) :
    lowerMethodUserRawOps progMethods props m = [.opcode "OP_VERIFY"] := by
  obtain ⟨hBody, hRev⟩ := hSingle
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singleton_assert bn n src]
  rw [collectConstInts_singleton_assert bn n src]
  -- Unfold `lowerBindingsP` once on the singleton body.
  unfold Stack.Lower.lowerBindingsP
  -- For `.assert`, `lowerValueP` returns `(load ++ [OP_VERIFY], sm1.popN 1, localBindings)`
  -- where `(load, sm1) = loadRefLive sm n 0 [(n,0)] []`.
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil_local n]
  rw [isLastUse_singleton n]
  -- consume = !false && true = true
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  -- `(n :: tail).findIdx? (· == n) = some 0`
  have hFind : (n :: tail).findIdx? (· == n) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  -- consume = true at depth 0 produces `([], sm)`
  simp only [if_true]
  -- Body's load is now [], so ops = [] ++ [OP_VERIFY] = [OP_VERIFY].
  -- The tail of lowerBindingsP is empty (singleton body).
  simp [Stack.Lower.lowerBindingsP]

/-! ### Runtime success for `[OP_VERIFY]` given `agreesTagged + lookup` -/

/-- Helper: under `agreesTagged + lookupParam = some (.vBool true)`, the
runtime stack has `.vBool true` on top. -/
private theorem initialStack_top_vBool_true_of_agreesTagged
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool true)) :
    ∃ rest, initialStack.stack = .vBool true :: rest := by
  have hAlign : taggedStackAligned ((n, .param) :: tsm_rest) anfSt initialStack.stack :=
    hAgrees.1
  -- We need to read off the head value of the runtime stack. The tagged
  -- alignment gives `lookupAnfByKind anfSt (n, .param) = some topV`, which
  -- after unfolding the kind dispatch equals `anfSt.lookupParam n = some topV`,
  -- which by `hLookup` equals `some (.vBool true)`.
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | topV :: rest =>
      rw [hCases] at hAlign
      have hHead : lookupAnfByKind anfSt (n, .param) = some topV := by
        unfold taggedStackAligned at hAlign
        exact hAlign.1
      have hHead' : anfSt.lookupParam n = some topV := hHead
      have hVeq : topV = .vBool true := by
        have hCombined : some topV = some (.vBool true) := hHead'.symm.trans hLookup
        exact Option.some.inj hCombined
      exact ⟨rest, by rw [hVeq]⟩

/-- Under `agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack` and
`anfSt.lookupParam n = some (.vBool true)`, the runtime stack has
`.vBool true` on top, and `runOps [.opcode "OP_VERIFY"] initialStack`
succeeds. -/
private theorem runOps_verify_of_agreesTagged_paramTrue
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool true)) :
    (Stack.Eval.runOps [.opcode "OP_VERIFY"] initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_vBool_true_of_agreesTagged n tsm_rest anfSt initialStack
      hAgrees hLookup
  have hVerify :
      Stack.Eval.runOpcode "OP_VERIFY" initialStack
        = .ok { initialStack with stack := rest } :=
    Stack.Sim.runOpcode_verify_pop_vBool_true initialStack rest hStk
  -- Use the existing `run_assert_true`-style reduction inline.
  show (Stack.Eval.runOps (.opcode "OP_VERIFY" :: []) initialStack).toOption.isSome
  unfold Stack.Eval.runOps
  rw [Stack.Eval.stepNonIf_opcode, hVerify]
  simp [Stack.Eval.runOps, Except.toOption]

/-! ### Method-level wrapper for the singleton-assert sub-fragment

The Tier-1 deliverable. Hypotheses:
* `hSingle` — body shape (singleton assert at depth 0 in the reversed
  param list).
* `hMem` / `hPublic` / `hUnique` — public-name-uniqueness for
  `runMethod` dispatch.
* `hAgrees` — initial agreesTagged invariant. INPUT-SIDE.
* `hLookup` — operand resolves to `.vBool true`. INPUT-SIDE.
* `hUntagSm` — the tagged-stack-map's underlying string list matches
  the lowerer's initial stack map (reversed params).
* `hAssertConditionsHandled` — caller-supplied predicate guarantees
  the four standard no-implicit/post-processing flags. We unpack the
  flags structurally from `hSingle` (none of them fire on a
  singleton-assert body, EXCEPT terminal-assert elision, which is
  why we additionally accept `hAllowTerminalAssert : bodyEndsInAssert
  m.body = true` and route through the elided code path).

**Note on terminal-assert elision.** For a singleton-assert body, the
last binding IS an assert. The standard `runMethod_lower_public_unique_no_post_eq_userRaw`
bridge requires `bodyEndsInAssert = false` (so elision does NOT fire);
that path is invalid for our case. We could:
(a) route through the elision path (different bridge, different ops);
(b) require the caller to provide a body shape where the assert is
not terminal — e.g. `body = [assertBinding, throwawayBinding]`.

Option (b) keeps the wrapper compatible with the standard bridge.
We take option (b): require the body to be the singleton plus a
terminal `.loadConst (.bool true)` capping binding, which makes
`bodyEndsInAssert = false`. The caller provides this composite body
shape via `singletonAssertWithCap`. -/

/-- Composite structural shape: body is `[⟨bn, .assert n, src⟩,
⟨bcap, .loadConst (.bool true), srcCap⟩]` — an assert followed by a
sentinel const-load whose only role is to keep the assert from being
the terminal binding (so the standard `bodyEndsInAssert = false`
bridge applies). The cap binding's value is a const literal, which
`lowerValueP` lowers to a single `.push` op that `runOps` cannot
fail on. -/
def singletonAssertWithCap (m : ANFMethod)
    (n bn bcap : String) (tail : List String)
    (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n :: tail ∧
  bn ≠ bcap ∧ bcap ≠ n

/-! ### Lowering reductions for `singletonAssertWithCap` -/

/-- `collectRefs (.loadConst (.bool true)) = []`. -/
private theorem collectRefs_loadConst_bool_true :
    Stack.Lower.collectRefs (.loadConst (.bool true)) = [] := rfl

/-- `computeLastUses` on `[assertBinding, capBinding]` records `[(n, 0)]`
(the cap binding reads nothing). -/
private theorem computeLastUses_singletonAssertWithCap
    (bn bcap n : String) (src srcCap : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [(n, 0)] := by
  unfold Stack.Lower.computeLastUses
  simp [Stack.Lower.computeLastUses.go, collectRefs_assert n,
        collectRefs_loadConst_bool_true, lastUsesUpdate_empty]

/-- `collectConstInts` on `[assertBinding, capBinding]` is `[]` (no
`.loadConst (.int _)` bindings). -/
private theorem collectConstInts_singletonAssertWithCap
    (bn bcap n : String) (src srcCap : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

/-- The four flag-free side conditions on a `singletonAssertWithCap` body. -/
private theorem bindingsUseCheckPreimage_singletonAssertWithCap
    (bn bcap n : String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage
        [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

private theorem bindingsUseCodePart_singletonAssertWithCap
    (bn bcap n : String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart
        [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

private theorem bindingsUseDeserializeState_singletonAssertWithCap
    (bn bcap n : String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState
        [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

private theorem bodyEndsInAssert_singletonAssertWithCap
    (bn bcap n : String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert
        [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  rfl

/-! ### Lowering of `singletonAssertWithCap`: `[OP_VERIFY, push true]` -/

set_option maxHeartbeats 1600000 in
private theorem lowerMethodUserRawOps_singletonAssertWithCap
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (n bn bcap : String) (tail : List String)
    (src srcCap : Option SourceLoc)
    (hCap : singletonAssertWithCap m n bn bcap tail src srcCap) :
    lowerMethodUserRawOps progMethods props m
      = [.opcode "OP_VERIFY", .push (.bool true)] := by
  obtain ⟨hBody, hRev, _, _⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonAssertWithCap bn bcap n src srcCap]
  rw [collectConstInts_singletonAssertWithCap bn bcap n src srcCap]
  -- The depth-0 lookup of n in the param stack map is `some 0`.
  have hFind : (n :: tail).findIdx? (· == n) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  -- Step 1: unfold the outer lowerBindingsP cons on the assert binding.
  unfold Stack.Lower.lowerBindingsP
  -- Step 2: reduce lowerValueP for the .assert head using consume-mode at depth 0.
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
  rw [listContains_nil_local n, isLastUse_singleton n]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.StackMap.depth?
  rw [hFind]
  simp only [if_true]
  -- After the depth-0 consume reduction, the head emits `([], n :: tail)`, so the
  -- assert binding's load is empty and its ops are `[OP_VERIFY]`.
  -- The inner lowerBindingsP processes the cap binding `.loadConst (.bool true)`.
  unfold Stack.Lower.StackMap.popN
  -- Continue with the second binding.
  unfold Stack.Lower.lowerBindingsP
  -- Reduce lowerValueP for `.loadConst (.bool true)`: emits `[.push (.bool true)]`.
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  -- The tail of lowerBindingsP on [] is empty.
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### Runtime success for `[OP_VERIFY, push true]` -/

/-- Under `agreesTagged + lookup`, `runOps [.opcode "OP_VERIFY", .push (.bool true)] initialStack`
succeeds (the `OP_VERIFY` pops the `.vBool true` operand, then `.push (.bool true)`
unconditionally pushes onto the residue). -/
private theorem runOps_verify_pushTrue_of_agreesTagged
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool true)) :
    (Stack.Eval.runOps [.opcode "OP_VERIFY", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_vBool_true_of_agreesTagged n tsm_rest anfSt initialStack
      hAgrees hLookup
  have hVerify :
      Stack.Eval.runOpcode "OP_VERIFY" initialStack
        = .ok { initialStack with stack := rest } :=
    Stack.Sim.runOpcode_verify_pop_vBool_true initialStack rest hStk
  -- Run the two ops in sequence: OP_VERIFY pops `.vBool true`, then push pushes.
  show (Stack.Eval.runOps (.opcode "OP_VERIFY" :: .push (.bool true) :: []) initialStack).toOption.isSome
  unfold Stack.Eval.runOps
  rw [Stack.Eval.stepNonIf_opcode, hVerify]
  -- Now the tail is `runOps [.push (.bool true)] _`, which is unconditionally `.ok`.
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrapper -- the deliverable -/

/-- **Method-level runtime-success wrapper for the singleton-assert-with-cap
sub-fragment of the real arith body.**

Hypotheses are all structural / well-formedness / input-side:
* `hCap` — composite body shape (assert + sentinel-true cap).
* `hMem` / `hPublic` / `hUnique` — public-name uniqueness.
* `hAgrees` / `hLookup` / `hUntagSm` — initial state agreement +
  operand resolution (input-side, allowed by §2.1).

**No `hRunOk` / `hSimulates`** — the runtime success of `[OP_VERIFY,
push true]` is derived from `hAgrees + hLookup` directly.

This is the Tier-1 widening: a real-arith body (not const-only) whose
runtime success is proved structurally. Tier-2 (more depth pairs,
binOp / unaryOp) follows the same template once the
`loadRefLive_*_eq_loadRef` bridges are re-proved inline. -/
theorem runMethod_lower_public_unique_no_post_structuralArith_real_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n bn bcap : String) (tail : List String)
    (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonAssertWithCap m n bn bcap tail src srcCap)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool true))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  -- Step 1: derive the four flag-free side conditions from `hCap`.
  have hBody : m.body = [⟨bn, .assert n, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩] :=
    hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonAssertWithCap bn bcap n src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonAssertWithCap bn bcap n src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonAssertWithCap bn bcap n src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonAssertWithCap bn bcap n src srcCap
  -- Step 2: route through the standard no-implicit/no-postprocessing bridge.
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- Step 3: reduce `lowerMethodUserRawOps` to `[OP_VERIFY, push true]`.
  rw [lowerMethodUserRawOps_singletonAssertWithCap
        methods props m n bn bcap tail src srcCap hCap]
  -- Step 4: discharge runtime success of the two-op sequence.
  exact runOps_verify_pushTrue_of_agreesTagged n tsm_rest anfSt initialStack
    hAgrees hLookup

/-! ## A3 — Tier-2 widening: singleton `unaryOp` / `binOp` at common depth pairs

This block widens the Tier-1 singleton-`assert`-with-cap wrapper to cover
single `unaryOp` (depth 0) and single `binOp` (depth pair (1,0)) bindings.
The cap binding (`.loadConst (.bool true)`) is preserved so the standard
`runMethod_lower_public_unique_no_post_eq_userRaw` bridge applies
(`bodyEndsInAssert m.body = false`).

The Tier-2 wrappers all reuse the consume-mode `loadRefLive` reduction
from Tier 1 (last-use at the binding's index ⇒ consume = true ⇒ `[]`):
under that reduction `lowerValueP` for the head binding emits only the
operator's opcode (plus the SWAP-style pre-load for the binOp depth-1
operand). No new `simpleStepRel` arm is required because the wrappers
do not rely on `agreesTagged_chain_preserves` — they discharge runtime
success directly from `agreesTagged` on the initial state plus a
`lookupParam` fact giving the operand its concrete dynamic type.

### Hypothesis-hygiene contract

Every Tier-2 wrapper takes the same input-side hypothesis pack as
Tier 1:
* `hCap` — composite body shape (head binding + sentinel-true cap).
* `hMem` / `hPublic` / `hUnique` — public-name uniqueness for dispatch.
* `hAgrees` — initial `agreesTagged` invariant.
* `hLookup` — operand's value in the ANF state (`.vBigint i` / `.vBool b`).
* `hUntagSm` — tagged stack map's underlying string list matches the
  lowerer's initial map.

**No `hRunOk` / `hSimulates`** — the runtime success follows from
`hAgrees + hLookup`.
-/

/-! ### Top-of-stack extraction helpers (vBigint, vBool) -/

/-- Under `agreesTagged + lookupParam = some (.vBigint i)`, the runtime
stack has `.vBigint i` on top. -/
private theorem initialStack_top_vBigint_of_agreesTagged
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (i : Int)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBigint i)) :
    ∃ rest, initialStack.stack = .vBigint i :: rest := by
  have hAlign : taggedStackAligned ((n, .param) :: tsm_rest) anfSt initialStack.stack :=
    hAgrees.1
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | topV :: rest =>
      rw [hCases] at hAlign
      have hHead : lookupAnfByKind anfSt (n, .param) = some topV := by
        unfold taggedStackAligned at hAlign
        exact hAlign.1
      have hHead' : anfSt.lookupParam n = some topV := hHead
      have hVeq : topV = .vBigint i := by
        have hCombined : some topV = some (.vBigint i) := hHead'.symm.trans hLookup
        exact Option.some.inj hCombined
      exact ⟨rest, by rw [hVeq]⟩

/-- Under `agreesTagged + lookupParam = some (.vBool b)`, the runtime
stack has `.vBool b` on top. -/
private theorem initialStack_top_vBool_of_agreesTagged
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (b : Bool)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool b)) :
    ∃ rest, initialStack.stack = .vBool b :: rest := by
  have hAlign : taggedStackAligned ((n, .param) :: tsm_rest) anfSt initialStack.stack :=
    hAgrees.1
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | topV :: rest =>
      rw [hCases] at hAlign
      have hHead : lookupAnfByKind anfSt (n, .param) = some topV := by
        unfold taggedStackAligned at hAlign
        exact hAlign.1
      have hHead' : anfSt.lookupParam n = some topV := hHead
      have hVeq : topV = .vBool b := by
        have hCombined : some topV = some (.vBool b) := hHead'.symm.trans hLookup
        exact Option.some.inj hCombined
      exact ⟨rest, by rw [hVeq]⟩

/-! ### `singletonUnaryNegateWithCap` — body shape `-x; true` at depth 0 -/

/-- Composite body shape for a single `unaryOp "-" n rt` binding at depth 0
followed by the sentinel-true cap. -/
def singletonUnaryNegateWithCap (m : ANFMethod)
    (n bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n :: tail ∧
  bn ≠ bcap ∧ bcap ≠ n

/-- `computeLastUses` on `[unaryBinding, capBinding]` records `[(n, 0)]`. -/
private theorem computeLastUses_singletonUnaryNegateWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [(n, 0)] := by
  unfold Stack.Lower.computeLastUses
  -- collectRefs of .unaryOp returns [operand]; collectRefs of loadConst is [].
  have hRefsUnary : Stack.Lower.collectRefs (.unaryOp "-" n rt) = [n] := by
    unfold Stack.Lower.collectRefs
    rfl
  simp [Stack.Lower.computeLastUses.go, hRefsUnary,
        collectRefs_loadConst_bool_true, lastUsesUpdate_empty]

/-- `collectConstInts` on `[unaryBinding, capBinding]` is `[]`. -/
private theorem collectConstInts_singletonUnaryNegateWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

/-- The four flag-free side conditions on a `singletonUnaryNegateWithCap` body. -/
private theorem bindingsUseCheckPreimage_singletonUnaryNegateWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage
        [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

private theorem bindingsUseCodePart_singletonUnaryNegateWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart
        [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

private theorem bindingsUseDeserializeState_singletonUnaryNegateWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState
        [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

private theorem bodyEndsInAssert_singletonUnaryNegateWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert
        [⟨bn, .unaryOp "-" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  rfl

/-! ### Lowering of `singletonUnaryNegateWithCap`: `[OP_NEGATE, push true]` -/

set_option maxHeartbeats 1600000 in
private theorem lowerMethodUserRawOps_singletonUnaryNegateWithCap
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (n bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonUnaryNegateWithCap m n bn bcap tail rt src srcCap) :
    lowerMethodUserRawOps progMethods props m
      = [.opcode "OP_NEGATE", .push (.bool true)] := by
  obtain ⟨hBody, hRev, _, _⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonUnaryNegateWithCap bn bcap n rt src srcCap]
  rw [collectConstInts_singletonUnaryNegateWithCap bn bcap n rt src srcCap]
  -- Depth-0 lookup of n in the param stack map is some 0.
  have hFind : (n :: tail).findIdx? (· == n) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  -- Step 1: unfold lowerBindingsP cons on the unary head.
  unfold Stack.Lower.lowerBindingsP
  -- Step 2: reduce lowerValueP for the .unaryOp head using consume-mode at depth 0.
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
  rw [listContains_nil_local n, isLastUse_singleton n]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.StackMap.depth?
  rw [hFind]
  simp only [if_true]
  -- After depth-0 consume reduction, head emits ([], n :: tail). The unary
  -- binding's ops become [] ++ [.opcode "OP_NEGATE"] = [.opcode "OP_NEGATE"].
  unfold Stack.Lower.StackMap.popN
  -- Continue with the cap binding.
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  -- Tail of lowerBindingsP on [] is empty.
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push,
        Stack.Lower.unaryOpcode]

/-! ### Runtime success for `[OP_NEGATE, push true]` -/

/-- Under `agreesTagged + lookup = some (.vBigint i)`,
`runOps [.opcode "OP_NEGATE", .push (.bool true)] initialStack` succeeds. -/
private theorem runOps_negate_pushTrue_of_agreesTagged
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (i : Int)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBigint i)) :
    (Stack.Eval.runOps [.opcode "OP_NEGATE", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_vBigint_of_agreesTagged n tsm_rest anfSt initialStack i
      hAgrees hLookup
  have hNeg :
      Stack.Eval.runOpcode "OP_NEGATE" initialStack
        = .ok ({ initialStack with stack := rest }.push (.vBigint (-i))) :=
    Stack.Sim.runOpcode_NEGATE_int initialStack i rest hStk
  show (Stack.Eval.runOps (.opcode "OP_NEGATE" :: .push (.bool true) :: []) initialStack).toOption.isSome
  unfold Stack.Eval.runOps
  rw [Stack.Eval.stepNonIf_opcode, hNeg]
  -- Tail = runOps [.push (.bool true)] _, always succeeds.
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrapper for `singletonUnaryNegateWithCap` -/

/-- **Method-level runtime-success wrapper for the singleton-unary-negate-
with-cap Tier-2 sub-fragment.**

A real-arith body (unaryOp at depth 0) whose runtime success is proved
structurally — no `hRunOk` / `hSimulates`. -/
theorem runMethod_lower_public_unique_no_post_singletonUnaryNegate_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (i : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonUnaryNegateWithCap m n bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBigint i))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .unaryOp "-" n rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonUnaryNegateWithCap bn bcap n rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonUnaryNegateWithCap bn bcap n rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonUnaryNegateWithCap bn bcap n rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonUnaryNegateWithCap bn bcap n rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [lowerMethodUserRawOps_singletonUnaryNegateWithCap
        methods props m n bn bcap tail rt src srcCap hCap]
  exact runOps_negate_pushTrue_of_agreesTagged n tsm_rest anfSt initialStack i
    hAgrees hLookup

/-! ### `singletonUnaryNotWithCap` — body shape `!x; true` at depth 0 -/

/-- Composite body shape for a single `unaryOp "!" n rt` binding at depth 0
followed by the sentinel-true cap. -/
def singletonUnaryNotWithCap (m : ANFMethod)
    (n bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n :: tail ∧
  bn ≠ bcap ∧ bcap ≠ n

private theorem computeLastUses_singletonUnaryNotWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [(n, 0)] := by
  unfold Stack.Lower.computeLastUses
  have hRefsUnary : Stack.Lower.collectRefs (.unaryOp "!" n rt) = [n] := by
    unfold Stack.Lower.collectRefs
    rfl
  simp [Stack.Lower.computeLastUses.go, hRefsUnary,
        collectRefs_loadConst_bool_true, lastUsesUpdate_empty]

private theorem collectConstInts_singletonUnaryNotWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

private theorem bindingsUseCheckPreimage_singletonUnaryNotWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage
        [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

private theorem bindingsUseCodePart_singletonUnaryNotWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart
        [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

private theorem bindingsUseDeserializeState_singletonUnaryNotWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState
        [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

private theorem bodyEndsInAssert_singletonUnaryNotWithCap
    (bn bcap n : String) (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert
        [⟨bn, .unaryOp "!" n rt, src⟩, ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  rfl

set_option maxHeartbeats 1600000 in
private theorem lowerMethodUserRawOps_singletonUnaryNotWithCap
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (n bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonUnaryNotWithCap m n bn bcap tail rt src srcCap) :
    lowerMethodUserRawOps progMethods props m
      = [.opcode "OP_NOT", .push (.bool true)] := by
  obtain ⟨hBody, hRev, _, _⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonUnaryNotWithCap bn bcap n rt src srcCap]
  rw [collectConstInts_singletonUnaryNotWithCap bn bcap n rt src srcCap]
  have hFind : (n :: tail).findIdx? (· == n) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
  rw [listContains_nil_local n, isLastUse_singleton n]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.StackMap.depth?
  rw [hFind]
  simp only [if_true]
  unfold Stack.Lower.StackMap.popN
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push,
        Stack.Lower.unaryOpcode]

/-- Under `agreesTagged + lookup = some (.vBool b)`,
`runOps [.opcode "OP_NOT", .push (.bool true)] initialStack` succeeds. -/
private theorem runOps_not_pushTrue_of_agreesTagged
    (n : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (b : Bool)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool b)) :
    (Stack.Eval.runOps [.opcode "OP_NOT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_vBool_of_agreesTagged n tsm_rest anfSt initialStack b
      hAgrees hLookup
  have hNot :
      Stack.Eval.runOpcode "OP_NOT" initialStack
        = .ok ({ initialStack with stack := rest }.push (.vBool (!b))) :=
    Stack.Sim.runOpcode_NOT_bool initialStack b rest hStk
  show (Stack.Eval.runOps (.opcode "OP_NOT" :: .push (.bool true) :: []) initialStack).toOption.isSome
  unfold Stack.Eval.runOps
  rw [Stack.Eval.stepNonIf_opcode, hNot]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- **Method-level runtime-success wrapper for the singleton-unary-not-with-cap
Tier-2 sub-fragment.** -/
theorem runMethod_lower_public_unique_no_post_singletonUnaryNot_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (b : Bool)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonUnaryNotWithCap m n bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged ((n, .param) :: tsm_rest) anfSt initialStack)
    (hLookup : anfSt.lookupParam n = some (.vBool b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .unaryOp "!" n rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonUnaryNotWithCap bn bcap n rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonUnaryNotWithCap bn bcap n rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonUnaryNotWithCap bn bcap n rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonUnaryNotWithCap bn bcap n rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [lowerMethodUserRawOps_singletonUnaryNotWithCap
        methods props m n bn bcap tail rt src srcCap hCap]
  exact runOps_not_pushTrue_of_agreesTagged n tsm_rest anfSt initialStack b
    hAgrees hLookup

/-! ## A3 — Tier-2 wave 3: singleton `binOp` at depth pair (1, 0) with sentinel cap

This block widens the Tier-2 unary wrappers to cover singleton `binOp`
bindings at the depth pair `(1, 0)`: the bottom operand at depth 1, the
top operand at depth 0. Both operands are at last-use, so consume-mode
fires for both; the program-aware lowerer emits
`[.swap, .swap, .opcode (binopOpcode op rt)]` as the head binding's ops,
followed by the cap binding's `[.push (.bool true)]`.

Runtime success of the two-swap composition is delivered by the wave-3
substrate `Stack.Agrees.stageC_simpleStep_binOp_d1d0_consume_core`
(in `Stack/Agrees.lean`), which takes `hAgrees + hOpcode` and proves the
3-op sequence post-state directly. We rebuild `hOpcode` from the
input-side `lookupAnfByKind` lookups for the two operands, then chain
the result with the cap binding's unconditional push.

### Body shape

`singletonBinOpWithCap m opName n1 n2 bn bcap tail rt src srcCap` means:

* `m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
             ⟨bcap, .loadConst (.bool true), srcCap⟩]` — a binOp followed
   by the sentinel-true cap (keeping `bodyEndsInAssert = false`).
* `(m.params.map (·.name)).reverse = n2 :: n1 :: tail` — `n2` is on top
  of the runtime stack at depth 0, `n1` sits at depth 1.
* Distinct names: `n1 ≠ n2`, `bn ≠ bcap`, `bcap ≠ n1`, `bcap ≠ n2`.

The `opName` parameter is generic; each integer-arithmetic kind below
(`+`, `-`, `*`) instantiates it via a tier-local body-shape predicate
and discharges runtime success against the matching `runOpcode_*_intInt`
simulation lemma. -/

/-! ### Generic body shape and shared lowering reductions -/

/-- Generic composite body shape for a single `binOp opName n1 n2 rt`
binding at depth pair (1, 0) followed by the sentinel-true cap. The
`opName` parameter is the surface arithmetic operator (`"+"`, `"-"`,
`"*"`, …) that the lowerer translates via `binopOpcode`. -/
def singletonBinOpWithCap (m : ANFMethod)
    (opName : String) (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
            ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n2 :: n1 :: tail ∧
  n1 ≠ n2 ∧ bn ≠ bcap ∧ bcap ≠ n1 ∧ bcap ≠ n2

/-- `collectRefs (.binOp opName n1 n2 rt) = [n1, n2]`. -/
private theorem collectRefs_binOp (opName n1 n2 : String) (rt : Option String) :
    Stack.Lower.collectRefs (.binOp opName n1 n2 rt) = [n1, n2] := by
  unfold Stack.Lower.collectRefs
  rfl

/-- `lastUsesUpdate (lastUsesUpdate [] n1 0) n2 0 = [(n2, 0), (n1, 0)]`
when `n1 ≠ n2`. -/
private theorem lastUsesUpdate_two_distinct
    (n1 n2 : String) (hne : n1 ≠ n2) :
    Stack.Lower.lastUsesUpdate (Stack.Lower.lastUsesUpdate [] n1 0) n2 0
      = [(n2, 0), (n1, 0)] := by
  unfold Stack.Lower.lastUsesUpdate
  -- First: lastUsesUpdate [] n1 0 = [(n1, 0)] (filtered list is empty).
  -- Second: prepend (n2, 0) to filter [(n1, 0)] keeping entries where
  -- p.1 != n2; (n1, 0)'s first component is n1 ≠ n2, so the filter keeps it.
  have hbne : (n1 != n2) = true := by
    simp [bne_iff_ne, hne]
  simp [List.filter, hbne]

/-- `computeLastUses` on `[binOpBinding, capBinding]` records
`[(n2, 0), (n1, 0)]` when `n1 ≠ n2`. -/
private theorem computeLastUses_singletonBinOpWithCap
    (opName : String) (bn bcap n1 n2 : String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hne : n1 ≠ n2) :
    Stack.Lower.computeLastUses
        [⟨bn, .binOp opName n1 n2 rt, src⟩,
         ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [(n2, 0), (n1, 0)] := by
  unfold Stack.Lower.computeLastUses
  -- collectRefs of .binOp returns [n1, n2]; collectRefs of loadConst is [].
  -- foldl over [n1, n2] from [] gives lastUsesUpdate (lastUsesUpdate [] n1 0) n2 0.
  simp [Stack.Lower.computeLastUses.go, collectRefs_binOp opName n1 n2 rt,
        collectRefs_loadConst_bool_true,
        lastUsesUpdate_two_distinct n1 n2 hne]

/-- `collectConstInts` on `[binOpBinding, capBinding]` is `[]` (no
`.loadConst (.int _)` bindings). -/
private theorem collectConstInts_singletonBinOpWithCap
    (opName : String) (bn bcap n1 n2 : String)
    (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨bn, .binOp opName n1 n2 rt, src⟩,
         ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

/-- The four flag-free side conditions on a `singletonBinOpWithCap` body. -/
private theorem bindingsUseCheckPreimage_singletonBinOpWithCap
    (opName : String) (bn bcap n1 n2 : String)
    (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage
        [⟨bn, .binOp opName n1 n2 rt, src⟩,
         ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

private theorem bindingsUseCodePart_singletonBinOpWithCap
    (opName : String) (bn bcap n1 n2 : String)
    (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart
        [⟨bn, .binOp opName n1 n2 rt, src⟩,
         ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

private theorem bindingsUseDeserializeState_singletonBinOpWithCap
    (opName : String) (bn bcap n1 n2 : String)
    (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState
        [⟨bn, .binOp opName n1 n2 rt, src⟩,
         ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

private theorem bodyEndsInAssert_singletonBinOpWithCap
    (opName : String) (bn bcap n1 n2 : String)
    (rt : Option String) (src srcCap : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert
        [⟨bn, .binOp opName n1 n2 rt, src⟩,
         ⟨bcap, .loadConst (.bool true), srcCap⟩]
      = false := by
  rfl

/-! ### `lastUsesLookup` / `isLastUse` reductions on `[(n2, 0), (n1, 0)]` -/

/-- `lastUsesLookup [(n2, 0), (n1, 0)] n1 = some 0` when `n1 ≠ n2`. -/
private theorem lastUsesLookup_two_first
    (n1 n2 : String) (hne : n1 ≠ n2) :
    Stack.Lower.lastUsesLookup [(n2, 0), (n1, 0)] n1 = some 0 := by
  unfold Stack.Lower.lastUsesLookup
  have hne2 : (n2 == n1) = false := by
    have : n2 ≠ n1 := fun h => hne h.symm
    simp [this]
  simp [hne2]

/-- `lastUsesLookup [(n2, 0), (n1, 0)] n2 = some 0`. -/
private theorem lastUsesLookup_two_second
    (n2 _n1 : String) :
    Stack.Lower.lastUsesLookup [(n2, 0), (_n1, 0)] n2 = some 0 := by
  unfold Stack.Lower.lastUsesLookup
  simp

/-- `isLastUse [(n2, 0), (n1, 0)] n1 0 = true`. -/
private theorem isLastUse_two_first
    (n1 n2 : String) (hne : n1 ≠ n2) :
    Stack.Lower.isLastUse [(n2, 0), (n1, 0)] n1 0 = true := by
  unfold Stack.Lower.isLastUse
  rw [lastUsesLookup_two_first n1 n2 hne]
  simp

/-- `isLastUse [(n2, 0), (n1, 0)] n2 0 = true`. -/
private theorem isLastUse_two_second
    (n1 n2 : String) :
    Stack.Lower.isLastUse [(n2, 0), (n1, 0)] n2 0 = true := by
  unfold Stack.Lower.isLastUse
  rw [lastUsesLookup_two_second n2 n1]
  simp

/-! ### Lowering of `singletonBinOpWithCap`:
   `[.swap, .swap, .opcode (binopOpcode opName rt), .push (.bool true)]`

For `opName ∈ {"+", "-", "*", "/", "%"}` and any `rt`, the
`binopOpcode opName rt` reduction is closed (the `!==` rebound only
fires on `opName = "!=="`). The wrapper below leaves the opcode in
`binopOpcode` form; per-kind callers rewrite it to `OP_ADD`/`OP_SUB`/
`OP_MUL`/etc. with a `decide`/`rfl` step.

Note: the body-shape predicate excludes `n1 = n2` (otherwise the depth
lookups would collide); the `n1 ≠ n2` hypothesis is part of `hCap`. -/

set_option maxHeartbeats 4000000 in
set_option linter.unusedSimpArgs false in
private theorem lowerMethodUserRawOps_singletonBinOpWithCap
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (opName : String)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonBinOpWithCap m opName n1 n2 bn bcap tail rt src srcCap)
    (hNotNeqBytes : (opName == "!==" && rt == some "bytes") = false) :
    lowerMethodUserRawOps progMethods props m
      = [.swap, .swap, .opcode (Stack.Lower.binopOpcode opName rt),
         .push (.bool true)] := by
  obtain ⟨hBody, hRev, hne, _hBnCap, _hBcapN1, _hBcapN2⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap hne]
  rw [collectConstInts_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap]
  -- Depth-1 lookup of n1 in [n2, n1, ...tail] is some 1.
  have hFind1 : (n2 :: n1 :: tail).findIdx? (· == n1) = some 1 := by
    have hne2 : (n2 == n1) = false := by
      have h : n2 ≠ n1 := fun h => hne h.symm
      simp [beq_iff_eq, h]
    unfold List.findIdx?
    simp [List.findIdx?.go, hne2]
  -- Depth-1 lookup of n2 in [n1, n2, ...tail] (after the first swap) is some 1.
  have hFind2 : (n1 :: n2 :: tail).findIdx? (· == n2) = some 1 := by
    have hne1 : (n1 == n2) = false := by
      have h : n1 ≠ n2 := hne
      simp [beq_iff_eq, h]
    unfold List.findIdx?
    simp [List.findIdx?.go, hne1]
  -- Build a `loadRefLive`-result lemma for n1 at depth 1, consume-mode.
  have hLoadN1 :
      Stack.Lower.loadRefLive (n2 :: n1 :: tail) n1 0 [(n2, 0), (n1, 0)] []
        = ([.swap], n1 :: n2 :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n1, isLastUse_two_first n1 n2 hne]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind1]
    simp
  -- Same for n2 at depth 1 of the swapped sm.
  have hLoadN2 :
      Stack.Lower.loadRefLive (n1 :: n2 :: tail) n2 0 [(n2, 0), (n1, 0)] []
        = ([.swap], n2 :: n1 :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n2, isLastUse_two_second n1 n2]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind2]
    simp
  -- Step 1: unfold lowerBindingsP cons on the binOp head.
  unfold Stack.Lower.lowerBindingsP
  -- Step 2: reduce the binOp arm of lowerValueP. Use the two precomputed
  -- loadRefLive equalities to discharge both operand loads in one go.
  unfold Stack.Lower.lowerValueP
  rw [hLoadN1]
  simp only [hLoadN2]
  -- Discharge the `op == "!==" && rt == some "bytes"` guard.
  rw [hNotNeqBytes]
  -- After `rw [hNotNeqBytes]`, the if-guard is `false = true`. Reduce.
  simp only [Bool.false_eq_true, if_false, reduceIte]
  unfold Stack.Lower.StackMap.popN
  -- Continue with the cap binding.
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  -- Tail of lowerBindingsP on [] reduces to ([], _).
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### Two-value top-of-stack extraction

For binOp at depth pair (1, 0) we need both operand values as `.vBigint`
on top of the runtime stack. The lookups `(n1, .param) ↦ some (.vBigint a)`
and `(n2, .param) ↦ some (.vBigint b)` plus `agreesTagged` over the
prefix `[(n2, .param), (n1, .param)]` give us the two-value shape
`.vBigint b :: .vBigint a :: rest`. -/

private theorem initialStack_top_two_vBigint_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ rest, initialStack.stack = .vBigint b :: .vBigint a :: rest := by
  have hAlign :
      taggedStackAligned ((n2, .param) :: (n1, .param) :: tsm_rest)
                         anfSt initialStack.stack := hAgrees.1
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | [_] =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      simp [taggedStackAligned] at hTail
  | topV :: midV :: rest =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨hHeadTop, hRestAlign⟩ := hAlign
      unfold taggedStackAligned at hRestAlign
      obtain ⟨hHeadMid, _⟩ := hRestAlign
      have hHeadTop' : anfSt.lookupParam n2 = some topV := hHeadTop
      have hHeadMid' : anfSt.lookupParam n1 = some midV := hHeadMid
      have hTopEq : topV = .vBigint b := by
        have hCombined : some topV = some (.vBigint b) := hHeadTop'.symm.trans hLookupR
        exact Option.some.inj hCombined
      have hMidEq : midV = .vBigint a := by
        have hCombined : some midV = some (.vBigint a) := hHeadMid'.symm.trans hLookupL
        exact Option.some.inj hCombined
      exact ⟨rest, by rw [hTopEq, hMidEq]⟩

/-! ### Per-kind method-level wrappers

Each per-kind wrapper instantiates `singletonBinOpWithCap` with a
specific `opName`, derives `hOpcode` for the matching `runOpcode_*_intInt`
simulation lemma, and composes against
`stageC_simpleStep_binOp_d1d0_consume_core` to discharge the runtime
success of `[.swap, .swap, .opcode]`. The cap binding's `.push` succeeds
unconditionally; the four-op sequence's success follows by
`runOps_append`. -/

/-- Singleton `+` body shape (alias of `singletonBinOpWithCap` with
`opName := "+"`). -/
def singletonBinAddWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "+" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `-` body shape. -/
def singletonBinSubWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "-" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `*` body shape. -/
def singletonBinMulWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "*" n1 n2 bn bcap tail rt src srcCap

/-! ### Runtime success for the four-op sequences

For each integer-arithmetic opcode `O ∈ {OP_ADD, OP_SUB, OP_MUL}`, the
sequence `[.swap, .swap, .opcode O, .push (.bool true)]` succeeds on a
stack whose top two values are `.vBigint b :: .vBigint a :: rest`.

The wave-3 substrate handles the `[.swap, .swap, .opcode]` prefix; the
trailing `.push` succeeds unconditionally on any stack via `runOps`'s
push semantics. -/

/-- Runtime success of `[.swap, .swap, .opcode "OP_ADD", .push (.bool true)]`
under `agreesTagged + two-int lookups`. -/
private theorem runOps_swap_swap_add_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_ADD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  -- Build hOpcode for OP_ADD from the stack shape.
  have hAdd :
      Stack.Eval.runOpcode "OP_ADD" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBigint (a + b))) :=
    Stack.Sim.runOpcode_ADD_intInt initialStack a b rest hStk
  -- Rewrite `{... with stack := rest}` as `{... with stack := initialStack.stack.tail.tail}`.
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hAdd' :
      Stack.Eval.runOpcode "OP_ADD" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a + b))) := by
    rw [hAdd, hTailTail]
  -- Apply the wave-3 substrate.
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_ADD"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a + b))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_ADD" (.vBigint (a + b))
      [.swap, .swap, .opcode "OP_ADD"]
      hAgrees hLookupL hLookupR rfl hAdd'
  -- Append the unconditional `.push`.
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_ADD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_SUB", .push (.bool true)]`
under `agreesTagged + two-int lookups`. -/
private theorem runOps_swap_swap_sub_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_SUB", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hSub :
      Stack.Eval.runOpcode "OP_SUB" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBigint (a - b))) :=
    Stack.Sim.runOpcode_SUB_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hSub' :
      Stack.Eval.runOpcode "OP_SUB" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a - b))) := by
    rw [hSub, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_SUB"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a - b))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_SUB" (.vBigint (a - b))
      [.swap, .swap, .opcode "OP_SUB"]
      hAgrees hLookupL hLookupR rfl hSub'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_SUB"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_MUL", .push (.bool true)]`
under `agreesTagged + two-int lookups`. -/
private theorem runOps_swap_swap_mul_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_MUL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hMul :
      Stack.Eval.runOpcode "OP_MUL" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBigint (a * b))) :=
    Stack.Sim.runOpcode_MUL_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hMul' :
      Stack.Eval.runOpcode "OP_MUL" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a * b))) := by
    rw [hMul, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_MUL"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a * b))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_MUL" (.vBigint (a * b))
      [.swap, .swap, .opcode "OP_MUL"]
      hAgrees hLookupL hLookupR rfl hMul'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_MUL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrappers for `+`, `-`, `*` at depth pair (1, 0) -/

/-- **Method-level runtime-success wrapper for `singletonBinAddWithCap`.**

Real-arith body (binOp `+` at depth pair (1, 0)) whose runtime success is
proved structurally — no `hRunOk` / `hSimulates`. The two operand lookups
plus `agreesTagged` deliver the runtime stack shape; the wave-3 substrate
discharges the two-swap-plus-opcode prefix; the cap binding's `.push`
succeeds unconditionally. -/
theorem runMethod_lower_public_unique_no_post_singletonBinAdd_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinAddWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "+" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("+" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "+" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  -- `binopOpcode "+" rt = "OP_ADD"` by definitional reduction.
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_ADD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_add_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinSubWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinSub_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinSubWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "-" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("-" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "-" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_SUB", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_sub_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinMulWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMul_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinMulWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "*" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("*" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "*" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_MUL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_mul_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-! ## A3 — Wave 10: widen wave-4 binOp d1d0 consume coverage

Wave-4 (`singletonBin{Add,Sub,Mul}WithCap`) covered the three integer-
arithmetic binops `+`, `-`, `*` at depth pair (1, 0) under consume mode.
This wave extends the same template to every other integer-input binOp
whose `runOpcode_*_intInt` simulation lemma is already available in
`Stack/Sim.lean`:

* Integer-arith with a `nonzero` side condition: `/`, `%`
* Comparators (int → bool result): `<`, `<=`, `>`, `>=`, `===` (int),
  `!==` (int)
* Integer logical: `&&`, `||`
* Integer shifts: `<<`, `>>`

Each wrapper has the same shape as wave-4 — a body-shape alias around
`singletonBinOpWithCap` and a per-kind method-level theorem.

**No new substrate** — every wrapper composes against the existing
`stageC_simpleStep_binOp_d1d0_consume_core` (which is opcode- and
return-type-polymorphic) plus the per-opcode `runOpcode_*_intInt` from
`Stack/Sim.lean`. -/

/-! ### Per-kind body shape aliases for the new opcodes -/

/-- Singleton `/` body shape. -/
def singletonBinDivWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "/" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `%` body shape. -/
def singletonBinModWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "%" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `<` body shape. -/
def singletonBinLtWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "<" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `<=` body shape. -/
def singletonBinLeWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "<=" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `>` body shape. -/
def singletonBinGtWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m ">" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `>=` body shape. -/
def singletonBinGeWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m ">=" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `===` body shape — integer return type (rt ≠ some "bytes"). -/
def singletonBinEqWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "===" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `!==` body shape — integer return type (rt ≠ some "bytes"). -/
def singletonBinNeqWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "!==" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `&&` body shape. -/
def singletonBinAndWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "&&" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `||` body shape. -/
def singletonBinOrWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "||" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `<<` body shape. -/
def singletonBinShlWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m "<<" n1 n2 bn bcap tail rt src srcCap

/-- Singleton `>>` body shape. -/
def singletonBinShrWithCap (m : ANFMethod)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  singletonBinOpWithCap m ">>" n1 n2 bn bcap tail rt src srcCap

/-! ### Per-kind 4-op runtime-success helpers

Each helper mirrors `runOps_swap_swap_{add,sub,mul}_pushTrue_of_agreesTagged`
above — extract the two-int stack shape, build `hOpcode` via the
matching `runOpcode_*_intInt` simulation lemma, apply the wave-3
substrate, then append the unconditional `.push (.bool true)`. -/

/-- Runtime success of `[.swap, .swap, .opcode "OP_DIV", .push (.bool true)]`
under `agreesTagged + two-int lookups + b ≠ 0`. -/
private theorem runOps_swap_swap_div_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_DIV", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hDiv :
      Stack.Eval.runOpcode "OP_DIV" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBigint (a / b))) :=
    Stack.Sim.runOpcode_DIV_intInt_nonzero initialStack a b rest hStk hNonzero
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hDiv' :
      Stack.Eval.runOpcode "OP_DIV" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a / b))) := by
    rw [hDiv, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_DIV"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a / b))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_DIV" (.vBigint (a / b))
      [.swap, .swap, .opcode "OP_DIV"]
      hAgrees hLookupL hLookupR rfl hDiv'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_DIV"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_MOD", .push (.bool true)]`
under `agreesTagged + two-int lookups + b ≠ 0`. -/
private theorem runOps_swap_swap_mod_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_MOD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hMod :
      Stack.Eval.runOpcode "OP_MOD" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBigint (a % b))) :=
    Stack.Sim.runOpcode_MOD_intInt_nonzero initialStack a b rest hStk hNonzero
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hMod' :
      Stack.Eval.runOpcode "OP_MOD" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a % b))) := by
    rw [hMod, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_MOD"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a % b))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_MOD" (.vBigint (a % b))
      [.swap, .swap, .opcode "OP_MOD"]
      hAgrees hLookupL hLookupR rfl hMod'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_MOD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]`. -/
private theorem runOps_swap_swap_lt_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hLt :
      Stack.Eval.runOpcode "OP_LESSTHAN" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBool (decide (a < b)))) :=
    Stack.Sim.runOpcode_LESSTHAN_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hLt' :
      Stack.Eval.runOpcode "OP_LESSTHAN" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a < b)))) := by
    rw [hLt, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_LESSTHAN"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a < b)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_LESSTHAN" (.vBool (decide (a < b)))
      [.swap, .swap, .opcode "OP_LESSTHAN"]
      hAgrees hLookupL hLookupR rfl hLt'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_LESSTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_swap_le_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hLe :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBool (decide (a ≤ b)))) :=
    Stack.Sim.runOpcode_LESSTHANOREQUAL_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hLe' :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≤ b)))) := by
    rw [hLe, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_LESSTHANOREQUAL"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≤ b)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_LESSTHANOREQUAL" (.vBool (decide (a ≤ b)))
      [.swap, .swap, .opcode "OP_LESSTHANOREQUAL"]
      hAgrees hLookupL hLookupR rfl hLe'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_LESSTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]`. -/
private theorem runOps_swap_swap_gt_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hGt :
      Stack.Eval.runOpcode "OP_GREATERTHAN" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBool (decide (a > b)))) :=
    Stack.Sim.runOpcode_GREATERTHAN_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hGt' :
      Stack.Eval.runOpcode "OP_GREATERTHAN" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a > b)))) := by
    rw [hGt, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_GREATERTHAN"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a > b)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_GREATERTHAN" (.vBool (decide (a > b)))
      [.swap, .swap, .opcode "OP_GREATERTHAN"]
      hAgrees hLookupL hLookupR rfl hGt'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_GREATERTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_swap_ge_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hGe :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBool (decide (a ≥ b)))) :=
    Stack.Sim.runOpcode_GREATERTHANOREQUAL_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hGe' :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≥ b)))) := by
    rw [hGe, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_GREATERTHANOREQUAL"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≥ b)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_GREATERTHANOREQUAL" (.vBool (decide (a ≥ b)))
      [.swap, .swap, .opcode "OP_GREATERTHANOREQUAL"]
      hAgrees hLookupL hLookupR rfl hGe'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_GREATERTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_swap_eq_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hEq :
      Stack.Eval.runOpcode "OP_NUMEQUAL" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBool (decide (a = b)))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hEq' :
      Stack.Eval.runOpcode "OP_NUMEQUAL" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a = b)))) := by
    rw [hEq, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_NUMEQUAL"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a = b)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_NUMEQUAL" (.vBool (decide (a = b)))
      [.swap, .swap, .opcode "OP_NUMEQUAL"]
      hAgrees hLookupL hLookupR rfl hEq'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_NUMEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_swap_neq_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hNeq :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" initialStack
        = .ok ({initialStack with stack := rest}.push (.vBool (decide (a ≠ b)))) :=
    Stack.Sim.runOpcode_NUMNOTEQUAL_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hNeq' :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≠ b)))) := by
    rw [hNeq, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_NUMNOTEQUAL"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≠ b)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_NUMNOTEQUAL" (.vBool (decide (a ≠ b)))
      [.swap, .swap, .opcode "OP_NUMNOTEQUAL"]
      hAgrees hLookupL hLookupR rfl hNeq'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_NUMNOTEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_BOOLAND", .push (.bool true)]`. -/
private theorem runOps_swap_swap_booland_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_BOOLAND", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hAnd :
      Stack.Eval.runOpcode "OP_BOOLAND" initialStack
        = .ok ({initialStack with stack := rest}.push
                 (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLAND_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hAnd' :
      Stack.Eval.runOpcode "OP_BOOLAND" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) := by
    rw [hAnd, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_BOOLAND"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_BOOLAND" (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))
      [.swap, .swap, .opcode "OP_BOOLAND"]
      hAgrees hLookupL hLookupR rfl hAnd'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_BOOLAND"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_BOOLOR", .push (.bool true)]`. -/
private theorem runOps_swap_swap_boolor_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_BOOLOR", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hOr :
      Stack.Eval.runOpcode "OP_BOOLOR" initialStack
        = .ok ({initialStack with stack := rest}.push
                 (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLOR_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hOr' :
      Stack.Eval.runOpcode "OP_BOOLOR" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) := by
    rw [hOr, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_BOOLOR"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_BOOLOR" (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))
      [.swap, .swap, .opcode "OP_BOOLOR"]
      hAgrees hLookupL hLookupR rfl hOr'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_BOOLOR"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_LSHIFT", .push (.bool true)]`. -/
private theorem runOps_swap_swap_shl_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_LSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hShl :
      Stack.Eval.runOpcode "OP_LSHIFT" initialStack
        = .ok ({initialStack with stack := rest}.push
                 (.vBigint (a * (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_LSHIFT_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hShl' :
      Stack.Eval.runOpcode "OP_LSHIFT" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a * (2 ^ b.toNat)))) := by
    rw [hShl, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_LSHIFT"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a * (2 ^ b.toNat)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_LSHIFT" (.vBigint (a * (2 ^ b.toNat)))
      [.swap, .swap, .opcode "OP_LSHIFT"]
      hAgrees hLookupL hLookupR rfl hShl'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_LSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .swap, .opcode "OP_RSHIFT", .push (.bool true)]`. -/
private theorem runOps_swap_swap_shr_pushTrue_of_agreesTagged
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .swap, .opcode "OP_RSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  have hShr :
      Stack.Eval.runOpcode "OP_RSHIFT" initialStack
        = .ok ({initialStack with stack := rest}.push
                 (.vBigint (a / (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_RSHIFT_intInt initialStack a b rest hStk
  have hTailTail : initialStack.stack.tail.tail = rest := by
    rw [hStk]; rfl
  have hShr' :
      Stack.Eval.runOpcode "OP_RSHIFT" initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a / (2 ^ b.toNat)))) := by
    rw [hShr, hTailTail]
  have hSubstrate :
      Stack.Eval.runOps [.swap, .swap, .opcode "OP_RSHIFT"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push
                 (.vBigint (a / (2 ^ b.toNat)))) :=
    stageC_simpleStep_binOp_d1d0_consume_core
      n2 n1 .param .param tsm_rest anfSt initialStack a b
      "OP_RSHIFT" (.vBigint (a / (2 ^ b.toNat)))
      [.swap, .swap, .opcode "OP_RSHIFT"]
      hAgrees hLookupL hLookupR rfl hShr'
  show (Stack.Eval.runOps
          ([.swap, .swap, .opcode "OP_RSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hSubstrate]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrappers for the additional integer binops at d1d0 consume

Each wrapper mirrors `runMethod_lower_public_unique_no_post_singletonBinAdd_isSome`
exactly. The `hNotNeqBytes` discriminant fires only when both `opName = "!=="`
and `rt = some "bytes"`; for `"==="` integer (rt ≠ some "bytes") we discharge
a separate `binopOpcode` reduction. -/

/-- **Method-level runtime-success wrapper for `singletonBinDivWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinDiv_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinDivWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "/" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("/" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "/" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_DIV", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_div_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `singletonBinModWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMod_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinModWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "%" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("%" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "%" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_MOD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_mod_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `singletonBinLtWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLt_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinLtWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "<" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_lt_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinLeWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLe_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinLeWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "<=" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_le_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinGtWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGt_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinGtWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m ">" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_gt_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinGeWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGe_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinGeWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m ">=" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_ge_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinEqWithCap`.**

Requires `rt ≠ some "bytes"` so the lowerer's `===` branch picks
`OP_NUMEQUAL`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinEq_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinEqWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "===" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("===" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "===" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  -- Reduce `binopOpcode "===" rt` to "OP_NUMEQUAL" using hRtNotBytes.
  have hOpcode : Stack.Lower.binopOpcode "===" rt = "OP_NUMEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_eq_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinNeqWithCap`.**

Requires `rt ≠ some "bytes"` so the lowerer's `!==` branch picks
`OP_NUMNOTEQUAL` (without the trailing `OP_NOT` peephole). -/
theorem runMethod_lower_public_unique_no_post_singletonBinNeq_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinNeqWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "!==" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- For "!==" with rt ≠ some "bytes" the `!== && rt == some "bytes"`
  -- guard is `true && false = false`.
  have hNotNeqBytes : (("!==" == "!==") && rt == some "bytes") = false := by
    have hRt : (rt == some "bytes") = false := by
      cases hRt' : rt with
      | none => rfl
      | some s =>
          by_cases hBytes : s = "bytes"
          · exact absurd (by rw [hRt', hBytes]) hRtNotBytes
          · simp [hBytes]
    simp [hRt]
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "!==" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  -- Reduce `binopOpcode "!==" rt` to "OP_NUMNOTEQUAL" using hRtNotBytes.
  have hOpcode : Stack.Lower.binopOpcode "!==" rt = "OP_NUMNOTEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_neq_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinAndWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAnd_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinAndWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "&&" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("&&" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "&&" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_BOOLAND", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_booland_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinOrWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinOr_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOrWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "||" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("||" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "||" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_BOOLOR", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_boolor_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinShlWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShl_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinShlWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m "<<" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_LSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_shl_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `singletonBinShrWithCap`.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShr_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinShrWithCap m n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">>" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">>" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap
        methods props m ">>" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .swap, .opcode "OP_RSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_swap_shr_pushTrue_of_agreesTagged n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-! ## Wave 12 — A3 binOp wrappers at depth pair (0, 1) consume mode

Wave 10 landed 15 method-level wrappers (Add/Sub/Mul/Div/Mod/Lt/Le/Gt/Ge/Eq/
Neq/And/Or/Shl/Shr) at depth pair (1, 0): params reversed `n2 :: n1 :: tail`,
lowerer emits `[.swap, .swap, .opcode opcode, .push (.bool true)]`.

This wave covers the mirror depth pair (0, 1): params reversed
`n1 :: n2 :: tail` (left at depth 0, right at depth 1), lowerer emits
`[.swap, .opcode opcode, .push (.bool true)]`. The single swap brings the right
operand to the top, after which the opcode sees `b=n2V` on top and `a=n1V` at
depth 1 — exactly the operand ordering `runOpcode_*_intInt` expects.

### History — wave-11 substrate defects, resolved in wave-11b/12/13

The original wave-11 substrates `stageC_simpleStep_binOp_d0d1_consume_core`,
`stageC_simpleStep_binOp_dge2_d0_consume_core`, and
`stageC_simpleStep_binOp_d0_dge2_consume_core` shipped with signature defects:

* `d0d1`: `hOpcode` was universally quantified over `stkPost` constrained only
  by metadata-equality and `stkPost.stack.tail.tail = stkSt.stack.tail.tail`,
  leaving the top two values of `stkPost.stack` arbitrary. For real opcodes
  the substrate's conclusion was then unprovable by any honest caller.

* `dge2_d0` and `d0_dge2`: the substrate's claimed post-state used a net `-2`
  element delta (`(eraseIdx d).tail.tail.push out`), whereas the actual
  runtime of `[.rot, .swap, .opcode]` (dge2_d0, d=2) / `[.rot, .opcode]`
  (d0_dge2, d=2) is a net `-1` delta — the stepped-over depth-1 element is
  preserved at runtime but was erased by the post-state.

These have since been fixed. Wave-12's `d0d1` wrappers (below) bypass the
`d0d1` substrate and prove runtime success directly via `runOps_append` +
`runOpcode_*_intInt`. Wave-11b corrected the `dge2_d0` / `d0_dge2` substrates
to the net `-1` post-state `(eraseIdx d).tail.push out` and added smoke tests
demonstrating consumability at d=2; wave-13 (end of this file) lands the
30 `dge2_d0` / `d0_dge2` binop wrappers (15 binops × 2 depth pairs) on top of
those corrected substrates, via per-pair lowerer reductions
(`lowerMethodUserRawOps_singletonBinOpWithCap_{dge2_d0,d0_dge2}`) plus direct
`[.rot(, .swap)]`-post-load runtime helpers. The wave-13 wrappers cover the
`d = 2` (`.rot`) instances; the `d ≥ 3` (`.roll d`) instances remain pending
the generic-`d` lowerer/runtime induction lemmas (see the wave-13 section
header for details).
-/

/-! ### Cap predicate at depth pair (0, 1) -/

/-- Generic composite body shape for a single `binOp opName n1 n2 rt`
binding at depth pair (0, 1) followed by the sentinel-true cap. Differs
from `singletonBinOpWithCap` only in `hRev`: params reversed is
`n1 :: n2 :: tail` rather than `n2 :: n1 :: tail`. -/
def singletonBinOpWithCap_d0d1 (m : ANFMethod)
    (opName : String) (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
            ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n1 :: n2 :: tail ∧
  n1 ≠ n2 ∧ bn ≠ bcap ∧ bcap ≠ n1 ∧ bcap ≠ n2

/-! ### Lowering of `singletonBinOpWithCap_d0d1`:
   `[.swap, .opcode (binopOpcode opName rt), .push (.bool true)]`

Mirrors `lowerMethodUserRawOps_singletonBinOpWithCap`. The body's
`computeLastUses` reduction is unchanged (depends only on body, not on
params); only the two `loadRefLive` reductions differ — the first load
sees `n1` at depth 0 (no-op, sm unchanged) and the second sees `n2`
at depth 1 (swap). -/

set_option maxHeartbeats 4000000 in
set_option linter.unusedSimpArgs false in
private theorem lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (opName : String)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonBinOpWithCap_d0d1 m opName n1 n2 bn bcap tail rt src srcCap)
    (hNotNeqBytes : (opName == "!==" && rt == some "bytes") = false) :
    lowerMethodUserRawOps progMethods props m
      = [.swap, .opcode (Stack.Lower.binopOpcode opName rt),
         .push (.bool true)] := by
  obtain ⟨hBody, hRev, hne, _hBnCap, _hBcapN1, _hBcapN2⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap hne]
  rw [collectConstInts_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap]
  -- Depth-0 lookup of n1 in [n1, n2, ...tail] is some 0.
  have hFind1 : (n1 :: n2 :: tail).findIdx? (· == n1) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  -- Depth-1 lookup of n2 in [n1, n2, ...tail] (sm unchanged after the
  -- depth-0 consume) is some 1.
  have hFind2 : (n1 :: n2 :: tail).findIdx? (· == n2) = some 1 := by
    have hne1 : (n1 == n2) = false := by
      have h : n1 ≠ n2 := hne
      simp [beq_iff_eq, h]
    unfold List.findIdx?
    simp [List.findIdx?.go, hne1]
  -- Load n1 at depth 0, consume — bringToTop returns ([], sm) unchanged.
  have hLoadN1 :
      Stack.Lower.loadRefLive (n1 :: n2 :: tail) n1 0 [(n2, 0), (n1, 0)] []
        = ([], n1 :: n2 :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n1, isLastUse_two_first n1 n2 hne]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind1]
    simp
  -- Load n2 at depth 1 of the unchanged sm, consume — bringToTop emits .swap.
  have hLoadN2 :
      Stack.Lower.loadRefLive (n1 :: n2 :: tail) n2 0 [(n2, 0), (n1, 0)] []
        = ([.swap], n2 :: n1 :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n2, isLastUse_two_second n1 n2]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind2]
    simp
  -- Step 1: unfold lowerBindingsP cons on the binOp head.
  unfold Stack.Lower.lowerBindingsP
  -- Step 2: reduce the binOp arm of lowerValueP. Use the two precomputed
  -- loadRefLive equalities to discharge both operand loads.
  unfold Stack.Lower.lowerValueP
  rw [hLoadN1]
  simp only [hLoadN2]
  -- Discharge the `op == "!==" && rt == some "bytes"` guard.
  rw [hNotNeqBytes]
  -- After `rw [hNotNeqBytes]`, the if-guard is `false = true`. Reduce.
  simp only [Bool.false_eq_true, if_false, reduceIte]
  unfold Stack.Lower.StackMap.popN
  -- Continue with the cap binding.
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  -- Tail of lowerBindingsP on [] reduces to ([], _).
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### Two-value top-of-stack extraction at depth pair (0, 1)

For binOp at depth pair (0, 1) we need both operand values as `.vBigint`
on top of the runtime stack. The lookups `(n1, .param) ↦ some (.vBigint a)`
and `(n2, .param) ↦ some (.vBigint b)` plus `agreesTagged` over the
prefix `[(n1, .param), (n2, .param)]` give us the two-value shape
`.vBigint a :: .vBigint b :: rest`. -/

private theorem initialStack_top_two_vBigint_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ rest, initialStack.stack = .vBigint a :: .vBigint b :: rest := by
  have hAlign :
      taggedStackAligned ((n1, .param) :: (n2, .param) :: tsm_rest)
                         anfSt initialStack.stack := hAgrees.1
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | [_] =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      simp [taggedStackAligned] at hTail
  | topV :: midV :: rest =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨hHeadTop, hRestAlign⟩ := hAlign
      unfold taggedStackAligned at hRestAlign
      obtain ⟨hHeadMid, _⟩ := hRestAlign
      have hHeadTop' : anfSt.lookupParam n1 = some topV := hHeadTop
      have hHeadMid' : anfSt.lookupParam n2 = some midV := hHeadMid
      have hTopEq : topV = .vBigint a := by
        have hCombined : some topV = some (.vBigint a) := hHeadTop'.symm.trans hLookupL
        exact Option.some.inj hCombined
      have hMidEq : midV = .vBigint b := by
        have hCombined : some midV = some (.vBigint b) := hHeadMid'.symm.trans hLookupR
        exact Option.some.inj hCombined
      exact ⟨rest, by rw [hTopEq, hMidEq]⟩

/-! ### Single-swap post-state helper at depth pair (0, 1)

After `.swap` on `initialStack` with stack `.vBigint a :: .vBigint b :: rest`,
the runtime state is `{initialStack with stack := .vBigint b :: .vBigint a :: rest}`.
This is the canonical post-load state for the depth-pair (0, 1) opcode. -/

private theorem runOps_swap_post_state_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ rest,
      initialStack.stack = .vBigint a :: .vBigint b :: rest ∧
      Stack.Eval.runOps [.swap] initialStack
        = .ok ({initialStack with
                 stack := .vBigint b :: .vBigint a :: rest}) := by
  obtain ⟨rest, hStk⟩ :=
    initialStack_top_two_vBigint_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  refine ⟨rest, hStk, ?_⟩
  show Stack.Eval.runOps (.swap :: []) initialStack = _
  unfold Stack.Eval.runOps
  have hStep :
      Stack.Eval.stepNonIf .swap initialStack
        = Stack.Eval.applySwap initialStack := rfl
  rw [hStep]
  unfold Stack.Eval.applySwap
  rw [hStk]
  simp [Stack.Sim.run_empty]

/-! ### Per-kind 3-op runtime-success helpers at depth pair (0, 1)

Each helper mirrors `runOps_swap_swap_<op>_pushTrue_of_agreesTagged` from
the d1d0 wave. The lowered prefix is `[.swap, .opcode, .push true]`
instead of `[.swap, .swap, .opcode, .push true]`; the single swap is *not*
an identity, so we use `runOps_swap_post_state_d0d1` to expose the
post-swap runtime stack `.vBigint b :: .vBigint a :: rest`, then apply
the matching `runOpcode_*_intInt` simulation lemma.

Wave 11's `stageC_simpleStep_binOp_d0d1_consume_core` substrate is NOT
used: its `hOpcode` premise universally quantifies over `stkPost` whose
top two values are unconstrained Value's (only metadata equality and
`stack.tail.tail` agreement are enforced), and integer opcodes return
`.error` on non-`.vBigint` operands, so no caller can discharge that
universal `hOpcode` honestly. -/

/-- Runtime success of `[.swap, .opcode "OP_ADD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 1). -/
private theorem runOps_swap_add_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_ADD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  -- Compose .swap with the opcode via runOps_loadThenOpcode_unconditional.
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hAdd :
      Stack.Eval.runOpcode "OP_ADD" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a + b))) :=
    Stack.Sim.runOpcode_ADD_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_ADD"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a + b))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_ADD" initialStack
      stkSwap _ hSwap hAdd
  -- Append the unconditional `.push`.
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_ADD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_SUB", .push (.bool true)]`. -/
private theorem runOps_swap_sub_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_SUB", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hSub :
      Stack.Eval.runOpcode "OP_SUB" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a - b))) :=
    Stack.Sim.runOpcode_SUB_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_SUB"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a - b))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_SUB" initialStack
      stkSwap _ hSwap hSub
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_SUB"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_MUL", .push (.bool true)]`. -/
private theorem runOps_swap_mul_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_MUL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hMul :
      Stack.Eval.runOpcode "OP_MUL" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a * b))) :=
    Stack.Sim.runOpcode_MUL_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_MUL"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a * b))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_MUL" initialStack
      stkSwap _ hSwap hMul
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_MUL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_DIV", .push (.bool true)]` —
requires `b ≠ 0`. -/
private theorem runOps_swap_div_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_DIV", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hDiv :
      Stack.Eval.runOpcode "OP_DIV" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a / b))) :=
    Stack.Sim.runOpcode_DIV_intInt_nonzero stkSwap a b rest hStkSwap hNonzero
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_DIV"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a / b))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_DIV" initialStack
      stkSwap _ hSwap hDiv
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_DIV"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_MOD", .push (.bool true)]` —
requires `b ≠ 0`. -/
private theorem runOps_swap_mod_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_MOD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hMod :
      Stack.Eval.runOpcode "OP_MOD" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a % b))) :=
    Stack.Sim.runOpcode_MOD_intInt_nonzero stkSwap a b rest hStkSwap hNonzero
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_MOD"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a % b))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_MOD" initialStack
      stkSwap _ hSwap hMod
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_MOD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_LESSTHAN", .push (.bool true)]`. -/
private theorem runOps_swap_lt_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_LESSTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hLt :
      Stack.Eval.runOpcode "OP_LESSTHAN" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a < b)))) :=
    Stack.Sim.runOpcode_LESSTHAN_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_LESSTHAN"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a < b)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_LESSTHAN" initialStack
      stkSwap _ hSwap hLt
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_LESSTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_le_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hLe :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≤ b)))) :=
    Stack.Sim.runOpcode_LESSTHANOREQUAL_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_LESSTHANOREQUAL"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≤ b)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_LESSTHANOREQUAL" initialStack
      stkSwap _ hSwap hLe
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_LESSTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_GREATERTHAN", .push (.bool true)]`. -/
private theorem runOps_swap_gt_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hGt :
      Stack.Eval.runOpcode "OP_GREATERTHAN" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a > b)))) :=
    Stack.Sim.runOpcode_GREATERTHAN_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_GREATERTHAN"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a > b)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_GREATERTHAN" initialStack
      stkSwap _ hSwap hGt
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_GREATERTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_ge_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hGe :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≥ b)))) :=
    Stack.Sim.runOpcode_GREATERTHANOREQUAL_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_GREATERTHANOREQUAL"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≥ b)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_GREATERTHANOREQUAL" initialStack
      stkSwap _ hSwap hGe
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_GREATERTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_NUMEQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_eq_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hEq :
      Stack.Eval.runOpcode "OP_NUMEQUAL" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a = b)))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_NUMEQUAL"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a = b)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_NUMEQUAL" initialStack
      stkSwap _ hSwap hEq
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_NUMEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]`. -/
private theorem runOps_swap_neq_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hNeq :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≠ b)))) :=
    Stack.Sim.runOpcode_NUMNOTEQUAL_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_NUMNOTEQUAL"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≠ b)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_NUMNOTEQUAL" initialStack
      stkSwap _ hSwap hNeq
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_NUMNOTEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_BOOLAND", .push (.bool true)]`. -/
private theorem runOps_swap_booland_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_BOOLAND", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hAnd :
      Stack.Eval.runOpcode "OP_BOOLAND" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLAND_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_BOOLAND"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_BOOLAND" initialStack
      stkSwap _ hSwap hAnd
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_BOOLAND"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_BOOLOR", .push (.bool true)]`. -/
private theorem runOps_swap_boolor_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_BOOLOR", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hOr :
      Stack.Eval.runOpcode "OP_BOOLOR" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLOR_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_BOOLOR"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_BOOLOR" initialStack
      stkSwap _ hSwap hOr
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_BOOLOR"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_LSHIFT", .push (.bool true)]`. -/
private theorem runOps_swap_shl_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_LSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hShl :
      Stack.Eval.runOpcode "OP_LSHIFT" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_LSHIFT_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_LSHIFT"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_LSHIFT" initialStack
      stkSwap _ hSwap hShl
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_LSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.swap, .opcode "OP_RSHIFT", .push (.bool true)]`. -/
private theorem runOps_swap_shr_pushTrue_of_agreesTagged_d0d1
    (n1 n2 : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.swap, .opcode "OP_RSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨rest, _hStk, hSwap⟩ :=
    runOps_swap_post_state_d0d1 n1 n2 tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkSwap : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: rest}
  have hStkSwap : stkSwap.stack = .vBigint b :: .vBigint a :: rest := rfl
  have hShr :
      Stack.Eval.runOpcode "OP_RSHIFT" stkSwap
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_RSHIFT_intInt stkSwap a b rest hStkSwap
  have hChain :
      Stack.Eval.runOps [.swap, .opcode "OP_RSHIFT"] initialStack
        = .ok ({stkSwap with stack := rest}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.swap] "OP_RSHIFT" initialStack
      stkSwap _ hSwap hShr
  show (Stack.Eval.runOps
          ([.swap, .opcode "OP_RSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrapper for `singletonBinOpWithCap_d0d1 + "+"` -/

/-- **Method-level runtime-success wrapper for the `+` body at depth pair
(0, 1) consume.** Real-arith body whose runtime success is proved
structurally — no `hRunOk` / `hSimulates`. The two operand lookups plus
`agreesTagged` (with `n1` at depth 0, `n2` at depth 1) deliver the
runtime stack shape; the wave-12 d0d1 helper above discharges
`[.swap, .opcode, .push true]`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinAdd_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "+" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "+" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("+" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "+" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  -- `binopOpcode "+" rt = "OP_ADD"` by definitional reduction.
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_ADD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_add_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `-` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinSub_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "-" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "-" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("-" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "-" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_SUB", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_sub_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `*` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMul_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "*" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "*" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("*" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "*" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_MUL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_mul_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `/` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinDiv_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "/" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "/" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("/" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "/" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_DIV", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_div_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `%` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMod_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "%" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "%" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("%" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "%" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_MOD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_mod_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `<` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLt_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "<" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "<" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_LESSTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_lt_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<=` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLe_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "<=" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "<=" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_le_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGt_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m ">" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m ">" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_gt_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>=` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGe_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m ">=" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m ">=" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_ge_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `===` at d0d1 consume.**
Requires `rt ≠ some "bytes"` so the lowerer's `===` branch picks
`OP_NUMEQUAL`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinEq_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "===" n1 n2 bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "===" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("===" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "===" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  -- Reduce `binopOpcode "===" rt` to "OP_NUMEQUAL" using hRtNotBytes.
  have hOpcode : Stack.Lower.binopOpcode "===" rt = "OP_NUMEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_eq_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `!==` at d0d1 consume.**
Requires `rt ≠ some "bytes"` so the lowerer's `!==` branch picks
`OP_NUMNOTEQUAL` (without the trailing `OP_NOT` peephole). -/
theorem runMethod_lower_public_unique_no_post_singletonBinNeq_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "!==" n1 n2 bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "!==" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("!==" == "!==") && rt == some "bytes") = false := by
    have hRt : (rt == some "bytes") = false := by
      cases hRt' : rt with
      | none => rfl
      | some s =>
          by_cases hBytes : s = "bytes"
          · exact absurd (by rw [hRt', hBytes]) hRtNotBytes
          · simp [hBytes]
    simp [hRt]
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "!==" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "!==" rt = "OP_NUMNOTEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_neq_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `&&` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAnd_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "&&" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "&&" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("&&" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "&&" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_BOOLAND", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_booland_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `||` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinOr_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "||" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "||" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("||" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "||" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_BOOLOR", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_boolor_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<<` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShl_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m "<<" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m "<<" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_LSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_shl_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>>` at d0d1 consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShr_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0d1 m ">>" n1 n2 bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">>" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">>" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0d1
        methods props m ">>" n1 n2 bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.swap, .opcode "OP_RSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_swap_shr_pushTrue_of_agreesTagged_d0d1 n1 n2 tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-! ## A3 — Wave 13: binOp wrappers at depth pairs (d ≥ 2, 0) and (0, d ≥ 2)

Wave 12 landed the (1, 0) and (0, 1) depth-pair binop wrappers. This wave
lands the analogous wrappers at depth pairs (2, 0) [`dge2_d0`] and (0, 2)
[`d0_dge2`], i.e. the `d = 2` instances of the general `d ≥ 2` family.

### Why d = 2 (not generic d ≥ 3) here

The lowerer reduction at a *generic* depth `d ≥ 3` would require the
method's params (= the initial `StackMap`) to carry a generic list of
`d − 1` "stepped-over" middle slots between the top operand and the
depth-`d` operand, and to reason about `StackMap.depth? = some d` and
`StackMap.removeAtDepth d` on that generic-length list, AND the runtime
side needs `applyRoll d` on a generic-length runtime stack. Both are
provable by list induction but add machinery disproportionate to this
wave. The Wave 11b smoke tests (`_smokeTest_stageC_dge2_d0_consume_OP_ADD_d2`,
`_smokeTest_stageC_d0_dge2_consume_OP_ADD_d2`) likewise pin `d = 2`. The
wrappers below therefore cover the `d = 2` (`.rot`) instances. The
`d ≥ 3` (`.roll d`) instances are documented BLOCKED at the end of this
section pending the generic-`d` lowerer/runtime induction lemmas.

### Substrate use

The Wave 11b corrected substrates `stageC_simpleStep_binOp_dge2_d0_consume_core`
and `stageC_simpleStep_binOp_d0_dge2_consume_core` have a net `−1` element
delta post-state `(stkSt.stack.eraseIdx d).tail.push out`. The runtime
helpers below follow the smoke-test recipe: build `hLoadRun` against
`applyRot (∘ applySwap)`, build `hOpcode` against `runOpcode_*_intInt`,
then close via the substrate. The method-level wrappers reduce the
lowered method to the fixed op list via the per-pair lowerer reductions
and chain through the runtime helper. -/

/-! ### Cap predicate at depth pair (2, 0) -/

/-- Generic composite body shape for a single `binOp opName n1 n2 rt`
binding at depth pair (2, 0) followed by the sentinel-true cap. The left
operand `n1` sits at depth 2, the right operand `n2` at depth 0, with one
"stepped-over" middle slot `nm` at depth 1. Params reversed is
`n2 :: nm :: n1 :: tail`. -/
def singletonBinOpWithCap_dge2_d0 (m : ANFMethod)
    (opName : String) (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
            ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n2 :: nm :: n1 :: tail ∧
  n1 ≠ n2 ∧ n1 ≠ nm ∧ n2 ≠ nm ∧
  bn ≠ bcap ∧ bcap ≠ n1 ∧ bcap ≠ n2

/-! ### Lowering of `singletonBinOpWithCap_dge2_d0`:
   `[.rot, .swap, .opcode (binopOpcode opName rt), .push (.bool true)]`

The body's `computeLastUses` is `[(n2, 0), (n1, 0)]` (identical to the
(1, 0)/(0, 1) cases — depends only on the body, not on params). The
binOp loads `n1` (left) first: it is at depth 2, last-use → consume →
`bringToTop` emits `[.rot]` and updates the stack map to
`n1 :: n2 :: nm :: tail`. Then `n2` (right) is loaded: now at depth 1,
last-use → consume → `[.swap]`. -/

set_option maxHeartbeats 4000000 in
set_option linter.unusedSimpArgs false in
private theorem lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (opName : String)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonBinOpWithCap_dge2_d0 m opName n1 n2 nm bn bcap tail rt src srcCap)
    (hNotNeqBytes : (opName == "!==" && rt == some "bytes") = false) :
    lowerMethodUserRawOps progMethods props m
      = [.rot, .swap, .opcode (Stack.Lower.binopOpcode opName rt),
         .push (.bool true)] := by
  obtain ⟨hBody, hRev, hne12, hne1m, hne2m, _hBnCap, _hBcapN1, _hBcapN2⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap hne12]
  rw [collectConstInts_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap]
  -- Depth-2 lookup of n1 in [n2, nm, n1, ...tail] is some 2.
  have hFind1 : (n2 :: nm :: n1 :: tail).findIdx? (· == n1) = some 2 := by
    have h21 : (n2 == n1) = false := by
      have h : n2 ≠ n1 := fun h => hne12 h.symm
      simp [beq_iff_eq, h]
    have hm1 : (nm == n1) = false := by
      have h : nm ≠ n1 := fun h => hne1m h.symm
      simp [beq_iff_eq, h]
    unfold List.findIdx?
    simp [List.findIdx?.go, h21, hm1]
  -- Depth-1 lookup of n2 in [n1, n2, nm, ...tail] (after the rot) is some 1.
  have hFind2 : (n1 :: n2 :: nm :: tail).findIdx? (· == n2) = some 1 := by
    have h12 : (n1 == n2) = false := by
      simp [beq_iff_eq, hne12]
    unfold List.findIdx?
    simp [List.findIdx?.go, h12]
  -- Build a `loadRefLive` result for n1 at depth 2, consume-mode: `[.rot]`.
  have hLoadN1 :
      Stack.Lower.loadRefLive (n2 :: nm :: n1 :: tail) n1 0 [(n2, 0), (n1, 0)] []
        = ([.rot], n1 :: n2 :: nm :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n1, isLastUse_two_first n1 n2 hne12]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind1]
    simp [Stack.Lower.StackMap.removeAtDepth, Stack.Lower.StackMap.push]
  -- Same for n2 at depth 1 of the rotated sm: `[.swap]`.
  have hLoadN2 :
      Stack.Lower.loadRefLive (n1 :: n2 :: nm :: tail) n2 0 [(n2, 0), (n1, 0)] []
        = ([.swap], n2 :: n1 :: nm :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n2, isLastUse_two_second n1 n2]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind2]
    simp
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [hLoadN1]
  simp only [hLoadN2]
  rw [hNotNeqBytes]
  simp only [Bool.false_eq_true, if_false, reduceIte]
  unfold Stack.Lower.StackMap.popN
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### Three-value top-of-stack extraction at depth pair (2, 0)

For binOp at depth pair (2, 0) we need the right operand (`n2`, value `b`)
on top, a stepped-over middle slot (`nm`) at depth 1, and the left operand
(`n1`, value `a`) at depth 2. The lookups plus `agreesTagged` over the
prefix `[(n2, .param), (nm, .param), (n1, .param)]` deliver the shape
`.vBigint b :: midV :: .vBigint a :: rest`. -/

private theorem initialStack_top_three_vBigint_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ midV rest,
      initialStack.stack = .vBigint b :: midV :: .vBigint a :: rest := by
  have hAlign :
      taggedStackAligned ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest)
                         anfSt initialStack.stack := hAgrees.1
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | [_] =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      simp [taggedStackAligned] at hTail
  | [_, _] =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      unfold taggedStackAligned at hTail
      obtain ⟨_, hTail2⟩ := hTail
      simp [taggedStackAligned] at hTail2
  | topV :: midV :: botV :: rest =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨hHeadTop, hRestAlign⟩ := hAlign
      unfold taggedStackAligned at hRestAlign
      obtain ⟨_hHeadMid, hRest2⟩ := hRestAlign
      unfold taggedStackAligned at hRest2
      obtain ⟨hHeadBot, _⟩ := hRest2
      have hHeadTop' : anfSt.lookupParam n2 = some topV := hHeadTop
      have hHeadBot' : anfSt.lookupParam n1 = some botV := hHeadBot
      have hTopEq : topV = .vBigint b := by
        have hCombined : some topV = some (.vBigint b) := hHeadTop'.symm.trans hLookupR
        exact Option.some.inj hCombined
      have hBotEq : botV = .vBigint a := by
        have hCombined : some botV = some (.vBigint a) := hHeadBot'.symm.trans hLookupL
        exact Option.some.inj hCombined
      exact ⟨midV, rest, by rw [hTopEq, hBotEq]⟩

/-! ### `[.rot, .swap]` post-load helper at depth pair (2, 0)

After `[.rot, .swap]` on a stack `.vBigint b :: midV :: .vBigint a :: rest`,
`.rot` yields `.vBigint a :: .vBigint b :: midV :: rest` and `.swap`
yields `.vBigint b :: .vBigint a :: midV :: rest` — the canonical
post-load shape `.vBigint b :: .vBigint a :: (stack.eraseIdx 2).tail`. -/

private theorem runOps_rot_swap_post_state_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ midV rest,
      initialStack.stack = .vBigint b :: midV :: .vBigint a :: rest ∧
      Stack.Eval.runOps [.rot, .swap] initialStack
        = .ok ({initialStack with
                 stack := .vBigint b :: .vBigint a :: midV :: rest}) := by
  obtain ⟨midV, rest, hStk⟩ :=
    initialStack_top_three_vBigint_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  refine ⟨midV, rest, hStk, ?_⟩
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyRot,
        Stack.Eval.applySwap, hStk, Stack.Sim.run_empty]

/-! ### Per-kind runtime-success helpers at depth pair (2, 0)

Each helper exposes the `[.rot, .swap]` post-load state, applies the
matching `runOpcode_*_intInt` simulation lemma, chains via
`runOps_loadThenOpcode_unconditional`, and appends the unconditional
cap push. The lowered op list is `[.rot, .swap, .opcode O, .push true]`. -/

/-- Runtime success of `[.rot, .swap, .opcode "OP_ADD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_add_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_ADD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hAdd :
      Stack.Eval.runOpcode "OP_ADD" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a + b))) :=
    Stack.Sim.runOpcode_ADD_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_ADD"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a + b))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_ADD" initialStack
      stkLoad _ hLoad hAdd
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_ADD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_SUB", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_sub_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_SUB", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_SUB" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a - b))) :=
    Stack.Sim.runOpcode_SUB_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_SUB"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a - b))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_SUB" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_SUB"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_MUL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_mul_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_MUL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MUL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * b))) :=
    Stack.Sim.runOpcode_MUL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_MUL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * b))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_MUL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_MUL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_DIV", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). Requires `b ≠ 0`. -/
private theorem runOps_rot_swap_div_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_DIV", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_DIV" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / b))) :=
    Stack.Sim.runOpcode_DIV_intInt_nonzero stkLoad a b (midV :: rest) hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_DIV"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / b))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_DIV" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_DIV"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_MOD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). Requires `b ≠ 0`. -/
private theorem runOps_rot_swap_mod_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_MOD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MOD" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a % b))) :=
    Stack.Sim.runOpcode_MOD_intInt_nonzero stkLoad a b (midV :: rest) hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_MOD"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a % b))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_MOD" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_MOD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_lt_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHAN" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a < b)))) :=
    Stack.Sim.runOpcode_LESSTHAN_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_LESSTHAN"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a < b)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_LESSTHAN" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_LESSTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_le_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≤ b)))) :=
    Stack.Sim.runOpcode_LESSTHANOREQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_LESSTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≤ b)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_LESSTHANOREQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_LESSTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_gt_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHAN" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a > b)))) :=
    Stack.Sim.runOpcode_GREATERTHAN_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_GREATERTHAN"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a > b)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_GREATERTHAN" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_GREATERTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_ge_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≥ b)))) :=
    Stack.Sim.runOpcode_GREATERTHANOREQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_GREATERTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≥ b)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_GREATERTHANOREQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_GREATERTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_eq_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMEQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a = b)))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_NUMEQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a = b)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_NUMEQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_NUMEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_neq_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ b)))) :=
    Stack.Sim.runOpcode_NUMNOTEQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_NUMNOTEQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ b)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_NUMNOTEQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_NUMNOTEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_BOOLAND", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_and_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_BOOLAND", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLAND" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLAND_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_BOOLAND"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_BOOLAND" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_BOOLAND"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_BOOLOR", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_or_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_BOOLOR", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLOR" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLOR_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_BOOLOR"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_BOOLOR" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_BOOLOR"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_LSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_shl_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_LSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LSHIFT" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_LSHIFT_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_LSHIFT"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_LSHIFT" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_LSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .swap, .opcode "OP_RSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (2, 0). -/
private theorem runOps_rot_swap_shr_pushTrue_of_agreesTagged_dge2_d0
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .swap, .opcode "OP_RSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_swap_post_state_dge2_d0 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_RSHIFT" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_RSHIFT_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .swap, .opcode "OP_RSHIFT"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.rot, .swap] "OP_RSHIFT" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .swap, .opcode "OP_RSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrapper for `+` at depth pair (2, 0) -/

/-- **Method-level runtime-success wrapper for the `+` body at depth pair
(2, 0) consume.** The left operand sits at depth 2, the right at depth 0,
with a stepped-over middle slot at depth 1. The lowerer emits
`[.rot, .swap, .opcode, .push true]`; runtime success is delivered by
`runOps_rot_swap_add_pushTrue_of_agreesTagged_dge2_d0`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinAdd_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "+" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "+" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("+" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "+" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_ADD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_add_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `-` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinSub_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "-" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "-" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("-" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "-" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_SUB", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_sub_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `*` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMul_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "*" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "*" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("*" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "*" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_MUL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_mul_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `/` at depth pair (2, 0)
consume.** Requires `b ≠ 0`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinDiv_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "/" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "/" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("/" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "/" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_DIV", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_div_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `%` at depth pair (2, 0)
consume.** Requires `b ≠ 0`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinMod_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "%" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "%" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("%" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "%" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_MOD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_mod_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `<` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLt_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "<" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "<" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_lt_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<=` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLe_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "<=" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "<=" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_le_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGt_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m ">" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m ">" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_gt_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>=` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGe_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m ">=" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m ">=" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_ge_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `===` at depth pair (2, 0)
consume.** Requires `rt ≠ some "bytes"` so the lowerer picks `OP_NUMEQUAL`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinEq_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "===" n1 n2 nm bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "===" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("===" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "===" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "===" rt = "OP_NUMEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_eq_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `!==` at depth pair (2, 0)
consume.** Requires `rt ≠ some "bytes"` so the lowerer picks `OP_NUMNOTEQUAL`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinNeq_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "!==" n1 n2 nm bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "!==" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("!==" == "!==") && rt == some "bytes") = false := by
    have hRt : (rt == some "bytes") = false := by
      cases hRt' : rt with
      | none => rfl
      | some s =>
          by_cases hBytes : s = "bytes"
          · exact absurd (by rw [hRt', hBytes]) hRtNotBytes
          · simp [hBytes]
    simp [hRt]
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "!==" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "!==" rt = "OP_NUMNOTEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_neq_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `&&` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAnd_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "&&" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "&&" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("&&" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "&&" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_BOOLAND", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_and_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `||` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinOr_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "||" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "||" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("||" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "||" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_BOOLOR", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_or_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<<` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShl_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m "<<" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m "<<" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_LSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_shl_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>>` at depth pair (2, 0)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShr_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge2_d0 m ">>" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n2, .param) :: (nm, .param) :: (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">>" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">>" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge2_d0
        methods props m ">>" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .swap, .opcode "OP_RSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_swap_shr_pushTrue_of_agreesTagged_dge2_d0 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-! ### Cap predicate at depth pair (0, 2) -/

/-- Generic composite body shape for a single `binOp opName n1 n2 rt`
binding at depth pair (0, 2) followed by the sentinel-true cap. The left
operand `n1` sits at depth 0, the right operand `n2` at depth 2, with one
"stepped-over" middle slot `nm` at depth 1. Params reversed is
`n1 :: nm :: n2 :: tail`. -/
def singletonBinOpWithCap_d0_dge2 (m : ANFMethod)
    (opName : String) (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
            ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n1 :: nm :: n2 :: tail ∧
  n1 ≠ n2 ∧ n1 ≠ nm ∧ n2 ≠ nm ∧
  bn ≠ bcap ∧ bcap ≠ n1 ∧ bcap ≠ n2

/-! ### Lowering of `singletonBinOpWithCap_d0_dge2`:
   `[.rot, .opcode (binopOpcode opName rt), .push (.bool true)]`

The binOp loads `n1` (left) first: it is at depth 0, last-use → consume →
`bringToTop` emits `[]` (no-op), the stack map is unchanged. Then `n2`
(right) is loaded: at depth 2, last-use → consume → `[.rot]`. -/

set_option maxHeartbeats 4000000 in
set_option linter.unusedSimpArgs false in
private theorem lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (opName : String)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonBinOpWithCap_d0_dge2 m opName n1 n2 nm bn bcap tail rt src srcCap)
    (hNotNeqBytes : (opName == "!==" && rt == some "bytes") = false) :
    lowerMethodUserRawOps progMethods props m
      = [.rot, .opcode (Stack.Lower.binopOpcode opName rt),
         .push (.bool true)] := by
  obtain ⟨hBody, hRev, hne12, hne1m, hne2m, _hBnCap, _hBcapN1, _hBcapN2⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap hne12]
  rw [collectConstInts_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap]
  -- Depth-0 lookup of n1 in [n1, nm, n2, ...tail] is some 0.
  have hFind1 : (n1 :: nm :: n2 :: tail).findIdx? (· == n1) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  -- Depth-2 lookup of n2 in [n1, nm, n2, ...tail] (sm unchanged after no-op) is some 2.
  have hFind2 : (n1 :: nm :: n2 :: tail).findIdx? (· == n2) = some 2 := by
    have h12 : (n1 == n2) = false := by
      simp [beq_iff_eq, hne12]
    have hm2 : (nm == n2) = false := by
      have h : nm ≠ n2 := fun h => hne2m h.symm
      simp [beq_iff_eq, h]
    unfold List.findIdx?
    simp [List.findIdx?.go, h12, hm2]
  -- Load n1 at depth 0, consume-mode: no-op, sm unchanged.
  have hLoadN1 :
      Stack.Lower.loadRefLive (n1 :: nm :: n2 :: tail) n1 0 [(n2, 0), (n1, 0)] []
        = ([], n1 :: nm :: n2 :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n1, isLastUse_two_first n1 n2 hne12]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind1]
    simp
  -- Load n2 at depth 2 of the unchanged sm: `[.rot]`.
  have hLoadN2 :
      Stack.Lower.loadRefLive (n1 :: nm :: n2 :: tail) n2 0 [(n2, 0), (n1, 0)] []
        = ([.rot], n2 :: n1 :: nm :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n2, isLastUse_two_second n1 n2]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    rw [hFind2]
    simp [Stack.Lower.StackMap.removeAtDepth, Stack.Lower.StackMap.push]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [hLoadN1]
  simp only [hLoadN2]
  rw [hNotNeqBytes]
  simp only [Bool.false_eq_true, if_false, reduceIte]
  unfold Stack.Lower.StackMap.popN
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### Three-value top-of-stack extraction at depth pair (0, 2)

The left operand (`n1`, value `a`) sits on top, a stepped-over middle slot
(`nm`) at depth 1, and the right operand (`n2`, value `b`) at depth 2. -/

private theorem initialStack_top_three_vBigint_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ midV rest,
      initialStack.stack = .vBigint a :: midV :: .vBigint b :: rest := by
  have hAlign :
      taggedStackAligned ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest)
                         anfSt initialStack.stack := hAgrees.1
  match hCases : initialStack.stack with
  | [] =>
      rw [hCases] at hAlign
      simp [taggedStackAligned] at hAlign
  | [_] =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      simp [taggedStackAligned] at hTail
  | [_, _] =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      unfold taggedStackAligned at hTail
      obtain ⟨_, hTail2⟩ := hTail
      simp [taggedStackAligned] at hTail2
  | topV :: midV :: botV :: rest =>
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨hHeadTop, hRestAlign⟩ := hAlign
      unfold taggedStackAligned at hRestAlign
      obtain ⟨_hHeadMid, hRest2⟩ := hRestAlign
      unfold taggedStackAligned at hRest2
      obtain ⟨hHeadBot, _⟩ := hRest2
      have hHeadTop' : anfSt.lookupParam n1 = some topV := hHeadTop
      have hHeadBot' : anfSt.lookupParam n2 = some botV := hHeadBot
      have hTopEq : topV = .vBigint a := by
        have hCombined : some topV = some (.vBigint a) := hHeadTop'.symm.trans hLookupL
        exact Option.some.inj hCombined
      have hBotEq : botV = .vBigint b := by
        have hCombined : some botV = some (.vBigint b) := hHeadBot'.symm.trans hLookupR
        exact Option.some.inj hCombined
      exact ⟨midV, rest, by rw [hTopEq, hBotEq]⟩

/-! ### `[.rot]` post-load helper at depth pair (0, 2)

After `[.rot]` on a stack `.vBigint a :: midV :: .vBigint b :: rest`,
`.rot` yields `.vBigint b :: .vBigint a :: midV :: rest` — the canonical
post-load shape `.vBigint b :: .vBigint a :: (stack.eraseIdx 2).tail`. -/

private theorem runOps_rot_post_state_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ midV rest,
      initialStack.stack = .vBigint a :: midV :: .vBigint b :: rest ∧
      Stack.Eval.runOps [.rot] initialStack
        = .ok ({initialStack with
                 stack := .vBigint b :: .vBigint a :: midV :: rest}) := by
  obtain ⟨midV, rest, hStk⟩ :=
    initialStack_top_three_vBigint_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
      initialStack a b hAgrees hLookupL hLookupR
  refine ⟨midV, rest, hStk, ?_⟩
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyRot,
        hStk, Stack.Sim.run_empty]

/-! ### Per-kind runtime-success helpers at depth pair (0, 2) -/

/-- Runtime success of `[.rot, .opcode "OP_ADD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_add_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_ADD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_ADD" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a + b))) :=
    Stack.Sim.runOpcode_ADD_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_ADD"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a + b))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_ADD" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_ADD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_SUB", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_sub_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_SUB", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_SUB" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a - b))) :=
    Stack.Sim.runOpcode_SUB_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_SUB"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a - b))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_SUB" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_SUB"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_MUL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_mul_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_MUL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MUL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * b))) :=
    Stack.Sim.runOpcode_MUL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_MUL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * b))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_MUL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_MUL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_DIV", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). Requires `b ≠ 0`. -/
private theorem runOps_rot_div_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_DIV", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_DIV" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / b))) :=
    Stack.Sim.runOpcode_DIV_intInt_nonzero stkLoad a b (midV :: rest) hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_DIV"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / b))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_DIV" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_DIV"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_MOD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). Requires `b ≠ 0`. -/
private theorem runOps_rot_mod_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_MOD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MOD" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a % b))) :=
    Stack.Sim.runOpcode_MOD_intInt_nonzero stkLoad a b (midV :: rest) hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_MOD"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a % b))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_MOD" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_MOD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_LESSTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_lt_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_LESSTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHAN" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a < b)))) :=
    Stack.Sim.runOpcode_LESSTHAN_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_LESSTHAN"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a < b)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_LESSTHAN" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_LESSTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_le_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≤ b)))) :=
    Stack.Sim.runOpcode_LESSTHANOREQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_LESSTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≤ b)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_LESSTHANOREQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_LESSTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_GREATERTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_gt_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_GREATERTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHAN" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a > b)))) :=
    Stack.Sim.runOpcode_GREATERTHAN_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_GREATERTHAN"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a > b)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_GREATERTHAN" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_GREATERTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_ge_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≥ b)))) :=
    Stack.Sim.runOpcode_GREATERTHANOREQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_GREATERTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≥ b)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_GREATERTHANOREQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_GREATERTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_NUMEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_eq_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_NUMEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMEQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a = b)))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_NUMEQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a = b)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_NUMEQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_NUMEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_neq_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ b)))) :=
    Stack.Sim.runOpcode_NUMNOTEQUAL_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_NUMNOTEQUAL"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ b)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_NUMNOTEQUAL" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_NUMNOTEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_BOOLAND", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_and_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_BOOLAND", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLAND" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLAND_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_BOOLAND"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_BOOLAND" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_BOOLAND"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_BOOLOR", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_or_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_BOOLOR", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLOR" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLOR_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_BOOLOR"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_BOOLOR" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_BOOLOR"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_LSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_shl_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_LSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LSHIFT" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_LSHIFT_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_LSHIFT"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_LSHIFT" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_LSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.rot, .opcode "OP_RSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, 2). -/
private theorem runOps_rot_shr_pushTrue_of_agreesTagged_d0_dge2
    (n1 n2 nm : String) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    :
    (Stack.Eval.runOps
        [.rot, .opcode "OP_RSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midV, rest, _hStk, hLoad⟩ :=
    runOps_rot_post_state_d0_dge2 n1 n2 nm tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midV :: rest}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midV :: rest := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_RSHIFT" stkLoad
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_RSHIFT_intInt stkLoad a b (midV :: rest) hStkLoad
  have hChain :
      Stack.Eval.runOps [.rot, .opcode "OP_RSHIFT"] initialStack
        = .ok ({stkLoad with stack := midV :: rest}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.rot] "OP_RSHIFT" initialStack
      stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.rot, .opcode "OP_RSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrappers at depth pair (0, 2) -/

/-- **Method-level runtime-success wrapper for `+` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAdd_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "+" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "+" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("+" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "+" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_ADD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_add_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `-` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinSub_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "-" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "-" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("-" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "-" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_SUB", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_sub_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `*` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMul_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "*" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "*" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("*" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "*" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_MUL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_mul_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `/` at depth pair (0, 2)
consume.** Requires `b ≠ 0`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinDiv_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "/" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "/" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("/" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "/" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_DIV", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_div_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `%` at depth pair (0, 2)
consume.** Requires `b ≠ 0`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinMod_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "%" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0)
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "%" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("%" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "%" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_MOD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_mod_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `<` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLt_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "<" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "<" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_LESSTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_lt_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<=` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLe_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "<=" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "<=" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_le_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGt_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m ">" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m ">" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_GREATERTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_gt_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>=` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGe_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m ">=" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m ">=" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_ge_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `===` at depth pair (0, 2)
consume.** Requires `rt ≠ some "bytes"` so the lowerer picks `OP_NUMEQUAL`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinEq_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "===" n1 n2 nm bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "===" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("===" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "===" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "===" rt = "OP_NUMEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_NUMEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_eq_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `!==` at depth pair (0, 2)
consume.** Requires `rt ≠ some "bytes"` so the lowerer picks `OP_NUMNOTEQUAL`. -/
theorem runMethod_lower_public_unique_no_post_singletonBinNeq_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "!==" n1 n2 nm bn bcap tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "!==" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("!==" == "!==") && rt == some "bytes") = false := by
    have hRt : (rt == some "bytes") = false := by
      cases hRt' : rt with
      | none => rfl
      | some s =>
          by_cases hBytes : s = "bytes"
          · exact absurd (by rw [hRt', hBytes]) hRtNotBytes
          · simp [hBytes]
    simp [hRt]
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "!==" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "!==" rt = "OP_NUMNOTEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_neq_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `&&` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAnd_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "&&" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "&&" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("&&" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "&&" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_BOOLAND", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_and_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `||` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinOr_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "||" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "||" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("||" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "||" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_BOOLOR", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_or_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<<` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShl_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m "<<" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m "<<" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_LSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_shl_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>>` at depth pair (0, 2)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShr_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 nm bn bcap : String) (tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge2 m ">>" n1 n2 nm bn bcap tail rt src srcCap)
    (hAgrees : agreesTagged
      ((n1, .param) :: (nm, .param) :: (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (_hUntagSm : untagSm tsm_rest = tail) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">>" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">>" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge2
        methods props m ">>" n1 n2 nm bn bcap tail rt src srcCap hCap hNotNeqBytes]
  show (Stack.Eval.runOps
          [.rot, .opcode "OP_RSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rot_shr_pushTrue_of_agreesTagged_d0_dge2 n1 n2 nm tsm_rest anfSt
    initialStack a b hAgrees hLookupL hLookupR

/-! ## A3 — Wave 14: binOp wrappers at depth pairs (d ≥ 3, 0) and (0, d ≥ 3)

Wave 13 landed the `d = 2` (`.rot` lowering) instances of the general
`d ≥ 2` binop depth-pair family. This wave lands the `d ≥ 3` (`.roll d`
lowering) instances, kept SEPARATE from the wave-13 `d = 2` wrappers so
their callers stay byte-stable.

### Crux — `applyRoll d` post-state on a generic-length stack

The depth-`d` consume path emits `[.roll d]` (`Stack.Lower.bringToTop`'s
`some d` arm for `d ≥ 3`). Its runtime effect (`Stack.Eval.applyRoll`,
when `d < stack.length`) is `stkSt.stack[d]! :: stkSt.stack.eraseIdx d`.
`runOps_roll_postState` packages that no-`if` reduction. Composed with
`eraseIdx_cons_pos` (`(x :: xs).eraseIdx d = x :: xs.eraseIdx (d-1)` for
`d ≥ 1`), the rolled stack at `d ≥ 2` is `a :: b :: (eraseIdx d).tail`
when `a` sits at depth `d` and `b` on top — so a following `.swap`
delivers the canonical `b :: a :: (eraseIdx d).tail` post-load shape, the
same one wave-13 produced with `.rot`.

### Generic-length lowerer reductions

The cap's params carry a generic middle block `m1 :: m2 :: midsRest`
(length `≥ 2`, so the depth-`d` operand is at `d = midsRest.length + 3
≥ 3`). The lowerer's `findIdx?` / `removeAtDepth` over that block are
discharged by the two list-induction helpers `findIdx_skip_pre` /
`removeAt_skip_pre`. The remaining steps mirror the wave-13 `dge2_d0` /
`d0_dge2` lowerer proofs verbatim, with `.rot` replaced by `.roll d`. -/

/-! ### Foundation helpers for Wave 14 -/

/-- `runOps [.roll d]` post-state when `d < stack.length`: the depth-`d`
element moves to the top, the rest shifts up (`eraseIdx d`). -/
private theorem runOps_roll_postState
    (stkSt : StackState) (d : Nat) (hLen : d < stkSt.stack.length) :
    Stack.Eval.runOps [.roll d] stkSt
      = .ok ({stkSt with stack := stkSt.stack[d]! :: stkSt.stack.eraseIdx d}) := by
  unfold Stack.Eval.runOps
  have hStep : Stack.Eval.stepNonIf (.roll d) stkSt
      = Stack.Eval.applyRoll stkSt d := rfl
  rw [hStep]
  unfold Stack.Eval.applyRoll
  rw [if_neg (Nat.not_le.mpr hLen)]
  simp [Stack.Sim.run_empty]

/-- `eraseIdx` at a positive index keeps the head. -/
private theorem eraseIdx_cons_pos {α} (x : α) (xs : List α) (d : Nat) (hd : 1 ≤ d) :
    (x :: xs).eraseIdx d = x :: xs.eraseIdx (d - 1) := by
  cases d with
  | zero => omega
  | succ k => simp [List.eraseIdx_cons_succ]

/-- `findIdx?` skips a target-free prefix: the index lands at the prefix
length. -/
private theorem findIdx_skip_pre (target : String) (pre suf : List String)
    (hPre : ∀ x ∈ pre, (x == target) = false) :
    (pre ++ target :: suf).findIdx? (· == target) = some pre.length := by
  induction pre with
  | nil =>
      simp only [List.nil_append, List.length_nil]
      rw [List.findIdx?_cons]
      simp
  | cons h t ih =>
      have hh : (h == target) = false := hPre h (by simp)
      have ht : ∀ x ∈ t, (x == target) = false := fun x hx => hPre x (by simp [hx])
      simp only [List.cons_append, List.length_cons]
      rw [List.findIdx?_cons, hh]
      simp only [Bool.false_eq_true, if_false]
      rw [ih ht]
      simp [Option.map]

/-- `removeAtDepth` at a prefix length removes the element just past the
prefix. -/
private theorem removeAt_skip_pre (target : String) (pre suf : List String) :
    Stack.Lower.StackMap.removeAtDepth (pre ++ target :: suf) pre.length = pre ++ suf := by
  induction pre with
  | nil => simp [Stack.Lower.StackMap.removeAtDepth]
  | cons h t ih =>
      simp only [List.cons_append, List.length_cons]
      rw [Stack.Lower.StackMap.removeAtDepth, ih]

/-! ### Cap predicate at depth pair (d ≥ 3, 0) -/

/-- Composite body shape for a single `binOp opName n1 n2 rt` binding at
depth pair (d, 0) with `d = midsRest.length + 3 ≥ 3`, followed by the
sentinel-true cap. The left operand `n1` sits at depth `d`, the right
operand `n2` at depth 0, with `d - 1 = midsRest.length + 2` stepped-over
middle slots `m1 :: m2 :: midsRest` at depths 1 .. d-1. Params reversed
is `n2 :: m1 :: m2 :: midsRest ++ n1 :: tail`. The `hPre` clause asserts
`n1` is distinct from `n2` and every middle slot (so the depth-`d`
lookup is unambiguous). -/
def singletonBinOpWithCap_dge3_d0 (m : ANFMethod)
    (opName : String) (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
            ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n2 :: m1 :: m2 :: midsRest ++ n1 :: tail ∧
  n1 ≠ n2 ∧
  (∀ x ∈ (n2 :: m1 :: m2 :: midsRest), (x == n1) = false) ∧
  bn ≠ bcap ∧ bcap ≠ n1 ∧ bcap ≠ n2

/-! ### Lowering of `singletonBinOpWithCap_dge3_d0`:
   `[.roll (midsRest.length + 3), .swap, .opcode (binopOpcode opName rt),
     .push (.bool true)]`

The body's `computeLastUses` is `[(n2, 0), (n1, 0)]` (depends only on the
body). The binOp loads `n1` (left) first: at depth `d = midsRest.length
+ 3`, last-use → consume → `bringToTop`'s `some d` arm emits `[.roll d]`
and updates the stack map to `n1 :: n2 :: m1 :: m2 :: midsRest ++ tail`.
Then `n2` (right) is loaded: now at depth 1, last-use → consume →
`[.swap]`. -/

set_option maxHeartbeats 4000000 in
set_option linter.unusedSimpArgs false in
private theorem lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (opName : String)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonBinOpWithCap_dge3_d0 m opName n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hNotNeqBytes : (opName == "!==" && rt == some "bytes") = false) :
    lowerMethodUserRawOps progMethods props m
      = [.roll (midsRest.length + 3), .swap,
         .opcode (Stack.Lower.binopOpcode opName rt), .push (.bool true)] := by
  obtain ⟨hBody, hRev, hne12, hPre, _hBnCap, _hBcapN1, _hBcapN2⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap hne12]
  rw [collectConstInts_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap]
  -- Load n1 at depth (midsRest.length + 3), consume-mode: `[.roll d]`.
  have hLoadN1 :
      Stack.Lower.loadRefLive
          (n2 :: m1 :: m2 :: midsRest ++ n1 :: tail) n1 0 [(n2, 0), (n1, 0)] []
        = ([.roll (midsRest.length + 3)],
           n1 :: n2 :: m1 :: m2 :: midsRest ++ tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n1, isLastUse_two_first n1 n2 hne12]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    have hFind :
        (n2 :: m1 :: m2 :: midsRest ++ n1 :: tail).findIdx? (· == n1)
          = some (n2 :: m1 :: m2 :: midsRest).length := by
      have := findIdx_skip_pre n1 (n2 :: m1 :: m2 :: midsRest) tail hPre
      simpa using this
    rw [hFind]
    simp only [List.length_cons]
    have hRem :
        Stack.Lower.StackMap.removeAtDepth
            (n2 :: m1 :: m2 :: midsRest ++ n1 :: tail)
            (n2 :: m1 :: m2 :: midsRest).length
          = n2 :: m1 :: m2 :: midsRest ++ tail := by
      have := removeAt_skip_pre n1 (n2 :: m1 :: m2 :: midsRest) tail
      simpa using this
    simp only [List.length_cons] at hRem
    rw [hRem]
    rfl
  -- Load n2 at depth 1 of the rolled sm: `[.swap]`.
  have hLoadN2 :
      Stack.Lower.loadRefLive
          (n1 :: n2 :: m1 :: m2 :: midsRest ++ tail) n2 0 [(n2, 0), (n1, 0)] []
        = ([.swap], n2 :: n1 :: m1 :: m2 :: midsRest ++ tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n2, isLastUse_two_second n1 n2]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    have hFind2 :
        (n1 :: n2 :: m1 :: m2 :: midsRest ++ tail).findIdx? (· == n2) = some 1 := by
      have h12 : (n1 == n2) = false := by simp [beq_iff_eq, hne12]
      unfold List.findIdx?
      simp [List.findIdx?.go, h12]
    rw [hFind2]
    simp
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [hLoadN1]
  simp only [hLoadN2]
  rw [hNotNeqBytes]
  simp only [Bool.false_eq_true, if_false, reduceIte]
  unfold Stack.Lower.StackMap.popN
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### `[.roll d, .swap]` post-load helper at depth pair (d ≥ 3, 0)

The runtime hypotheses carry the tagged middle block `midTags`
(`= (m1,.param) :: (m2,.param) :: midsRestTags`, length `≥ 2`) and the
tagged tail `tsm_rest`. From `agreesTagged` the right operand `b` sits on
top (depth 0) and the left operand `a` at depth `d = midTags.length + 1`.
`runOps [.roll d]` brings `a` to the top giving `a :: b :: (eraseIdx
d).tail`; `.swap` produces `b :: a :: (eraseIdx d).tail`. -/

private theorem runOps_rollSwap_post_state_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ midTail,
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap] initialStack
        = .ok ({initialStack with
                 stack := .vBigint b :: .vBigint a :: midTail}) := by
  -- Alignment of the full tagged map. `d := midTags.length + 1`.
  have hAlign :
      taggedStackAligned ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest)
                         anfSt initialStack.stack := hAgrees.1
  -- Head extraction: top of stack is `.vBigint b` (n2 at depth 0).
  have hHead : ∃ rest0, initialStack.stack = .vBigint b :: rest0 := by
    match hCases : initialStack.stack with
    | [] => rw [hCases] at hAlign; simp [taggedStackAligned] at hAlign
    | topV :: rest0 =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        obtain ⟨hHd, _⟩ := hAlign
        have hHd' : anfSt.lookupParam n2 = some topV := hHd
        have hEq : topV = .vBigint b := by
          have : some topV = some (.vBigint b) := hHd'.symm.trans hLookupR
          exact Option.some.inj this
        exact ⟨rest0, by rw [hEq]⟩
  obtain ⟨rest0, hStk0⟩ := hHead
  -- Depth-d extraction via `taggedStackAlignedAt_value`: `n1` is at index
  -- `((n2,.param) :: midTags).length = midTags.length + 1` of the tagged map.
  have hTsmShape :
      (n2, .param) :: midTags ++ (n1, .param) :: tsm_rest
        = ((n2, .param) :: midTags) ++ (n1, .param) :: tsm_rest := by
    simp
  have hAt :
      taggedStackAlignedAt (((n2, .param) :: midTags) ++ (n1, .param) :: tsm_rest)
        anfSt initialStack.stack n1 .param ((n2, .param) :: midTags).length := by
    apply taggedStackAlignedAt_of_taggedStackAligned
    rw [← hTsmShape]
    exact hAlign
  obtain ⟨v, hLkV, hLenV, hGetV⟩ := taggedStackAlignedAt_value _ anfSt _ n1 .param _ hAt
  -- v = .vBigint a.
  have hVeq : v = .vBigint a := by
    have hLkV' : anfSt.lookupParam n1 = some v := hLkV
    have : some v = some (.vBigint a) := hLkV'.symm.trans hLookupL
    exact Option.some.inj this
  -- `((n2,.param) :: midTags).length = midTags.length + 1`.
  have hPreLen : ((n2, .param) :: midTags).length = midTags.length + 1 := by
    simp [List.length_cons]
  -- Restate the length / get-at-d facts at depth `midTags.length + 1`.
  rw [hPreLen] at hLenV hGetV
  have hLenD : midTags.length + 1 < initialStack.stack.length := hLenV
  have hGetD : initialStack.stack[midTags.length + 1]! = .vBigint a := by
    rw [hGetV, hVeq]
  -- `d ≥ 1` so eraseIdx keeps the head.
  have hdpos : 1 ≤ midTags.length + 1 := Nat.le_add_left 1 midTags.length
  -- Roll post-state.
  have hRoll :
      Stack.Eval.runOps [.roll (midTags.length + 1)] initialStack
        = .ok ({initialStack with
                 stack := initialStack.stack[midTags.length + 1]!
                            :: initialStack.stack.eraseIdx (midTags.length + 1)}) :=
    runOps_roll_postState initialStack (midTags.length + 1) hLenD
  -- Rewrite the rolled stack into `a :: b :: (eraseIdx d).tail`.
  have hEraseHead :
      initialStack.stack.eraseIdx (midTags.length + 1)
        = .vBigint b :: rest0.eraseIdx (midTags.length + 1 - 1) := by
    rw [hStk0]
    exact eraseIdx_cons_pos (.vBigint b) rest0 (midTags.length + 1) hdpos
  have hRoll' :
      Stack.Eval.runOps [.roll (midTags.length + 1)] initialStack
        = .ok ({initialStack with
                 stack := .vBigint a :: .vBigint b
                            :: rest0.eraseIdx (midTags.length + 1 - 1)}) := by
    rw [hRoll, hGetD, hEraseHead]
  -- Append `.swap`.
  refine ⟨rest0.eraseIdx (midTags.length + 1 - 1), ?_⟩
  show Stack.Eval.runOps ([.roll (midTags.length + 1)] ++ [.swap]) initialStack = _
  rw [Stack.Sim.runOps_append, hRoll']
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applySwap,
        Stack.Sim.run_empty]

/-! ### Per-kind runtime-success helpers at depth pair (d ≥ 3, 0)

Each helper exposes the `[.roll d, .swap]` post-load state, applies the
matching `runOpcode_*_intInt` simulation lemma, chains via
`runOps_loadThenOpcode_unconditional`, and appends the unconditional cap
push. The lowered op list is `[.roll d, .swap, .opcode O, .push true]`
with `d = midTags.length + 1`. -/

/-- Runtime success of `[.roll d, .swap, .opcode "OP_ADD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_add_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_ADD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hAdd :
      Stack.Eval.runOpcode "OP_ADD" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a + b))) :=
    Stack.Sim.runOpcode_ADD_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_ADD"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a + b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_ADD" initialStack stkLoad _ hLoad hAdd
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_ADD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrapper for `+` at depth pair (d ≥ 3, 0) consume -/

/-- **Method-level runtime-success wrapper for `+` at depth pair (d ≥ 3, 0)
consume.** The left operand sits at depth `d = midsRest.length + 3` with
`d - 1` stepped-over middle slots `m1 :: m2 :: midsRest`. The lowerer
emits `[.roll d, .swap, .opcode, .push true]`. The `_hMidLen` and
`_hUntagSm` hypotheses bridge the lowering's untagged params to the
runtime's tagged middle/tail blocks (`d = midTags.length + 1`). -/
theorem runMethod_lower_public_unique_no_post_singletonBinAdd_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "+" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "+" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("+" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "+" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  -- Bridge the lowering's `midsRest.length + 3` to the runtime's
  -- `midTags.length + 1` via `hMidLen`.
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_ADD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_add_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- Runtime success of `[.roll d, .swap, .opcode "OP_SUB", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_sub_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_SUB", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_SUB" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a - b))) :=
    Stack.Sim.runOpcode_SUB_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_SUB"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a - b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_SUB" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_SUB"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_MUL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_mul_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_MUL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MUL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * b))) :=
    Stack.Sim.runOpcode_MUL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_MUL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_MUL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_MUL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_DIV", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_div_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_DIV", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_DIV" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / b))) :=
    Stack.Sim.runOpcode_DIV_intInt_nonzero stkLoad a b midTail hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_DIV"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_DIV" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_DIV"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_MOD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_mod_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_MOD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MOD" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a % b))) :=
    Stack.Sim.runOpcode_MOD_intInt_nonzero stkLoad a b midTail hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_MOD"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a % b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_MOD" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_MOD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_LESSTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_lt_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHAN" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a < b)))) :=
    Stack.Sim.runOpcode_LESSTHAN_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHAN"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a < b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_LESSTHAN" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_le_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≤ b)))) :=
    Stack.Sim.runOpcode_LESSTHANOREQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≤ b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_LESSTHANOREQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_gt_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHAN" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a > b)))) :=
    Stack.Sim.runOpcode_GREATERTHAN_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHAN"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a > b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_GREATERTHAN" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_ge_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≥ b)))) :=
    Stack.Sim.runOpcode_GREATERTHANOREQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≥ b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_GREATERTHANOREQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_eq_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMEQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a = b)))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_NUMEQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a = b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_NUMEQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_NUMEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_neq_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ b)))) :=
    Stack.Sim.runOpcode_NUMNOTEQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_NUMNOTEQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_NUMNOTEQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_NUMNOTEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_BOOLAND", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_and_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_BOOLAND", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLAND" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLAND_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_BOOLAND"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_BOOLAND" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_BOOLAND"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_BOOLOR", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_or_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_BOOLOR", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLOR" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLOR_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_BOOLOR"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_BOOLOR" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_BOOLOR"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_LSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_shl_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_LSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LSHIFT" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_LSHIFT_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_LSHIFT"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_LSHIFT" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_LSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .swap, .opcode "OP_RSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (d ≥ 3, 0). -/
private theorem runOps_rollSwap_shr_pushTrue_of_agreesTagged_dge3_d0
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .swap, .opcode "OP_RSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_rollSwap_post_state_dge3_d0 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_RSHIFT" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_RSHIFT_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .swap, .opcode "OP_RSHIFT"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1), .swap]
      "OP_RSHIFT" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .swap, .opcode "OP_RSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrappers at depth pair (d ≥ 3, 0) for the remaining binops -/

/-- **Method-level runtime-success wrapper for `-` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinSub_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "-" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "-" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("-" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "-" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_SUB", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_sub_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `*` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMul_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "*" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "*" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("*" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "*" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_MUL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_mul_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `/` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinDiv_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "/" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "/" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("/" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "/" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_DIV", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_div_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `%` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMod_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "%" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "%" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("%" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "%" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_MOD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_mod_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `<` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLt_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_lt_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<=` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLe_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "<=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "<=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_le_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGt_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m ">" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m ">" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_gt_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>=` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGe_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m ">=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m ">=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_ge_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `===` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinEq_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "===" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "===" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("===" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "===" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "===" rt = "OP_NUMEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_NUMEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_eq_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `!==` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinNeq_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "!==" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "!==" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("!==" == "!==") && rt == some "bytes") = false := by
    have hRt : (rt == some "bytes") = false := by
      cases hRt' : rt with
      | none => rfl
      | some s =>
          by_cases hBytes : s = "bytes"
          · exact absurd (by rw [hRt', hBytes]) hRtNotBytes
          · simp [hBytes]
    simp [hRt]
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "!==" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "!==" rt = "OP_NUMNOTEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_neq_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `&&` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAnd_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "&&" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "&&" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("&&" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "&&" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_BOOLAND", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_and_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `||` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinOr_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "||" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "||" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("||" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "||" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_BOOLOR", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_or_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<<` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShl_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m "<<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m "<<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_LSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_shl_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>>` at depth pair
(d ≥ 3, 0) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShr_dge3_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_dge3_d0 m ">>" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n2, .param) :: midTags ++ (n1, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">>" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">>" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_dge3_d0
        methods props m ">>" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .swap, .opcode "OP_RSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_rollSwap_shr_pushTrue_of_agreesTagged_dge3_d0 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-! ### Cap predicate at depth pair (0, d ≥ 3) -/

/-- Composite body shape for a single `binOp opName n1 n2 rt` binding at
depth pair (0, d) with `d = midsRest.length + 3 ≥ 3`. The left operand
`n1` sits at depth 0, the right operand `n2` at depth `d`, with the
stepped-over middle slots `m1 :: m2 :: midsRest` between them. Params
reversed is `n1 :: m1 :: m2 :: midsRest ++ n2 :: tail`. The `hPre`
clause asserts `n2` is distinct from `n1` and every middle slot. -/
def singletonBinOpWithCap_d0_dge3 (m : ANFMethod)
    (opName : String) (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc) : Prop :=
  m.body = [⟨bn, .binOp opName n1 n2 rt, src⟩,
            ⟨bcap, .loadConst (.bool true), srcCap⟩] ∧
  (m.params.map (fun p => p.name)).reverse = n1 :: m1 :: m2 :: midsRest ++ n2 :: tail ∧
  n1 ≠ n2 ∧
  (∀ x ∈ (n1 :: m1 :: m2 :: midsRest), (x == n2) = false) ∧
  bn ≠ bcap ∧ bcap ≠ n1 ∧ bcap ≠ n2

/-! ### Lowering of `singletonBinOpWithCap_d0_dge3`:
   `[.roll (midsRest.length + 3), .opcode (binopOpcode opName rt),
     .push (.bool true)]`

The binOp loads `n1` (left) first: at depth 0, last-use → consume →
`bringToTop` emits `[]` (no-op), the stack map is unchanged. Then `n2`
(right) is loaded: at depth `d = midsRest.length + 3` of the unchanged
map → consume → `[.roll d]`. -/

set_option maxHeartbeats 4000000 in
set_option linter.unusedSimpArgs false in
private theorem lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (m : ANFMethod) (opName : String)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (hCap : singletonBinOpWithCap_d0_dge3 m opName n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hNotNeqBytes : (opName == "!==" && rt == some "bytes") = false) :
    lowerMethodUserRawOps progMethods props m
      = [.roll (midsRest.length + 3),
         .opcode (Stack.Lower.binopOpcode opName rt), .push (.bool true)] := by
  obtain ⟨hBody, hRev, hne12, hPre, _hBnCap, _hBcapN1, _hBcapN2⟩ := hCap
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  rw [computeLastUses_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap hne12]
  rw [collectConstInts_singletonBinOpWithCap opName bn bcap n1 n2 rt src srcCap]
  -- Load n1 at depth 0, consume-mode: no-op, sm unchanged.
  have hLoadN1 :
      Stack.Lower.loadRefLive
          (n1 :: m1 :: m2 :: midsRest ++ n2 :: tail) n1 0 [(n2, 0), (n1, 0)] []
        = ([], n1 :: m1 :: m2 :: midsRest ++ n2 :: tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n1, isLastUse_two_first n1 n2 hne12]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    have hFind1 : (n1 :: m1 :: m2 :: midsRest ++ n2 :: tail).findIdx? (· == n1) = some 0 := by
      simp only [List.cons_append]
      rw [List.findIdx?_cons]
      simp
    rw [hFind1]
    simp
  -- Load n2 at depth d of the unchanged sm: `[.roll d]`.
  have hLoadN2 :
      Stack.Lower.loadRefLive
          (n1 :: m1 :: m2 :: midsRest ++ n2 :: tail) n2 0 [(n2, 0), (n1, 0)] []
        = ([.roll (midsRest.length + 3)],
           n2 :: n1 :: m1 :: m2 :: midsRest ++ tail) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    rw [listContains_nil_local n2, isLastUse_two_second n1 n2]
    simp only [Bool.not_false, Bool.true_and]
    unfold Stack.Lower.StackMap.depth?
    have hFind2 :
        (n1 :: m1 :: m2 :: midsRest ++ n2 :: tail).findIdx? (· == n2)
          = some (n1 :: m1 :: m2 :: midsRest).length := by
      have := findIdx_skip_pre n2 (n1 :: m1 :: m2 :: midsRest) tail hPre
      simpa using this
    rw [hFind2]
    simp only [List.length_cons]
    have hRem :
        Stack.Lower.StackMap.removeAtDepth
            (n1 :: m1 :: m2 :: midsRest ++ n2 :: tail)
            (n1 :: m1 :: m2 :: midsRest).length
          = n1 :: m1 :: m2 :: midsRest ++ tail := by
      have := removeAt_skip_pre n2 (n1 :: m1 :: m2 :: midsRest) tail
      simpa using this
    simp only [List.length_cons] at hRem
    rw [hRem]
    rfl
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [hLoadN1]
  simp only [hLoadN2]
  rw [hNotNeqBytes]
  simp only [Bool.false_eq_true, if_false, reduceIte]
  unfold Stack.Lower.StackMap.popN
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  simp [Stack.Lower.lowerBindingsP, Stack.Lower.StackMap.push]

/-! ### `[.roll d]` post-load helper at depth pair (0, d ≥ 3)

From `agreesTagged` the left operand `a` sits on top (depth 0) and the
right operand `b` at depth `d = midTags.length + 1`. `runOps [.roll d]`
brings `b` to the top giving `b :: a :: (eraseIdx d).tail` — no swap
needed. -/

private theorem runOps_roll_post_state_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    ∃ midTail,
      Stack.Eval.runOps [.roll (midTags.length + 1)] initialStack
        = .ok ({initialStack with
                 stack := .vBigint b :: .vBigint a :: midTail}) := by
  have hAlign :
      taggedStackAligned ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest)
                         anfSt initialStack.stack := hAgrees.1
  -- Head extraction: top of stack is `.vBigint a` (n1 at depth 0).
  have hHead : ∃ rest0, initialStack.stack = .vBigint a :: rest0 := by
    match hCases : initialStack.stack with
    | [] => rw [hCases] at hAlign; simp [taggedStackAligned] at hAlign
    | topV :: rest0 =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        obtain ⟨hHd, _⟩ := hAlign
        have hHd' : anfSt.lookupParam n1 = some topV := hHd
        have hEq : topV = .vBigint a := by
          have : some topV = some (.vBigint a) := hHd'.symm.trans hLookupL
          exact Option.some.inj this
        exact ⟨rest0, by rw [hEq]⟩
  obtain ⟨rest0, hStk0⟩ := hHead
  -- Depth-d extraction: `n2` is at index `((n1,.param) :: midTags).length`.
  have hTsmShape :
      (n1, .param) :: midTags ++ (n2, .param) :: tsm_rest
        = ((n1, .param) :: midTags) ++ (n2, .param) :: tsm_rest := by
    simp
  have hAt :
      taggedStackAlignedAt (((n1, .param) :: midTags) ++ (n2, .param) :: tsm_rest)
        anfSt initialStack.stack n2 .param ((n1, .param) :: midTags).length := by
    apply taggedStackAlignedAt_of_taggedStackAligned
    rw [← hTsmShape]
    exact hAlign
  obtain ⟨v, hLkV, hLenV, hGetV⟩ := taggedStackAlignedAt_value _ anfSt _ n2 .param _ hAt
  have hVeq : v = .vBigint b := by
    have hLkV' : anfSt.lookupParam n2 = some v := hLkV
    have : some v = some (.vBigint b) := hLkV'.symm.trans hLookupR
    exact Option.some.inj this
  have hPreLen : ((n1, .param) :: midTags).length = midTags.length + 1 := by
    simp [List.length_cons]
  rw [hPreLen] at hLenV hGetV
  have hLenD : midTags.length + 1 < initialStack.stack.length := hLenV
  have hGetD : initialStack.stack[midTags.length + 1]! = .vBigint b := by
    rw [hGetV, hVeq]
  have hdpos : 1 ≤ midTags.length + 1 := Nat.le_add_left 1 midTags.length
  have hRoll :
      Stack.Eval.runOps [.roll (midTags.length + 1)] initialStack
        = .ok ({initialStack with
                 stack := initialStack.stack[midTags.length + 1]!
                            :: initialStack.stack.eraseIdx (midTags.length + 1)}) :=
    runOps_roll_postState initialStack (midTags.length + 1) hLenD
  have hEraseHead :
      initialStack.stack.eraseIdx (midTags.length + 1)
        = .vBigint a :: rest0.eraseIdx (midTags.length + 1 - 1) := by
    rw [hStk0]
    exact eraseIdx_cons_pos (.vBigint a) rest0 (midTags.length + 1) hdpos
  refine ⟨rest0.eraseIdx (midTags.length + 1 - 1), ?_⟩
  rw [hRoll, hGetD, hEraseHead]

/-! ### Per-kind runtime-success helpers at depth pair (0, d ≥ 3) -/

/-- Runtime success of `[.roll d, .opcode "OP_ADD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_add_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_ADD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_ADD" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a + b))) :=
    Stack.Sim.runOpcode_ADD_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_ADD"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a + b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_ADD" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_ADD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- **Method-level runtime-success wrapper for `+` at depth pair (0, d ≥ 3)
consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAdd_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "+" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "+" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "+" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("+" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "+" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_ADD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_add_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- Runtime success of `[.roll d, .opcode "OP_SUB", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_sub_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_SUB", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_SUB" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a - b))) :=
    Stack.Sim.runOpcode_SUB_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_SUB"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a - b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_SUB" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_SUB"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_MUL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_mul_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_MUL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MUL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * b))) :=
    Stack.Sim.runOpcode_MUL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_MUL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_MUL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_MUL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_DIV", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_div_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_DIV", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_DIV" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / b))) :=
    Stack.Sim.runOpcode_DIV_intInt_nonzero stkLoad a b midTail hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_DIV"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_DIV" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_DIV"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_MOD", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_mod_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_MOD", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_MOD" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a % b))) :=
    Stack.Sim.runOpcode_MOD_intInt_nonzero stkLoad a b midTail hStkLoad hNonzero
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_MOD"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a % b))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_MOD" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_MOD"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_LESSTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_lt_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_LESSTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHAN" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a < b)))) :=
    Stack.Sim.runOpcode_LESSTHAN_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_LESSTHAN"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a < b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_LESSTHAN" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_LESSTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_le_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LESSTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≤ b)))) :=
    Stack.Sim.runOpcode_LESSTHANOREQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_LESSTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≤ b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_LESSTHANOREQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_LESSTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_GREATERTHAN", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_gt_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_GREATERTHAN", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHAN" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a > b)))) :=
    Stack.Sim.runOpcode_GREATERTHAN_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_GREATERTHAN"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a > b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_GREATERTHAN" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_GREATERTHAN"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_ge_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_GREATERTHANOREQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≥ b)))) :=
    Stack.Sim.runOpcode_GREATERTHANOREQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_GREATERTHANOREQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≥ b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_GREATERTHANOREQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_GREATERTHANOREQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_NUMEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_eq_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_NUMEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMEQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a = b)))) :=
    Stack.Sim.runOpcode_NUMEQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_NUMEQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a = b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_NUMEQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_NUMEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_NUMNOTEQUAL", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_neq_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_NUMNOTEQUAL" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ b)))) :=
    Stack.Sim.runOpcode_NUMNOTEQUAL_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_NUMNOTEQUAL"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ b)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_NUMNOTEQUAL" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_NUMNOTEQUAL"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_BOOLAND", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_and_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_BOOLAND", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLAND" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLAND_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_BOOLAND"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_BOOLAND" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_BOOLAND"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_BOOLOR", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_or_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_BOOLOR", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_BOOLOR" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    Stack.Sim.runOpcode_BOOLOR_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_BOOLOR"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_BOOLOR" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_BOOLOR"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_LSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_shl_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_LSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_LSHIFT" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_LSHIFT_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_LSHIFT"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a * (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_LSHIFT" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_LSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-- Runtime success of `[.roll d, .opcode "OP_RSHIFT", .push (.bool true)]`
under `agreesTagged + two-int lookups` at depth pair (0, d ≥ 3). -/
private theorem runOps_roll_shr_pushTrue_of_agreesTagged_d0_dge3
    (n1 n2 : String) (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap)
    (anfSt : State) (initialStack : StackState) (a b : Int)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runOps
        [.roll (midTags.length + 1), .opcode "OP_RSHIFT", .push (.bool true)]
        initialStack).toOption.isSome := by
  obtain ⟨midTail, hLoad⟩ :=
    runOps_roll_post_state_d0_dge3 n1 n2 midTags tsm_rest anfSt initialStack a b
      hAgrees hLookupL hLookupR
  let stkLoad : StackState :=
    {initialStack with stack := .vBigint b :: .vBigint a :: midTail}
  have hStkLoad : stkLoad.stack = .vBigint b :: .vBigint a :: midTail := rfl
  have hOp :
      Stack.Eval.runOpcode "OP_RSHIFT" stkLoad
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    Stack.Sim.runOpcode_RSHIFT_intInt stkLoad a b midTail hStkLoad
  have hChain :
      Stack.Eval.runOps [.roll (midTags.length + 1), .opcode "OP_RSHIFT"] initialStack
        = .ok ({stkLoad with stack := midTail}.push (.vBigint (a / (2 ^ b.toNat)))) :=
    runOps_loadThenOpcode_unconditional [.roll (midTags.length + 1)]
      "OP_RSHIFT" initialStack stkLoad _ hLoad hOp
  show (Stack.Eval.runOps
          ([.roll (midTags.length + 1), .opcode "OP_RSHIFT"] ++ [.push (.bool true)])
          initialStack).toOption.isSome
  rw [Stack.Sim.runOps_append]
  rw [hChain]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Method-level wrappers at depth pair (0, d ≥ 3) for the remaining binops -/

/-- **Method-level runtime-success wrapper for `-` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinSub_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "-" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "-" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "-" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("-" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "-" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_SUB", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_sub_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `*` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMul_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "*" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "*" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "*" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("*" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "*" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_MUL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_mul_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `/` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinDiv_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "/" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "/" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "/" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("/" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "/" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_DIV", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_div_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `%` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinMod_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "%" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b))
    (hNonzero : b ≠ 0) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "%" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "%" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("%" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "%" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_MOD", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_mod_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR hNonzero

/-- **Method-level runtime-success wrapper for `<` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLt_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_LESSTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_lt_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<=` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinLe_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "<=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "<=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_LESSTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_le_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGt_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m ">" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m ">" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_GREATERTHAN", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_gt_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>=` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinGe_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m ">=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">=" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">=" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">=" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m ">=" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_GREATERTHANOREQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_ge_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `===` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinEq_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "===" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "===" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "===" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("===" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "===" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "===" rt = "OP_NUMEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_NUMEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_eq_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `!==` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinNeq_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "!==" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hRtNotBytes : rt ≠ some "bytes")
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "!==" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "!==" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("!==" == "!==") && rt == some "bytes") = false := by
    have hRt : (rt == some "bytes") = false := by
      cases hRt' : rt with
      | none => rfl
      | some s =>
          by_cases hBytes : s = "bytes"
          · exact absurd (by rw [hRt', hBytes]) hRtNotBytes
          · simp [hBytes]
    simp [hRt]
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "!==" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hOpcode : Stack.Lower.binopOpcode "!==" rt = "OP_NUMNOTEQUAL" := by
    unfold Stack.Lower.binopOpcode
    cases hRt : rt with
    | none => rfl
    | some s =>
        by_cases hBytes : s = "bytes"
        · exact absurd (by rw [hRt, hBytes]) hRtNotBytes
        · simp [hBytes]
  rw [hOpcode]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_NUMNOTEQUAL", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_neq_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `&&` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinAnd_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "&&" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "&&" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "&&" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("&&" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "&&" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_BOOLAND", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_and_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `||` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinOr_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "||" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "||" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "||" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("||" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "||" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_BOOLOR", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_or_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `<<` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShl_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m "<<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp "<<" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap "<<" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : (("<<" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m "<<" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_LSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_shl_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-- **Method-level runtime-success wrapper for `>>` at depth pair
(0, d ≥ 3) consume.** -/
theorem runMethod_lower_public_unique_no_post_singletonBinShr_d0_dge3_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (n1 n2 m1 m2 bn bcap : String) (midsRest tail : List String)
    (rt : Option String) (src srcCap : Option SourceLoc)
    (midTags : TaggedStackMap) (tsm_rest : TaggedStackMap) (anfSt : State) (a b : Int)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hCap : singletonBinOpWithCap_d0_dge3 m ">>" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap)
    (hMidLen : midTags.length = midsRest.length + 2)
    (hAgrees : agreesTagged
      ((n1, .param) :: midTags ++ (n2, .param) :: tsm_rest) anfSt initialStack)
    (hLookupL : anfSt.lookupParam n1 = some (.vBigint a))
    (hLookupR : anfSt.lookupParam n2 = some (.vBigint b)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  have hBody : m.body = [⟨bn, .binOp ">>" n1 n2 rt, src⟩,
                          ⟨bcap, .loadConst (.bool true), srcCap⟩] := hCap.1
  have hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoCode : Stack.Lower.bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  have hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_singletonBinOpWithCap ">>" bn bcap n1 n2 rt src srcCap
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  have hNotNeqBytes : ((">>" == "!==") && rt == some "bytes") = false := by
    simp
  rw [lowerMethodUserRawOps_singletonBinOpWithCap_d0_dge3
        methods props m ">>" n1 n2 m1 m2 bn bcap midsRest tail rt src srcCap hCap hNotNeqBytes]
  have hDepthEq : midsRest.length + 3 = midTags.length + 1 := by omega
  rw [hDepthEq]
  show (Stack.Eval.runOps
          [.roll (midTags.length + 1), .opcode "OP_RSHIFT", .push (.bool true)]
          initialStack).toOption.isSome
  exact runOps_roll_shr_pushTrue_of_agreesTagged_d0_dge3 n1 n2 midTags tsm_rest
    anfSt initialStack a b hAgrees hLookupL hLookupR

/-! ### Wave 14 — non-vacuity smoke tests (consumability proofs)

The depth-`d` runtime helpers above must not be vacuously true. Each
smoke test below builds a CONCRETE `agreesTagged` witness at `d = 3`
(`midTags = [(m1,.param), (m2,.param)]`) over a real `State` / runtime
stack, discharges the helper's hypotheses, and shows the helper's
post-load conclusion goes through end-to-end with `n1 ↦ a`, `n2 ↦ b`. If
a smoke test failed to compile, the corresponding runtime helper would
carry contradictory hypotheses and be inconsumable. -/

/-- Concrete d=3 model: params `n2`(0) `m1`(1) `m2`(2) `n1`(3); the
runtime stack carries the matching values (`b = 7` on top, `a = 5` at
depth 3). -/
private theorem _smoke_agrees_dge3_d0 :
    agreesTagged
      (("n2", .param) :: [("m1", .param), ("m2", .param)] ++ ("n1", .param) :: [])
      ({ (default : State) with
          params := [("n2", .vBigint 7), ("m1", .vBigint 0),
                     ("m2", .vBigint 0), ("n1", .vBigint 5)] })
      ({ (default : StackState) with
          stack := [.vBigint 7, .vBigint 0, .vBigint 0, .vBigint 5] }) := by
  refine ⟨?_, rfl, rfl⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  refine ⟨rfl, ?_⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  refine ⟨rfl, ?_⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  refine ⟨rfl, ?_⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  exact ⟨rfl, trivial⟩

/-- Non-vacuity for `runOps_rollSwap_post_state_dge3_d0`: the helper fires
on the concrete `d = 3` model, yielding the `b :: a :: midTail` post-load
shape (`b = 7`, `a = 5`). -/
private theorem _smoke_postState_dge3_d0 :
    ∃ midTail,
      Stack.Eval.runOps
        [.roll (([("m1", SlotKind.param), ("m2", .param)] : TaggedStackMap).length + 1),
         .swap]
        ({ (default : StackState) with
            stack := [.vBigint 7, .vBigint 0, .vBigint 0, .vBigint 5] })
        = .ok ({ ({ (default : StackState) with
                    stack := [.vBigint 7, .vBigint 0, .vBigint 0, .vBigint 5] })
                  with stack := .vBigint 7 :: .vBigint 5 :: midTail }) :=
  runOps_rollSwap_post_state_dge3_d0 "n1" "n2" [("m1", .param), ("m2", .param)] []
    ({ (default : State) with
        params := [("n2", .vBigint 7), ("m1", .vBigint 0),
                   ("m2", .vBigint 0), ("n1", .vBigint 5)] })
    ({ (default : StackState) with
        stack := [.vBigint 7, .vBigint 0, .vBigint 0, .vBigint 5] })
    5 7 _smoke_agrees_dge3_d0 rfl rfl

/-- Concrete d=3 model for the (0, d) pair: params `n1`(0) `m1`(1)
`m2`(2) `n2`(3); the runtime stack carries the matching values (`a = 5`
on top, `b = 7` at depth 3). -/
private theorem _smoke_agrees_d0_dge3 :
    agreesTagged
      (("n1", .param) :: [("m1", .param), ("m2", .param)] ++ ("n2", .param) :: [])
      ({ (default : State) with
          params := [("n1", .vBigint 5), ("m1", .vBigint 0),
                     ("m2", .vBigint 0), ("n2", .vBigint 7)] })
      ({ (default : StackState) with
          stack := [.vBigint 5, .vBigint 0, .vBigint 0, .vBigint 7] }) := by
  refine ⟨?_, rfl, rfl⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  refine ⟨rfl, ?_⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  refine ⟨rfl, ?_⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  refine ⟨rfl, ?_⟩
  unfold taggedStackAligned lookupAnfByKind State.lookupParam
  exact ⟨rfl, trivial⟩

/-- Non-vacuity for `runOps_roll_post_state_d0_dge3`: the helper fires on
the concrete `d = 3` model, yielding the `b :: a :: midTail` post-load
shape (`b = 7`, `a = 5`). -/
private theorem _smoke_postState_d0_dge3 :
    ∃ midTail,
      Stack.Eval.runOps
        [.roll (([("m1", SlotKind.param), ("m2", .param)] : TaggedStackMap).length + 1)]
        ({ (default : StackState) with
            stack := [.vBigint 5, .vBigint 0, .vBigint 0, .vBigint 7] })
        = .ok ({ ({ (default : StackState) with
                    stack := [.vBigint 5, .vBigint 0, .vBigint 0, .vBigint 7] })
                  with stack := .vBigint 7 :: .vBigint 5 :: midTail }) :=
  runOps_roll_post_state_d0_dge3 "n1" "n2" [("m1", .param), ("m2", .param)] []
    ({ (default : State) with
        params := [("n1", .vBigint 5), ("m1", .vBigint 0),
                   ("m2", .vBigint 0), ("n2", .vBigint 7)] })
    ({ (default : StackState) with
        stack := [.vBigint 5, .vBigint 0, .vBigint 0, .vBigint 7] })
    5 7 _smoke_agrees_d0_dge3 rfl rfl

end Agrees
end RunarVerification.Stack

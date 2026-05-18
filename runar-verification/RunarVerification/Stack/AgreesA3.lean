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

end Agrees
end RunarVerification.Stack

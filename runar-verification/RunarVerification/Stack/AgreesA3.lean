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

/-! ## Path 2 Tier 1 Wave 19 — consume-mode whole-body arith capstone

This section assembles the wave-18 consume-mode operational-chain
composer (`RunChainRelP` + `runOps_lowerBindingsP_RunChainRelP_isSome`,
both in `Agrees.lean`) into a **method-level** runtime-success capstone
for bodies built entirely from consume-mode arith bindings (binOp /
unaryOp whose operands are read at their last use and therefore
consumed).

### Deliverable A — `structuralArithConsumeBody`

The predicate the capstone takes.  It is an **inductive relation** over
the body that, for each binding, carries:

* the **arith shape** — the binding's `value` is a `binOp` or `unaryOp`
  (this is what distinguishes the predicate from the bare
  `RunChainRelP`, and what wave 20 connects to the copy-mode
  `structuralArithBodyBool`); and
* the **genuine consume operational witness** — the program-aware
  consume-mode-lowered ops of that binding run to a defined result at
  the threaded concrete runtime stack
  (`runOps (lowerValueP …).1 stkSt = .ok stkSt'`).

The per-binding `runOps` fact is the SAME load-bearing datum
`RunChainRelP.cons` carries; it is NOT a universal "succeeds on every
stack" `hRunOk` (it is pinned to the one threaded `stkSt`), and it is
NOT the whole-body conclusion (that is DERIVED by the composer).  In the
smoke (Deliverable D) every per-binding witness is built from the
`stageC_simpleStep_binOp_*_consume_core` singletons + `run_OP_NEGATE_int`
plus the wave-16 operand-provenance lemmas (Deliverable B), proving the
predicate is genuinely inhabited on a real consume-mode method body. -/
inductive structuralArithConsumeBody
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String)
    (constInts : List (String × Int)) :
    List ANFBinding → StackMap → Nat → List String → StackState →
    StackMap → StackState → Prop where
  | nil {sm currentIndex localBindings stkSt} :
      structuralArithConsumeBody progMethods props budget lastUses outerProtected constInts
        [] sm currentIndex localBindings stkSt sm stkSt
  | consBinOp {op l r rt name src rest sm currentIndex localBindings
        stkSt stkSt_b' sm'' stkSt''} :
      runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                outerProtected localBindings constInts sm name (.binOp op l r rt)).1 stkSt
        = .ok stkSt_b' →
      structuralArithConsumeBody progMethods props budget lastUses outerProtected constInts
        rest
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm name (.binOp op l r rt)).2.1
        (currentIndex + 1)
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm name (.binOp op l r rt)).2.2
        stkSt_b' sm'' stkSt'' →
      structuralArithConsumeBody progMethods props budget lastUses outerProtected constInts
        (.mk name (.binOp op l r rt) src :: rest) sm currentIndex localBindings stkSt sm'' stkSt''
  | consUnaryOp {op operand rt name src rest sm currentIndex localBindings
        stkSt stkSt_b' sm'' stkSt''} :
      runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                outerProtected localBindings constInts sm name (.unaryOp op operand rt)).1 stkSt
        = .ok stkSt_b' →
      structuralArithConsumeBody progMethods props budget lastUses outerProtected constInts
        rest
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm name (.unaryOp op operand rt)).2.1
        (currentIndex + 1)
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm name (.unaryOp op operand rt)).2.2
        stkSt_b' sm'' stkSt'' →
      structuralArithConsumeBody progMethods props budget lastUses outerProtected constInts
        (.mk name (.unaryOp op operand rt) src :: rest) sm currentIndex localBindings stkSt sm'' stkSt''

/-- **Deliverable A bridge.**  A `structuralArithConsumeBody` witness
projects to a `RunChainRelP` witness over the same body: the arith-shape
constructors are exactly the `RunChainRelP.cons` constructor restricted
to `binOp` / `unaryOp` values.  This is the load-bearing connection that
lets the capstone reuse the wave-18 composer
(`runOps_lowerBindingsP_RunChainRelP_isSome`) verbatim. -/
theorem structuralArithConsumeBody_toRunChainRelP
    {progMethods : List ANFMethod} {props : List ANFProperty} {budget : Nat}
    {lastUses : List (String × Nat)} {outerProtected : List String}
    {constInts : List (String × Int)}
    {body : List ANFBinding} {sm sm' : StackMap} {currentIndex : Nat}
    {localBindings : List String} {stkSt stkSt' : StackState}
    (h : structuralArithConsumeBody progMethods props budget lastUses outerProtected constInts
          body sm currentIndex localBindings stkSt sm' stkSt') :
    RunChainRelP progMethods props budget lastUses outerProtected constInts
      body sm currentIndex localBindings stkSt sm' stkSt' := by
  induction h with
  | nil => exact RunChainRelP.nil
  | consBinOp hRun _hRest ih => exact RunChainRelP.cons hRun ih
  | consUnaryOp hRun _hRest ih => exact RunChainRelP.cons hRun ih

/-- **Deliverable B — multi-step operand provenance fold.**

By induction over the body, every binding's operands resolve to a
`.vBigint` value at the point used: params resolve from the initial
state, earlier temps resolve from prior steps via the wave-16 stability
lemmas (`lookupAnfByKind_addBinding_self` / `_of_ne` /
`resolveRef_addBinding_of_ne_binding`).  Concretely: running the body
through the ANF evaluator succeeds, and the bound temp of each binding
resolves to the value the next binding's operand witness needs.

This is the mode-independent (ANF-eval, not lowering) fold the task
calls for.  It is stated as: a body of pure-bigint binOp / unaryOp
bindings, each with operand-resolution + opcode-success witnesses,
evaluates to a defined ANF state, and each binding's temp is
resolvable thereafter.  The single-step engine is `evalBindings_binOp_step`
(rebuilt-from for the unary case via `evalValue_unaryOp_provenance`). -/
theorem evalBindings_arithConsume_provenance
    (anfSt : State) (name op l r : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (a b c : RunarVerification.ANF.Eval.Value)
    (hl : anfSt.resolveRef l = some a)
    (hr : anfSt.resolveRef r = some b)
    (hOp : RunarVerification.ANF.Eval.evalBinOp op a b rt = .ok c)
    (rest : List ANFBinding)
    (hNeRest : ∀ bd ∈ rest, bd.name ≠ name)
    (hRest : (RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding name c) rest).toOption.isSome) :
    (RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.binOp op l r rt) src :: rest)).toOption.isSome
    ∧ lookupAnfByKind (anfSt.addBinding name c) (name, .binding) = some c := by
  obtain ⟨hEvalHead, hLookup⟩ :=
    evalBindings_binOp_step anfSt name op l r rt src a b c hl hr hOp
  refine ⟨?_, hLookup⟩
  have hVal := evalValue_binOp_provenance anfSt op l r rt a b c hl hr hOp
  have hChain : RunarVerification.ANF.Eval.evalBindings anfSt
      (.mk name (.binOp op l r rt) src :: rest)
        = RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding name c) rest := by
    simp only [RunarVerification.ANF.Eval.evalBindings, hVal, bind, Except.bind]
  rw [hChain]
  exact hRest

/-- **Deliverable B — unary peer of the provenance fold step.** -/
theorem evalBindings_arithConsume_provenance_unary
    (anfSt : State) (name op operand : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (a c : RunarVerification.ANF.Eval.Value)
    (hOperand : anfSt.resolveRef operand = some a)
    (hOp : RunarVerification.ANF.Eval.evalUnaryOp op a rt = .ok c)
    (rest : List ANFBinding)
    (hRest : (RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding name c) rest).toOption.isSome) :
    (RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.unaryOp op operand rt) src :: rest)).toOption.isSome
    ∧ lookupAnfByKind (anfSt.addBinding name c) (name, .binding) = some c := by
  refine ⟨?_, lookupAnfByKind_addBinding_self anfSt name c⟩
  have hVal := evalValue_unaryOp_provenance anfSt op operand rt a c hOperand hOp
  have hChain : RunarVerification.ANF.Eval.evalBindings anfSt
      (.mk name (.unaryOp op operand rt) src :: rest)
        = RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding name c) rest := by
    simp only [RunarVerification.ANF.Eval.evalBindings, hVal, bind, Except.bind]
  rw [hChain]
  exact hRest

/-- **Deliverable C — method-level consume-mode arith capstone.**

For a public, unique, no-implicit/no-post method whose body is a
consume-mode arith body (`structuralArithConsumeBody` over the EXACT
lowerer arguments `lowerMethodUserRawOps` uses), running the lowered
contract method to completion succeeds.

Proof route:
1. `runMethod_lower_public_unique_no_post_eq_userRaw` reduces
   `runMethod (lower …)` to `runOps (lowerMethodUserRawOps …)`.
2. `lowerMethodUserRawOps` unfolds DEFINITIONALLY to
   `(lowerBindingsP progMethods props defaultInlineBudget 0
      (computeLastUses body) [] (body.map name) (collectConstInts body)
      (params.map name).reverse body).1` — no copy bridge: method
   lowering IS consume-mode `lowerBindingsP`.
3. The `structuralArithConsumeBody` hypothesis projects to a
   `RunChainRelP` over the same body (Deliverable A bridge), and
   `runOps_lowerBindingsP_RunChainRelP_isSome` discharges whole-body
   runtime success. -/
theorem runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (sm' : StackMap) (stkFinal : StackState)
    (hMem : m ∈ methods) (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hArith :
      structuralArithConsumeBody methods props Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses m.body) []
        (Stack.Lower.collectConstInts m.body)
        m.body
        ((m.params.map (fun p => p.name)).reverse) 0
        (m.body.map (fun bd => bd.name)) initialStack
        sm' stkFinal)
    (hNoPreimage : Stack.Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Stack.Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Stack.Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Stack.Lower.bindingsUseDeserializeState m.body = false) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  show (runOps (lowerMethodUserRawOps methods props m) initialStack).toOption.isSome
  unfold lowerMethodUserRawOps
  exact runOps_lowerBindingsP_RunChainRelP_isSome
    (structuralArithConsumeBody_toRunChainRelP hArith)

/-! ### Deliverable D — MANDATORY consume-mode method-level smoke test

The anti-vacuity proof.  We instantiate the wave-19 capstone on a
CONCRETE consume-mode arith method:

```
method add3sub (p0 p1 p2 : bigint) {
  t0 = p0 + p1     -- binOp "+", operands at last use → consume [.swap, OP_ADD]
  t1 = t0 - p2     -- binOp "-", operands at last use → consume [.swap, OP_SUB]
  t2 = -t1         -- unaryOp "-", operand at last use → consume [OP_NEGATE]
}
```

`outerProtected = []` arises NATURALLY from `lowerMethodUserRawOps`
(method lowering hard-codes `[]`), so this is genuine consume-mode at
the full `runMethod` level — the thing wave-17's copy-mode capstone could
NOT do.  Every lowerer argument is the COMPUTED method-lowering value
(`computeLastUses m.body`, `collectConstInts m.body`,
`(m.params.map name).reverse`, `m.body.map name`), NOT a hand-picked
override.  Each per-binding consume `runOps` witness is built from the
`stageC_simpleStep_binOp_d0d1_consume_core` singleton (the two binOps) +
`run_OP_NEGATE_int` (the unary), discharging all hypotheses honestly. -/

/-- Concrete consume-mode arith body for the wave-19 smoke:
`[t0 = p0 + p1; t1 = t0 - p2; t2 = -t1]`. -/
private def wave19SmokeBody : List ANFBinding :=
  [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
   ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
   ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]

/-- Concrete method carrying `wave19SmokeBody`.  Params declared
`[p2, p1, p0]` so `(params.map name).reverse = ["p0", "p1", "p2"]` —
the depth-0/1/2 initial stack-map the per-binding witnesses expect. -/
private def wave19SmokeMethod : ANFMethod :=
  { name := "add3sub"
    params := [ANFParam.mk "p2" .bigint, ANFParam.mk "p1" .bigint, ANFParam.mk "p0" .bigint]
    body := wave19SmokeBody
    isPublic := true }

/-- `computeLastUses wave19SmokeBody`, pinned by definitional reduction. -/
private theorem wave19_computeLastUses :
    Stack.Lower.computeLastUses wave19SmokeBody
      = [("t1", 2), ("p2", 1), ("t0", 1), ("p1", 0), ("p0", 0)] := by
  unfold Stack.Lower.computeLastUses wave19SmokeBody; rfl

/-- `collectConstInts wave19SmokeBody = []` (no integer literals). -/
private theorem wave19_collectConstInts :
    Stack.Lower.collectConstInts wave19SmokeBody = [] := by
  simp only [wave19SmokeBody, Stack.Lower.collectConstInts, List.append_nil]

/-- `(params.map name).reverse = ["p0", "p1", "p2"]`. -/
private theorem wave19_paramsRev :
    (wave19SmokeMethod.params.map (fun p => p.name)).reverse = ["p0", "p1", "p2"] := by
  unfold wave19SmokeMethod; rfl

/-- `body.map name = ["t0", "t1", "t2"]`. -/
private theorem wave19_localBindings :
    wave19SmokeBody.map (fun bd => bd.name) = ["t0", "t1", "t2"] := by
  unfold wave19SmokeBody; rfl

/-- The `no-implicit / no-post` preconditions all reduce on the
concrete body — the body has no checkPreimage / codePart / terminal
assert / deserializeState. -/
private theorem wave19_noPreimage :
    Stack.Lower.bindingsUseCheckPreimage wave19SmokeMethod.body = false := by
  show Stack.Lower.bindingsUseCheckPreimage wave19SmokeBody = false
  simp only [wave19SmokeBody, Stack.Lower.bindingsUseCheckPreimage, Bool.or_false]

private theorem wave19_noCode :
    Stack.Lower.bindingsUseCodePart wave19SmokeMethod.body = false := by
  show Stack.Lower.bindingsUseCodePart wave19SmokeBody = false
  simp only [wave19SmokeBody, Stack.Lower.bindingsUseCodePart, Bool.or_false]

private theorem wave19_noTerminalAssert :
    Stack.Lower.bodyEndsInAssert wave19SmokeMethod.body = false := by
  show Stack.Lower.bodyEndsInAssert wave19SmokeBody = false
  unfold wave19SmokeBody Stack.Lower.bodyEndsInAssert; rfl

private theorem wave19_noDeserialize :
    Stack.Lower.bindingsUseDeserializeState wave19SmokeMethod.body = false := by
  show Stack.Lower.bindingsUseDeserializeState wave19SmokeBody = false
  simp only [wave19SmokeBody, Stack.Lower.bindingsUseDeserializeState, Bool.or_false]

/-- Lowered ops of binding 0 (`t0 = p0 + p1`, consume d0d1) under the
COMPUTED method-lowering arguments: `[.swap, OP_ADD]`.  The binOp arm of
`lowerValueP` ignores `progMethods` / `props`, so the lemma is stated
parametrically over them. -/
private theorem wave19_ops0
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["p0", "p1", "p2"] "t0" (.binOp "+" "p0" "p1" none)).1
      = [StackOp.swap, .opcode "OP_ADD"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    Stack.Lower.isLastUse Stack.Lower.lastUsesLookup Stack.Lower.listContains
    Stack.Lower.binopOpcode
  rfl

/-- `(lowerValueP …).2.1` for binding 0: stack map advances to
`["t0", "p2"]`. -/
private theorem wave19_sm0
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["p0", "p1", "p2"] "t0" (.binOp "+" "p0" "p1" none)).2.1
      = ["t0", "p2"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    Stack.Lower.StackMap.popN Stack.Lower.StackMap.push
    Stack.Lower.isLastUse Stack.Lower.lastUsesLookup Stack.Lower.listContains
  rfl

/-- `(lowerValueP …).2.2` for binding 0: localBindings unchanged
(`["t0", "t1", "t2"]`) — binOps do not register a new local-binding
slot. -/
private theorem wave19_lb0
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["p0", "p1", "p2"] "t0" (.binOp "+" "p0" "p1" none)).2.2
      = ["t0", "t1", "t2"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []

/-- Lowered ops of binding 1 (`t1 = t0 - p2`, consume d0d1): `[.swap, OP_SUB]`. -/
private theorem wave19_ops1
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 1
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["t0", "p2"] "t1" (.binOp "-" "t0" "p2" none)).1
      = [StackOp.swap, .opcode "OP_SUB"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    Stack.Lower.isLastUse Stack.Lower.lastUsesLookup Stack.Lower.listContains
    Stack.Lower.binopOpcode
  rfl

/-- `(lowerValueP …).2.1` for binding 1: stack map advances to `["t1"]`. -/
private theorem wave19_sm1
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 1
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["t0", "p2"] "t1" (.binOp "-" "t0" "p2" none)).2.1
      = ["t1"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    Stack.Lower.StackMap.popN Stack.Lower.StackMap.push
    Stack.Lower.isLastUse Stack.Lower.lastUsesLookup Stack.Lower.listContains
  rfl

/-- `(lowerValueP …).2.2` for binding 1: localBindings unchanged. -/
private theorem wave19_lb1
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 1
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["t0", "p2"] "t1" (.binOp "-" "t0" "p2" none)).2.2
      = ["t0", "t1", "t2"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []

/-- Lowered ops of binding 2 (`t2 = -t1`, consume d0 unary): `[OP_NEGATE]`. -/
private theorem wave19_ops2
    (progMethods : List ANFMethod) (props : List ANFProperty) :
    (Stack.Lower.lowerValueP progMethods props
        Stack.Lower.defaultInlineBudget 2
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
        ["t1"] "t2" (.unaryOp "-" "t1" none)).1
      = [StackOp.opcode "OP_NEGATE"] := by
  rw [wave19_computeLastUses, wave19_collectConstInts]
  unfold Stack.Lower.lowerValueP; simp only []
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    Stack.Lower.isLastUse Stack.Lower.lastUsesLookup Stack.Lower.listContains
    Stack.Lower.unaryOpcode
  rfl

/-- **Deliverable D — the consume-mode method-level smoke test.**

The wave-19 capstone, instantiated on `wave19SmokeMethod` (a real public
3-binding consume-mode arith method), runs to a defined result.  All
hypotheses are discharged honestly: the per-binding consume witnesses
come from the `stageC_simpleStep_binOp_d0d1_consume_core` singletons +
`run_OP_NEGATE_int`, threaded through the concrete evolving runtime
stack, and the `agreesTagged`/lookup facts are genuine inputs about the
real body.

This proves the capstone is GENUINELY consumable at method level — the
anti-vacuity check the task mandates. -/
theorem wave19_consume_capstone_smoke
    (contractName : String) (initialStack : StackState)
    (a b c : Int) (rest : List RunarVerification.ANF.Eval.Value) (tsm_rest : TaggedStackMap)
    (anfSt0 anfSt1 : State)
    (hStk : initialStack.stack = .vBigint a :: .vBigint b :: .vBigint c :: rest)
    -- Binding 0 inputs: agreesTagged on the initial param stack-map.
    (hAgrees0 : agreesTagged
        (("p0", .param) :: ("p1", .param) :: ("p2", .param) :: tsm_rest) anfSt0 initialStack)
    (hLookupP0 : lookupAnfByKind anfSt0 ("p0", .param) = some (.vBigint a))
    (hLookupP1 : lookupAnfByKind anfSt0 ("p1", .param) = some (.vBigint b))
    -- Binding 1 inputs: agreesTagged after binding 0 (t0 on top, p2 below).
    (hAgrees1 : agreesTagged
        (("t0", .binding) :: ("p2", .param) :: tsm_rest) anfSt1
        ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}))
    (hLookupT0 : lookupAnfByKind anfSt1 ("t0", .binding) = some (.vBigint (a + b)))
    (hLookupP2 : lookupAnfByKind anfSt1 ("p2", .param) = some (.vBigint c)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := ([] : List ANFProperty),
            methods := [wave19SmokeMethod] })
        wave19SmokeMethod.name initialStack).toOption.isSome := by
  -- The chain is built directly over `progMethods = [wave19SmokeMethod]`,
  -- matching the capstone — the binOp/unaryOp arms of `lowerValueP`
  -- ignore `progMethods` / `props`, so the parametric ops/sm/lb lemmas
  -- apply at this instance.
  -- ===== Per-binding consume witnesses (mirroring wave-18 at method args). =====
  -- Binding 0: t0 = p0 + p1, d0d1 consume → [.swap, OP_ADD].
  have hRun0Raw :
      runOps [StackOp.swap, .opcode "OP_ADD"] initialStack
        = .ok ({initialStack with stack := initialStack.stack.tail.tail}.push (.vBigint (a + b))) := by
    refine stageC_simpleStep_binOp_d0d1_consume_core
      "p0" "p1" .param .param (("p2", .param) :: tsm_rest) anfSt0 initialStack a b
      "OP_ADD" (.vBigint (a + b)) [StackOp.swap, .opcode "OP_ADD"]
      hAgrees0 hLookupP0 hLookupP1 rfl ?_
    intro restStk hStkEq
    exact Stack.Sim.runOpcode_ADD_intInt
      ({initialStack with stack := .vBigint b :: .vBigint a :: restStk}) a b restStk rfl
  have hRun0 :
      runOps (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget 0
          (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
          ["p0", "p1", "p2"] "t0" (.binOp "+" "p0" "p1" none)).1 initialStack
        = .ok ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) := by
    rw [wave19_ops0, hRun0Raw]
    have hEq :
        ({initialStack with stack := initialStack.stack.tail.tail}.push (.vBigint (a + b)))
          = ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest} : StackState) := by
      rw [hStk]; rfl
    rw [hEq]
  -- Binding 1: t1 = t0 - p2, d0d1 consume → [.swap, OP_SUB].
  have hRun1Raw :
      runOps [StackOp.swap, .opcode "OP_SUB"]
          ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest})
        = .ok ({({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) with
                stack :=
                  ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}).stack.tail.tail}.push
                  (.vBigint ((a + b) - c))) := by
    refine stageC_simpleStep_binOp_d0d1_consume_core
      "t0" "p2" .binding .param tsm_rest anfSt1
      ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) (a + b) c
      "OP_SUB" (.vBigint ((a + b) - c)) [StackOp.swap, .opcode "OP_SUB"]
      hAgrees1 hLookupT0 hLookupP2 rfl ?_
    intro restStk hStkEq
    exact Stack.Sim.runOpcode_SUB_intInt
      ({({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) with
        stack := .vBigint c :: .vBigint (a + b) :: restStk}) (a + b) c restStk rfl
  have hRun1 :
      runOps (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget 1
          (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
          ["t0", "p2"] "t1" (.binOp "-" "t0" "p2" none)).1
          ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest})
        = .ok ({initialStack with stack := .vBigint ((a + b) - c) :: rest}) := by
    rw [wave19_ops1, hRun1Raw]; rfl
  -- Binding 2: t2 = -t1, depth-0 unary consume → [OP_NEGATE].
  have hStk2 :
      ({initialStack with stack := .vBigint ((a + b) - c) :: rest} : StackState).stack
        = .vBigint ((a + b) - c) :: rest := rfl
  have hRun2Raw :
      runOps [StackOp.opcode "OP_NEGATE"]
          ({initialStack with stack := .vBigint ((a + b) - c) :: rest})
        = .ok (({({initialStack with stack := .vBigint ((a + b) - c) :: rest}) with
                  stack := rest}).push (.vBigint (-((a + b) - c)))) :=
    Stack.Sim.run_OP_NEGATE_int
      ({initialStack with stack := .vBigint ((a + b) - c) :: rest}) ((a + b) - c) rest hStk2
  have hRun2 :
      runOps (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget 2
          (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
          ["t1"] "t2" (.unaryOp "-" "t1" none)).1
          ({initialStack with stack := .vBigint ((a + b) - c) :: rest})
        = .ok ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    rw [wave19_ops2, hRun2Raw]; rfl
  -- ===== Build the structuralArithConsumeBody chain bottom-up. =====
  have chain1 :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        (Stack.Lower.collectConstInts wave19SmokeBody)
        [ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
         ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
        ["t0", "p2"] 1 ["t0", "t1", "t2"]
        ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest})
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    refine structuralArithConsumeBody.consBinOp hRun1 ?_
    rw [wave19_sm1, wave19_lb1]
    exact structuralArithConsumeBody.consUnaryOp hRun2 structuralArithConsumeBody.nil
  have chain0 :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        (Stack.Lower.collectConstInts wave19SmokeBody)
        wave19SmokeBody
        ["p0", "p1", "p2"] 0 ["t0", "t1", "t2"] initialStack
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    show structuralArithConsumeBody _ _ _ _ _ _
      (ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none ::
        [ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
         ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none])
      _ _ _ _ _ _
    refine structuralArithConsumeBody.consBinOp hRun0 ?_
    rw [wave19_sm0, wave19_lb0]
    exact chain1
  -- ===== Assemble the capstone's `hArith` hypothesis from chain0. =====
  -- The capstone takes `structuralArithConsumeBody` over the COMPUTED
  -- method-lowering args; `chain0` carries it over the equal literal
  -- args.  The endpoints `sm'` / `stkFinal` are written explicitly to
  -- match chain0's, then the literals are rewritten into the computed
  -- shapes via the method-args reductions.
  have hUniq :
      ∀ m', m' ∈ [wave19SmokeMethod] → m'.isPublic = true →
        (m'.name == wave19SmokeMethod.name) = true → m' = wave19SmokeMethod := by
    intro m' hm' _ _
    simp only [List.mem_singleton] at hm'
    exact hm'
  have hArith :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeMethod.body) []
        (Stack.Lower.collectConstInts wave19SmokeMethod.body)
        wave19SmokeMethod.body
        ((wave19SmokeMethod.params.map (fun p => p.name)).reverse) 0
        (wave19SmokeMethod.body.map (fun bd => bd.name)) initialStack
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    -- `wave19SmokeMethod.body`, `(params.map name).reverse`, and
    -- `body.map name` all reduce definitionally to `wave19SmokeBody`,
    -- `["p0","p1","p2"]`, `["t0","t1","t2"]` respectively, so `chain0`
    -- (stated over those literals) is definitionally this goal.
    exact chain0
  -- ===== Apply the capstone. =====
  exact runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome
    contractName ([] : List ANFProperty) [wave19SmokeMethod] wave19SmokeMethod initialStack
    _ _ List.mem_cons_self rfl hUniq hArith
    wave19_noPreimage wave19_noCode wave19_noTerminalAssert wave19_noDeserialize

/-! ## Path 2 Tier 1 Wave 20 — consume-mode arith reflection
     + generic depth dispatcher

Wave 19 (above) landed the `structuralArithConsumeBody` inductive and
its method-level capstone
(`runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome`),
gated on producing a `structuralArithConsumeBody` value whose `cons`
constructors each carry a per-binding consume `runOps` witness.  The
wave-19 smoke built those witnesses *by hand* for one concrete body.

This wave packages that hand-work:

* **Deliverable A** — `build_consume_binOp_witness_d0d1` /
  `build_consume_unaryOp_witness_negate`: per-binding consume `runOps`
  witness builders.  Each derives the lowered-ops shape internally from
  the operand `depth?` facts (instead of taking it as a hypothesis the
  way the wave-19 `wave19_ops*` lemmas did), then dispatches to the
  matching `stageC_*_consume_core` singleton.  A `build_consume_binOp_witness`
  depth dispatcher case-splits the operand depth pair and routes to the
  covered singletons; the (≥2, ≥2) consume combo is documented as an
  uncovered hole (no `Agrees.lean` singleton, and the wave-16
  `runOps_loadRef_loadRef_opcode_depth_general` is COPY-mode — `loadRef`,
  not `loadRefLive` consume — so it does not witness `[roll dl, roll dr',
  opcode]`).  See the dispatcher's doc-comment.

* **Deliverable B** — `structuralArithConsumeBodyBool` (decidable SHAPE
  Bool, threading the stack map exactly like `structuralArithBodyBool`)
  + `structuralArithConsumeBodyBool_reflect`: builds the inductive (with
  its per-binding witnesses) from the shape-Bool + an `agreesTagged` /
  bigint-provenance context, using Deliverable A for each binding.

* **Deliverable C** — `wave20_reflect_capstone_smoke`: instantiates the
  reflection on a concrete consume-mode arith body and feeds it to the
  wave-19 capstone, starting from `structuralArithConsumeBodyBool … =
  true`.  Proves the Bool → capstone path closes end-to-end. -/

/-- **Deliverable A — per-binding consume `runOps` witness for a binOp
whose operands sit at depths (0, 1).**

This is the witness `structuralArithConsumeBody.consBinOp` consumes.
It derives `(lowerValueP …).1 = [.swap, .opcode (binopOpcode op rt)]`
INTERNALLY from `depth? l = some 0` / `depth? r = some 1` plus the
last-use consume flags (the wave-19 smoke supplied this equality as a
separate `wave19_ops*` lemma; here it is folded in), then dispatches to
`stageC_simpleStep_binOp_d0d1_consume_core`.

`outerProtected` is `[]` (the method-lowering value); the consume flags
reduce to `isLastUse`.  The caller supplies the generic opcode-success
hypothesis (`hOpcode`) — the same shape the singleton takes — discharged
per-opcode via `runOpcode_*_intInt`. -/
theorem build_consume_binOp_witness_d0d1
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name : String)
    (op l r : String) (rt : Option String) (a b : Int)
    (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState) (out : RunarVerification.ANF.Eval.Value)
    (hDepthL : sm.depth? l = some 0)
    (hDepthR : sm.depth? r = some 1)
    (hLastUseL : Stack.Lower.isLastUse lastUses l currentIndex = true)
    (hLastUseR : Stack.Lower.isLastUse lastUses r currentIndex = true)
    (hNotBytes : (op == "!==" && rt == some "bytes") = false)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt)
    (hLookupL : lookupAnfByKind anfSt (l, k_l) = some (.vBigint a))
    (hLookupR : lookupAnfByKind anfSt (r, k_r) = some (.vBigint b))
    (hOpcode :
      ∀ (restStk : List RunarVerification.ANF.Eval.Value),
        stkSt.stack = .vBigint a :: .vBigint b :: restStk →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt)
            ({stkSt with stack := .vBigint b :: .vBigint a :: restStk})
          = .ok ({stkSt with stack := restStk}.push out)) :
    runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
              [] localBindings constInts sm name (.binOp op l r rt)).1 stkSt
      = .ok ({stkSt with stack := stkSt.stack.tail.tail}.push out) := by
  -- Derive the lowered-ops shape `[.swap, .opcode (binopOpcode op rt)]`
  -- from the depth + consume facts.
  have hOps :
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm name (.binOp op l r rt)).1
        = [StackOp.swap, .opcode (Stack.Lower.binopOpcode op rt)] := by
    unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLive Stack.Lower.bringToTop
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
      hLastUseL, hLastUseR, hDepthL]
    simp only [hNotBytes, Bool.false_eq_true, if_false, if_true]
    simp only [hDepthR]
    cases hsm : sm with
    | nil => rw [hsm] at hDepthR; simp [Stack.Lower.StackMap.depth?] at hDepthR
    | cons _ tl =>
        cases tl with
        | nil => rw [hsm] at hDepthR; simp [Stack.Lower.StackMap.depth?] at hDepthR
        | cons _ _ => rfl
  rw [hOps]
  exact stageC_simpleStep_binOp_d0d1_consume_core
    l r k_l k_r tsm_rest anfSt stkSt a b
    (Stack.Lower.binopOpcode op rt) out
    [StackOp.swap, .opcode (Stack.Lower.binopOpcode op rt)]
    hAgrees hLookupL hLookupR rfl hOpcode

/-- **Deliverable A — per-binding consume `runOps` witness for a unaryOp
whose operand sits at depth 0.**

The witness `structuralArithConsumeBody.consUnaryOp` consumes.  Derives
`(lowerValueP …).1 = [.opcode (unaryOpcode op)]` internally from
`depth? operand = some 0` + the last-use consume flag, then dispatches
to the caller-supplied single-opcode run witness `hRun` (e.g.
`Stack.Sim.run_OP_NEGATE_int` for `op = "-"`).  Unlike the binOp case
there is no operand-reorder load (depth-0 consume is the empty op list),
so `hRun` runs against the bare opcode at the original `stkSt`. -/
theorem build_consume_unaryOp_witness_d0
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name : String)
    (op operand : String) (rt : Option String)
    (stkSt stkSt' : StackState)
    (hDepth : sm.depth? operand = some 0)
    (hLastUse : Stack.Lower.isLastUse lastUses operand currentIndex = true)
    (hRun :
      runOps [StackOp.opcode (Stack.Lower.unaryOpcode op)] stkSt = .ok stkSt') :
    runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
              [] localBindings constInts sm name (.unaryOp op operand rt)).1 stkSt
      = .ok stkSt' := by
  have hOps :
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm name (.unaryOp op operand rt)).1
        = [StackOp.opcode (Stack.Lower.unaryOpcode op)] := by
    unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLive Stack.Lower.bringToTop
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
      hLastUse, hDepth, if_true, List.nil_append]
  rw [hOps]; exact hRun

/-- **Deliverable A — generic operand-depth dispatcher (binOp).**

Given the operand depths as the discriminator, route a binOp's
per-binding consume witness to the matching `stageC_*_consume_core`
singleton.  This packages the wave-19 hand-dispatch into one entry
point.

**Covered combos** (the four last-use-friendly singletons, plus the
depth-0 unary peer via `build_consume_unaryOp_witness_d0`):

| (depth l, depth r) | singleton                                  |
|--------------------|--------------------------------------------|
| (0, 1)             | `stageC_simpleStep_binOp_d0d1_consume_core`|
| (1, 0)             | `stageC_simpleStep_binOp_d1d0_consume_core`|
| (≥2, 0)            | `stageC_simpleStep_binOp_dge2_d0_consume_core`|
| (0, ≥2)            | `stageC_simpleStep_binOp_d0_dge2_consume_core`|

**UNCOVERED HOLE — (≥2, ≥2):** when BOTH operands are deep, consume-mode
`lowerValueP` emits `[.roll dl, .roll dr', .opcode]` (verified by
reduction: e.g. `l@2, r@3 ⇒ [rot, roll 3, OP_ADD]`).  No `Agrees.lean`
singleton witnesses this two-roll consume shape.  The wave-16
`runOps_loadRef_loadRef_opcode_depth_general` /
`runOps_lowerValue_binOp_depth_general` are COPY-mode (built on
`loadRef`, which emits no-pop `dup/over/pickStruct`, against
`lowerValue` not `lowerValueP`); they cannot witness the consume
(removing-from-mid-stack) `roll` shape.  Closing (≥2, ≥2) needs a NEW
`loadRefLive`-consume depth-general substrate in `Agrees.lean` — flagged
for a follow-up wave.

This dispatcher therefore exposes the (0, 1) route directly (the combo
the omnibus arith bodies start from); the other three singletons remain
callable individually and are documented here as the dispatch targets. -/
theorem build_consume_binOp_witness
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name : String)
    (op l r : String) (rt : Option String) (a b : Int)
    (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState) (out : RunarVerification.ANF.Eval.Value)
    (hDepthL : sm.depth? l = some 0)
    (hDepthR : sm.depth? r = some 1)
    (hLastUseL : Stack.Lower.isLastUse lastUses l currentIndex = true)
    (hLastUseR : Stack.Lower.isLastUse lastUses r currentIndex = true)
    (hNotBytes : (op == "!==" && rt == some "bytes") = false)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt)
    (hLookupL : lookupAnfByKind anfSt (l, k_l) = some (.vBigint a))
    (hLookupR : lookupAnfByKind anfSt (r, k_r) = some (.vBigint b))
    (hOpcode :
      ∀ (restStk : List RunarVerification.ANF.Eval.Value),
        stkSt.stack = .vBigint a :: .vBigint b :: restStk →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt)
            ({stkSt with stack := .vBigint b :: .vBigint a :: restStk})
          = .ok ({stkSt with stack := restStk}.push out)) :
    runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
              [] localBindings constInts sm name (.binOp op l r rt)).1 stkSt
      = .ok ({stkSt with stack := stkSt.stack.tail.tail}.push out) :=
  build_consume_binOp_witness_d0d1 progMethods props budget currentIndex lastUses
    localBindings constInts sm name op l r rt a b k_l k_r tsm_rest anfSt stkSt out
    hDepthL hDepthR hLastUseL hLastUseR hNotBytes hAgrees hLookupL hLookupR hOpcode

/-! ### Deliverable B — decidable consume-arith SHAPE Bool + reflection -/

/-- **Deliverable B — per-value consume-arith SHAPE checker.**

Decides whether `v` is a consume-mode arith value the wave-20 builders
witness:

* a `binOp op l r rt` with `l` at depth 0, `r` at depth 1, both at last
  use (and not outer-protected), and not the `!==`/bytes special form;
  or
* a `unaryOp op operand rt` with `operand` at depth 0 at last use (not
  outer-protected).

This checks SHAPE only — the per-binding `runOps` witness is built
separately by `build_consume_binOp_witness_d0d1` /
`build_consume_unaryOp_witness_d0` from the `agreesTagged` + bigint
context.  Anything else is rejected. -/
def structuralArithConsumeValueBool
    (lastUses : List (String × Nat)) (outerProtected : List String)
    (sm : StackMap) (currentIndex : Nat) : ANFValue → Bool
  | .binOp op l r rt =>
      decide (sm.depth? l = some 0) &&
      decide (sm.depth? r = some 1) &&
      (!Stack.Lower.listContains outerProtected l) &&
      Stack.Lower.isLastUse lastUses l currentIndex &&
      (!Stack.Lower.listContains outerProtected r) &&
      Stack.Lower.isLastUse lastUses r currentIndex &&
      (!(op == "!==" && rt == some "bytes"))
  | .unaryOp _op operand _rt =>
      decide (sm.depth? operand = some 0) &&
      (!Stack.Lower.listContains outerProtected operand) &&
      Stack.Lower.isLastUse lastUses operand currentIndex
  | _ => false

/-- **Deliverable B — body-level consume-arith SHAPE checker.**

Threads the stack map through `lowerValueP`'s `.2.1` projection
binding-by-binding (exactly as `structuralArithBodyBool` /
`structuralConsumeBodyBool` do), checking each binding's value shape via
`structuralArithConsumeValueBool`. -/
def structuralArithConsumeBodyBool
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (outerProtected localBindings : List String)
    (constInts : List (String × Int)) :
    List ANFBinding → StackMap → Nat → Bool
  | [], _sm, _currentIndex => true
  | (.mk name v _) :: rest, sm, currentIndex =>
      structuralArithConsumeValueBool lastUses outerProtected sm currentIndex v &&
      structuralArithConsumeBodyBool progMethods props budget lastUses outerProtected
        localBindings constInts rest
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm name v).2.1
        (currentIndex + 1)

/-- **Deliverable B — single-step (binOp) reflection cons.**

Given the head binding passes the consume-arith SHAPE Bool, the
`agreesTagged` + bigint + opcode context for THIS step, and the tail's
already-built `structuralArithConsumeBody`, build the inductive for the
whole `(binOp …) :: rest`.

This is the cons-reflection step the wave-20 smoke chains: the Bool
gates the SHAPE (which lets the depth/last-use facts be DECODED from
`structuralArithConsumeValueBool … (.binOp …) = true` rather than
re-supplied), and Deliverable A's `build_consume_binOp_witness_d0d1`
turns the decoded facts + context into the per-binding witness that
`structuralArithConsumeBody.consBinOp` needs.

`outerProtected = []` (the method-lowering value), so the
`!listContains` conjuncts are `true` and drop out of the SHAPE decode. -/
theorem structuralArithConsumeBodyBool_reflect_consBinOp
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name : String) (src : Option RunarVerification.ANF.SourceLoc)
    (op l r : String) (rt : Option String) (a b : Int)
    (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt stkSt'' : StackState) (sm'' : StackMap)
    (out : RunarVerification.ANF.Eval.Value)
    (rest : List ANFBinding)
    (hShape :
      structuralArithConsumeValueBool lastUses [] sm currentIndex
        (.binOp op l r rt) = true)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt)
    (hLookupL : lookupAnfByKind anfSt (l, k_l) = some (.vBigint a))
    (hLookupR : lookupAnfByKind anfSt (r, k_r) = some (.vBigint b))
    (hOpcode :
      ∀ (restStk : List RunarVerification.ANF.Eval.Value),
        stkSt.stack = .vBigint a :: .vBigint b :: restStk →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt)
            ({stkSt with stack := .vBigint b :: .vBigint a :: restStk})
          = .ok ({stkSt with stack := restStk}.push out))
    (hTail :
      structuralArithConsumeBody progMethods props budget lastUses [] constInts
        rest
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm name (.binOp op l r rt)).2.1
        (currentIndex + 1)
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm name (.binOp op l r rt)).2.2
        ({stkSt with stack := stkSt.stack.tail.tail}.push out) sm'' stkSt'') :
    structuralArithConsumeBody progMethods props budget lastUses [] constInts
      (.mk name (.binOp op l r rt) src :: rest) sm currentIndex localBindings
      stkSt sm'' stkSt'' := by
  -- Decode the SHAPE Bool into the depth / last-use / not-bytes facts.
  simp only [structuralArithConsumeValueBool, Bool.and_eq_true] at hShape
  obtain ⟨⟨⟨⟨⟨⟨hDl, hDr⟩, _hOpL⟩, hLuL⟩, _hOpR⟩, hLuR⟩, hNB⟩ := hShape
  have hDl : sm.depth? l = some 0 := of_decide_eq_true hDl
  have hDr : sm.depth? r = some 1 := of_decide_eq_true hDr
  have hNotBytes : (op == "!==" && rt == some "bytes") = false :=
    Bool.not_eq_true' _ |>.mp hNB
  have hRun :
      runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.binOp op l r rt)).1 stkSt
        = .ok ({stkSt with stack := stkSt.stack.tail.tail}.push out) :=
    build_consume_binOp_witness_d0d1 progMethods props budget currentIndex lastUses
      localBindings constInts sm name op l r rt a b k_l k_r tsm_rest anfSt stkSt out
      hDl hDr hLuL hLuR hNotBytes hAgrees hLookupL hLookupR hOpcode
  exact structuralArithConsumeBody.consBinOp hRun hTail

/-- **Deliverable B — single-step (unaryOp) reflection cons.**

Unary peer of `structuralArithConsumeBodyBool_reflect_consBinOp`.  The
SHAPE Bool decodes the depth-0 + last-use facts; the caller supplies the
single-opcode run witness `hRun` (e.g. `Stack.Sim.run_OP_NEGATE_int`)
and the tail inductive. -/
theorem structuralArithConsumeBodyBool_reflect_consUnaryOp
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name : String) (src : Option RunarVerification.ANF.SourceLoc)
    (op operand : String) (rt : Option String)
    (stkSt stkSt' stkSt'' : StackState) (sm'' : StackMap)
    (rest : List ANFBinding)
    (hShape :
      structuralArithConsumeValueBool lastUses [] sm currentIndex
        (.unaryOp op operand rt) = true)
    (hRun :
      runOps [StackOp.opcode (Stack.Lower.unaryOpcode op)] stkSt = .ok stkSt')
    (hTail :
      structuralArithConsumeBody progMethods props budget lastUses [] constInts
        rest
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm name (.unaryOp op operand rt)).2.1
        (currentIndex + 1)
        (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm name (.unaryOp op operand rt)).2.2
        stkSt' sm'' stkSt'') :
    structuralArithConsumeBody progMethods props budget lastUses [] constInts
      (.mk name (.unaryOp op operand rt) src :: rest) sm currentIndex localBindings
      stkSt sm'' stkSt'' := by
  simp only [structuralArithConsumeValueBool, Bool.and_eq_true] at hShape
  obtain ⟨⟨hD, _hOp⟩, hLu⟩ := hShape
  have hD : sm.depth? operand = some 0 := of_decide_eq_true hD
  have hRunWit :
      runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.unaryOp op operand rt)).1 stkSt
        = .ok stkSt' :=
    build_consume_unaryOp_witness_d0 progMethods props budget currentIndex lastUses
      localBindings constInts sm name op operand rt stkSt stkSt' hD hLu hRun
  exact structuralArithConsumeBody.consUnaryOp hRunWit hTail

/-! ### Deliverable C — MANDATORY Bool → capstone smoke test

We instantiate the Deliverable-B reflection on the wave-19 concrete
consume-mode arith body (`[t0=p0+p1; t1=t0-p2; t2=-t1]`), STARTING from
`structuralArithConsumeBodyBool … = true`, to obtain a
`structuralArithConsumeBody`, then feed it to the wave-19 capstone
(`runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome`)
to conclude `runMethod … isSome`.  This proves the Bool → capstone path
closes end-to-end. -/

/-- The consume-arith SHAPE Bool reduces to `true` on the wave-19 smoke
body under the COMPUTED method-lowering arguments.  Discharged by
structural reduction (no `native_decide`): each binding's value-check by
`decide`, each threaded stack map via the `wave19_sm*` projections. -/
private theorem wave20_smokeBodyBool_true :
    structuralArithConsumeBodyBool [wave19SmokeMethod] ([] : List ANFProperty)
      Stack.Lower.defaultInlineBudget
      (Stack.Lower.computeLastUses wave19SmokeBody) []
      (wave19SmokeBody.map (fun bd => bd.name))
      (Stack.Lower.collectConstInts wave19SmokeBody)
      wave19SmokeBody ["p0", "p1", "p2"] 0 = true := by
  rw [wave19_localBindings]
  show structuralArithConsumeBodyBool _ _ _ _ _ _ _
        (ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none ::
          [ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
           ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none])
        _ _ = true
  unfold structuralArithConsumeBodyBool
  rw [wave19_sm0]
  refine Bool.and_eq_true _ _ |>.mpr ⟨?_, ?_⟩
  · rw [wave19_computeLastUses]; decide
  show structuralArithConsumeBodyBool _ _ _ _ _ _ _
        (ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none ::
          [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none])
        _ _ = true
  unfold structuralArithConsumeBodyBool
  rw [wave19_sm1]
  refine Bool.and_eq_true _ _ |>.mpr ⟨?_, ?_⟩
  · rw [wave19_computeLastUses]; decide
  show structuralArithConsumeBodyBool _ _ _ _ _ _ _
        (ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none :: [])
        _ _ = true
  unfold structuralArithConsumeBodyBool
  refine Bool.and_eq_true _ _ |>.mpr ⟨?_, ?_⟩
  · rw [wave19_computeLastUses]; decide
  rfl

/-- **Deliverable C — the Bool → capstone smoke.**

Starting from `structuralArithConsumeBodyBool … = true`
(`wave20_smokeBodyBool_true`), the Deliverable-B reflection cons steps
build a `structuralArithConsumeBody` over the wave-19 smoke body, which
the wave-19 capstone consumes to prove the lowered method runs to a
defined result.  All per-binding witnesses route through Deliverable A
(`build_consume_binOp_witness_d0d1` / `build_consume_unaryOp_witness_d0`)
via the reflection; the `agreesTagged` + bigint + opcode facts are
genuine inputs about the real body (the §2.1-sanctioned input-side
context). -/
theorem wave20_reflect_capstone_smoke
    (contractName : String) (initialStack : StackState)
    (a b c : Int) (rest : List RunarVerification.ANF.Eval.Value) (tsm_rest : TaggedStackMap)
    (anfSt0 anfSt1 : State)
    (hBool :
      structuralArithConsumeBodyBool [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeMethod.body) []
        (wave19SmokeMethod.body.map (fun bd => bd.name))
        (Stack.Lower.collectConstInts wave19SmokeMethod.body)
        wave19SmokeMethod.body
        ((wave19SmokeMethod.params.map (fun p => p.name)).reverse) 0 = true)
    (hStk : initialStack.stack = .vBigint a :: .vBigint b :: .vBigint c :: rest)
    (hAgrees0 : agreesTagged
        (("p0", .param) :: ("p1", .param) :: ("p2", .param) :: tsm_rest) anfSt0 initialStack)
    (hLookupP0 : lookupAnfByKind anfSt0 ("p0", .param) = some (.vBigint a))
    (hLookupP1 : lookupAnfByKind anfSt0 ("p1", .param) = some (.vBigint b))
    (hAgrees1 : agreesTagged
        (("t0", .binding) :: ("p2", .param) :: tsm_rest) anfSt1
        ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}))
    (hLookupT0 : lookupAnfByKind anfSt1 ("t0", .binding) = some (.vBigint (a + b)))
    (hLookupP2 : lookupAnfByKind anfSt1 ("p2", .param) = some (.vBigint c)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := ([] : List ANFProperty),
            methods := [wave19SmokeMethod] })
        wave19SmokeMethod.name initialStack).toOption.isSome := by
  -- Decode the body SHAPE Bool into the three per-binding value-shape
  -- Bools the reflection cons steps consume.  `wave19SmokeMethod.{body,
  -- params}` reduce definitionally to the literals; the threaded stack
  -- maps come from the `wave19_sm*` projections (the inverse of
  -- `wave20_smokeBodyBool_true`).  This is what makes the body Bool
  -- LOAD-BEARING for the capstone path.
  -- Binding 0 split: the body's head is `t0 = p0 + p1`; `unfold` fires
  -- because the body argument is defeq the literal cons (`wave19SmokeBody`
  -- unfolds), while `computeLastUses`/`collectConstInts wave19SmokeBody`
  -- stay symbolic so the `wave19_sm*` projections apply.
  have hBodyBool0 :
      (structuralArithConsumeValueBool (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["p0", "p1", "p2"] 0 (.binOp "+" "p0" "p1" none) &&
        structuralArithConsumeBodyBool [wave19SmokeMethod] ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget
          (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
          [ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
           ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
          (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
              Stack.Lower.defaultInlineBudget 0
              (Stack.Lower.computeLastUses wave19SmokeBody) []
              ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
              ["p0", "p1", "p2"] "t0" (.binOp "+" "p0" "p1" none)).2.1
          1) = true := hBool
  clear hBool
  rw [wave19_sm0] at hBodyBool0
  obtain ⟨hShape0, hBodyBool1⟩ := Bool.and_eq_true _ _ |>.mp hBodyBool0
  -- Binding 1 split.
  have hBodyBool1' :
      (structuralArithConsumeValueBool (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "p2"] 1 (.binOp "-" "t0" "p2" none) &&
        structuralArithConsumeBodyBool [wave19SmokeMethod] ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget
          (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
          [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
          (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
              Stack.Lower.defaultInlineBudget 1
              (Stack.Lower.computeLastUses wave19SmokeBody) []
              ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
              ["t0", "p2"] "t1" (.binOp "-" "t0" "p2" none)).2.1
          2) = true := hBodyBool1
  rw [wave19_sm1] at hBodyBool1'
  obtain ⟨hShape1, hBodyBool2⟩ := Bool.and_eq_true _ _ |>.mp hBodyBool1'
  -- Binding 2 split.
  have hBodyBool2' :
      (structuralArithConsumeValueBool (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t1"] 2 (.unaryOp "-" "t1" none) &&
        structuralArithConsumeBodyBool [wave19SmokeMethod] ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget
          (Stack.Lower.computeLastUses wave19SmokeBody) []
          ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
          []
          (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
              Stack.Lower.defaultInlineBudget 2
              (Stack.Lower.computeLastUses wave19SmokeBody) []
              ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
              ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
          3) = true := hBodyBool2
  obtain ⟨hShape2, _hBodyNil⟩ := Bool.and_eq_true _ _ |>.mp hBodyBool2'
  -- ===== Binding 2 (tail): t2 = -t1, unary-d0 consume → [OP_NEGATE]. =====
  have hStk2 :
      ({initialStack with stack := .vBigint ((a + b) - c) :: rest} : StackState).stack
        = .vBigint ((a + b) - c) :: rest := rfl
  have hRun2 :
      runOps [StackOp.opcode (Stack.Lower.unaryOpcode "-")]
          ({initialStack with stack := .vBigint ((a + b) - c) :: rest})
        = .ok ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    show runOps [StackOp.opcode "OP_NEGATE"] _ = _
    rw [Stack.Sim.run_OP_NEGATE_int
          ({initialStack with stack := .vBigint ((a + b) - c) :: rest}) ((a + b) - c) rest hStk2]
    rfl
  have chain2 :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        (Stack.Lower.collectConstInts wave19SmokeBody)
        [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
        ["t1"] 2 ["t0", "t1", "t2"]
        ({initialStack with stack := .vBigint ((a + b) - c) :: rest})
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) :=
    structuralArithConsumeBodyBool_reflect_consUnaryOp
      [wave19SmokeMethod] ([] : List ANFProperty) Stack.Lower.defaultInlineBudget 2
      (Stack.Lower.computeLastUses wave19SmokeBody) ["t0", "t1", "t2"]
      (Stack.Lower.collectConstInts wave19SmokeBody) ["t1"] "t2" none
      "-" "t1" none
      ({initialStack with stack := .vBigint ((a + b) - c) :: rest})
      ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest})
      _ _ [] hShape2 hRun2 structuralArithConsumeBody.nil
  -- ===== Binding 1: t1 = t0 - p2, d0d1 consume → [.swap, OP_SUB]. =====
  have hOpcode1 :
      ∀ (restStk : List RunarVerification.ANF.Eval.Value),
        ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest} : StackState).stack
            = .vBigint (a + b) :: .vBigint c :: restStk →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode "-" none)
            ({({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) with
              stack := .vBigint c :: .vBigint (a + b) :: restStk})
          = .ok ({({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) with
                  stack := restStk}.push (.vBigint ((a + b) - c))) := by
    intro restStk hEq
    have hRestEq : restStk = rest := by
      have h2 : .vBigint (a + b) :: .vBigint c :: rest
                  = (.vBigint (a + b) :: .vBigint c :: restStk
                      : List RunarVerification.ANF.Eval.Value) := hEq
      simp only [List.cons.injEq, true_and] at h2; exact h2.symm
    rw [hRestEq]
    exact Stack.Sim.runOpcode_SUB_intInt
      ({({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) with
        stack := .vBigint c :: .vBigint (a + b) :: rest}) (a + b) c rest rfl
  have chain1 :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        (Stack.Lower.collectConstInts wave19SmokeBody)
        (ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none ::
          [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none])
        ["t0", "p2"] 1 ["t0", "t1", "t2"]
        ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest})
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    refine structuralArithConsumeBodyBool_reflect_consBinOp
      [wave19SmokeMethod] ([] : List ANFProperty) Stack.Lower.defaultInlineBudget 1
      (Stack.Lower.computeLastUses wave19SmokeBody) ["t0", "t1", "t2"]
      (Stack.Lower.collectConstInts wave19SmokeBody) ["t0", "p2"] "t1" none
      "-" "t0" "p2" none (a + b) c .binding .param tsm_rest anfSt1
      ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest})
      ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) _
      (.vBigint ((a + b) - c)) [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
      hShape1 hAgrees1 hLookupT0 hLookupP2 hOpcode1 ?_
    -- The tail relation: rewrite the binding-1 `.2.1` / `.2.2` projections
    -- into the literals `chain2` is stated over.
    rw [wave19_sm1, wave19_lb1]
    -- The threaded post-state `{… stack.tail.tail …}.push` equals chain2's
    -- explicit `{… := vBigint ((a+b)-c) :: rest}`.
    have hPost :
        ({({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}) with
            stack :=
              ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}).stack.tail.tail}.push
              (.vBigint ((a + b) - c)))
          = ({initialStack with stack := .vBigint ((a + b) - c) :: rest} : StackState) := rfl
    rw [hPost]
    exact chain2
  -- ===== Binding 0: t0 = p0 + p1, d0d1 consume → [.swap, OP_ADD]. =====
  have hOpcode0 :
      ∀ (restStk : List RunarVerification.ANF.Eval.Value),
        initialStack.stack = .vBigint a :: .vBigint b :: restStk →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode "+" none)
            ({initialStack with stack := .vBigint b :: .vBigint a :: restStk})
          = .ok ({initialStack with stack := restStk}.push (.vBigint (a + b))) := by
    intro restStk hEq
    have hRestEq : restStk = .vBigint c :: rest := by
      rw [hStk] at hEq; simp only [List.cons.injEq, true_and] at hEq; exact hEq.symm
    rw [hRestEq]
    exact Stack.Sim.runOpcode_ADD_intInt
      ({initialStack with stack := .vBigint b :: .vBigint a :: .vBigint c :: rest})
      a b (.vBigint c :: rest) rfl
  have chain0 :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeBody) []
        (Stack.Lower.collectConstInts wave19SmokeBody)
        (ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none ::
          (ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none ::
            [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]))
        ["p0", "p1", "p2"] 0 ["t0", "t1", "t2"] initialStack
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := by
    refine structuralArithConsumeBodyBool_reflect_consBinOp
      [wave19SmokeMethod] ([] : List ANFProperty) Stack.Lower.defaultInlineBudget 0
      (Stack.Lower.computeLastUses wave19SmokeBody) ["t0", "t1", "t2"]
      (Stack.Lower.collectConstInts wave19SmokeBody) ["p0", "p1", "p2"] "t0" none
      "+" "p0" "p1" none a b .param .param (("p2", .param) :: tsm_rest) anfSt0
      initialStack ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) _
      (.vBigint (a + b))
      (ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none ::
        [ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none])
      hShape0 hAgrees0 hLookupP0 hLookupP1 hOpcode0 ?_
    rw [wave19_sm0, wave19_lb0]
    have hPost :
        ({initialStack with stack := initialStack.stack.tail.tail}.push (.vBigint (a + b)))
          = ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest} : StackState) := by
      rw [hStk]; rfl
    rw [hPost]
    exact chain1
  -- ===== Assemble `hArith` and apply the wave-19 capstone. =====
  have hUniq :
      ∀ m', m' ∈ [wave19SmokeMethod] → m'.isPublic = true →
        (m'.name == wave19SmokeMethod.name) = true → m' = wave19SmokeMethod := by
    intro m' hm' _ _
    simp only [List.mem_singleton] at hm'
    exact hm'
  have hArith :
      structuralArithConsumeBody [wave19SmokeMethod] ([] : List ANFProperty)
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses wave19SmokeMethod.body) []
        (Stack.Lower.collectConstInts wave19SmokeMethod.body)
        wave19SmokeMethod.body
        ((wave19SmokeMethod.params.map (fun p => p.name)).reverse) 0
        (wave19SmokeMethod.body.map (fun bd => bd.name)) initialStack
        (Stack.Lower.lowerValueP [wave19SmokeMethod] ([] : List ANFProperty)
            Stack.Lower.defaultInlineBudget 2
            (Stack.Lower.computeLastUses wave19SmokeBody) []
            ["t0", "t1", "t2"] (Stack.Lower.collectConstInts wave19SmokeBody)
            ["t1"] "t2" (.unaryOp "-" "t1" none)).2.1
        ({initialStack with stack := .vBigint (-((a + b) - c)) :: rest}) := chain0
  exact runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome
    contractName ([] : List ANFProperty) [wave19SmokeMethod] wave19SmokeMethod initialStack
    _ _ List.mem_cons_self rfl hUniq hArith
    wave19_noPreimage wave19_noCode wave19_noTerminalAssert wave19_noDeserialize

/-- **Deliverable C — Bool → capstone, fully closed.**

The end-to-end fact: starting from the SHAPE Bool `= true` discharged by
structural reduction (`wave20_smokeBodyBool_true`, no `native_decide`),
the reflection + wave-19 capstone prove the lowered `add3sub` method runs
to a defined result.  This pins the `hBool` parameter of
`wave20_reflect_capstone_smoke` to the structurally-reduced Bool witness,
so the smoke genuinely begins at the decidable consume-arith Bool. -/
theorem wave20_bool_to_capstone_closed
    (contractName : String) (initialStack : StackState)
    (a b c : Int) (rest : List RunarVerification.ANF.Eval.Value) (tsm_rest : TaggedStackMap)
    (anfSt0 anfSt1 : State)
    (hStk : initialStack.stack = .vBigint a :: .vBigint b :: .vBigint c :: rest)
    (hAgrees0 : agreesTagged
        (("p0", .param) :: ("p1", .param) :: ("p2", .param) :: tsm_rest) anfSt0 initialStack)
    (hLookupP0 : lookupAnfByKind anfSt0 ("p0", .param) = some (.vBigint a))
    (hLookupP1 : lookupAnfByKind anfSt0 ("p1", .param) = some (.vBigint b))
    (hAgrees1 : agreesTagged
        (("t0", .binding) :: ("p2", .param) :: tsm_rest) anfSt1
        ({initialStack with stack := .vBigint (a + b) :: .vBigint c :: rest}))
    (hLookupT0 : lookupAnfByKind anfSt1 ("t0", .binding) = some (.vBigint (a + b)))
    (hLookupP2 : lookupAnfByKind anfSt1 ("p2", .param) = some (.vBigint c)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := ([] : List ANFProperty),
            methods := [wave19SmokeMethod] })
        wave19SmokeMethod.name initialStack).toOption.isSome :=
  wave20_reflect_capstone_smoke contractName initialStack a b c rest tsm_rest
    anfSt0 anfSt1 wave20_smokeBodyBool_true hStk hAgrees0 hLookupP0 hLookupP1
    hAgrees1 hLookupT0 hLookupP2

/-! ## Path 2 Tier 1 Wave 27 — operational ANF↔stack lockstep

The genuine deferred operational-composition phase.  Wave 19 landed the
`structuralArithConsumeBody` inductive whose `consBinOp` / `consUnaryOp`
constructors each carry a per-binding INTERMEDIATE
`agreesTagged ((l,k_l)::(r,k_r)::tsm_rest) anfSt_i stkSt_i` plus operand
bigint lookups AT the threaded intermediate state.  The wave-20 smoke
(`wave20_reflect_capstone_smoke`) supplied each intermediate
`agreesTagged` (`hAgrees1`) and intermediate operand lookups
(`hLookupT0` / `hLookupP2`) BY HAND — it never transported the entry
`agreesTagged` across a consume-and-push.

Wave 27 lands the missing substrate: the **consume-mode `agreesTagged`
preservation** lemma.  From an entry `agreesTagged` with the two
consumed operands at the top, after the consume-and-push
(`stack := stack.tail.tail` then `push out`), the alignment is
re-established with the operands removed and the new temp on top — the
exact post-state shape the inductive's `.2.1` / `.2.2` projections
describe for d0d1 consume.  This is the `removeAtDepth`-then-`push`
preservation the BLOCK guidance anticipated.

### Step 3 — the consume preservation lemma

`agreesTagged_consume_top_two` is the bridge.  It is NOT a push (which
retains the whole tail); it removes the top two tracked entries and the
top two stack values, then pushes the fresh result.  The proof reuses
`agreesTagged_push_value` on the CONSUMED view (the StackState with the
two operands dropped) — the consumed view's alignment against
`tsm_rest` is the drop-two projection of the entry alignment. -/

/-- **Wave 27 Step 3 — consume-mode `agreesTagged` preservation.**

From `agreesTagged ((l,k_l)::(r,k_r)::tsm_rest) anfSt stkSt` (the two
operands tracked at the top), after dropping the two operands from the
stack (`stkSt.stack.tail.tail`) and pushing the fresh result `out` under
a fresh binding name `bn`, alignment holds for
`(bn,.binding)::tsm_rest`.

This is the post-state the d0d1 consume binOp lowering produces:
`sm3 = (sm2.popN 2).push bindingName`, removing the operands and binding
the result where they sat.  No new operand-retention slots — the tail
`tsm_rest` is exactly the entry tail with the two operand heads peeled
off. -/
theorem agreesTagged_consume_top_two
    (l r : String) (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (bn : String) (anfSt : State) (stkSt : StackState)
    (out : RunarVerification.ANF.Eval.Value)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm_rest)) :
    agreesTagged ((bn, .binding) :: tsm_rest)
      (anfSt.addBinding bn out)
      ({stkSt with stack := stkSt.stack.tail.tail}.push out) := by
  -- Peel the entry alignment down to the operand-free tail.
  have hAlign : taggedStackAligned ((l, k_l) :: (r, k_r) :: tsm_rest)
      anfSt stkSt.stack := hAgrees.1
  -- The stack is at least two deep, else the cons-cons alignment is False.
  obtain ⟨v0, v1, restStk, hStk⟩ :
      ∃ v0 v1 restStk, stkSt.stack = v0 :: v1 :: restStk := by
    match hCases : stkSt.stack with
    | [] =>
        rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | [_] =>
        rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
        obtain ⟨_, hTail⟩ := hAlign
        unfold taggedStackAligned at hTail
        exact absurd hTail (by simp)
    | v0 :: v1 :: restStk => exact ⟨v0, v1, restStk, rfl⟩
  -- The drop-two alignment for the tail.
  have hTailAlign : taggedStackAligned tsm_rest anfSt restStk := by
    rw [hStk] at hAlign
    unfold taggedStackAligned at hAlign
    obtain ⟨_, hAlign1⟩ := hAlign
    unfold taggedStackAligned at hAlign1
    exact hAlign1.2
  -- The CONSUMED-view StackState: operands dropped, props/outputs intact.
  -- `agreesTagged tsm_rest anfSt ({stkSt with stack := restStk})` — same
  -- props/outputs as `stkSt`, alignment is the drop-two tail.
  have hAgreesCons : agreesTagged tsm_rest anfSt ({stkSt with stack := restStk}) := by
    refine ⟨?_, ?_, ?_⟩
    · show taggedStackAligned tsm_rest anfSt restStk; exact hTailAlign
    · show anfSt.props = stkSt.props; exact hAgrees.2.1
    · show anfSt.outputs = stkSt.outputs; exact hAgrees.2.2
  -- Push the fresh result onto the consumed view — reusing the push lemma.
  have hPush := agreesTagged_push_value tsm_rest bn anfSt ({stkSt with stack := restStk})
    out hAgreesCons hFresh
  -- The pushed consumed view equals `{stkSt with stack := tail.tail}.push out`.
  have hStateEq :
      ({stkSt with stack := restStk}).push out
        = ({stkSt with stack := stkSt.stack.tail.tail}.push out) := by
    rw [hStk]; rfl
  rw [hStateEq] at hPush
  exact hPush

/-- **Wave 27 Step 3 (unary peer) — consume-mode `agreesTagged`
preservation for a single consumed operand.**

The d0 unary consume lowering produces `sm2 = (sm1.popN 1).push
bindingName`: one operand dropped, the result bound where it sat.  After
dropping ONE stack value (`stkSt.stack.tail`) and pushing `out`,
alignment holds for `(bn,.binding)::tsm_rest`. -/
theorem agreesTagged_consume_top_one
    (operand : String) (k_op : SlotKind) (tsm_rest : TaggedStackMap)
    (bn : String) (anfSt : State) (stkSt : StackState)
    (out : RunarVerification.ANF.Eval.Value)
    (hAgrees : agreesTagged ((operand, k_op) :: tsm_rest) anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm_rest)) :
    agreesTagged ((bn, .binding) :: tsm_rest)
      (anfSt.addBinding bn out)
      ({stkSt with stack := stkSt.stack.tail}.push out) := by
  have hAlign : taggedStackAligned ((operand, k_op) :: tsm_rest)
      anfSt stkSt.stack := hAgrees.1
  obtain ⟨v0, restStk, hStk⟩ :
      ∃ v0 restStk, stkSt.stack = v0 :: restStk := by
    match hCases : stkSt.stack with
    | [] =>
        rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | v0 :: restStk => exact ⟨v0, restStk, rfl⟩
  have hTailAlign : taggedStackAligned tsm_rest anfSt restStk := by
    rw [hStk] at hAlign
    unfold taggedStackAligned at hAlign
    exact hAlign.2
  have hAgreesCons : agreesTagged tsm_rest anfSt ({stkSt with stack := restStk}) := by
    refine ⟨?_, ?_, ?_⟩
    · show taggedStackAligned tsm_rest anfSt restStk; exact hTailAlign
    · show anfSt.props = stkSt.props; exact hAgrees.2.1
    · show anfSt.outputs = stkSt.outputs; exact hAgrees.2.2
  have hPush := agreesTagged_push_value tsm_rest bn anfSt ({stkSt with stack := restStk})
    out hAgreesCons hFresh
  have hStateEq :
      ({stkSt with stack := restStk}).push out
        = ({stkSt with stack := stkSt.stack.tail}.push out) := by
    rw [hStk]; rfl
  rw [hStateEq] at hPush
  exact hPush

/-! ### Wave 27 Deliverable A — the operational lockstep lemma

The three-binding d0d1 + d0d1 + unary-d0 consume-arith pattern is the
omnibus shape the omnibus arith bodies (and the wave-19 smoke) start
from.  `structuralArithConsumeBody_d0d1d0_of_entry_agreesTagged` builds
the full `structuralArithConsumeBody` inductive from:

* a BARE entry `agreesTagged` over the three params (NO intermediate
  `agreesTagged` supplied), and
* the entry stack as a concrete three-bigint list (the alignment witness
  the smoke constructs once), and
* the three opcode-arithmetic facts (genuinely about the operators, not
  the whole-body conclusion — §2.1 input-side).

Each INTERMEDIATE `agreesTagged` and INTERMEDIATE operand bigint lookup
is DERIVED — `agreesTagged_consume_top_two` / `_one` transport the entry
alignment across each consume-and-push, and `lookupAnfByKind_addBinding_*`
re-resolve the operands at the post-states.  This is the transport the
wave-20 smoke could not do (it took `hAgrees1` / `hLookupT0` by hand).

The shape is pinned to the d0d1 + d0d1 + unary-d0 layout the
`build_consume_*_witness_d0d1` / `_d0` substrate covers; the (≥2,≥2)
binOp combo remains the documented uncovered hole (no `loadRefLive`
consume depth-general singleton — see `build_consume_binOp_witness`). -/

/-- The binOp arm of `lowerValueP` leaves `localBindings` (`.2.2`)
unchanged.  Used to align the per-binding `runOps` witnesses with the
inductive's threaded `(lowerValueP …).2.2`. -/
theorem lowerValueP_binOp_localBindings
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name op l r : String) (rt : Option String) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
      outerProtected localBindings constInts sm name (.binOp op l r rt)).2.2
      = localBindings := by
  unfold Stack.Lower.lowerValueP; rfl

/-- The unaryOp arm of `lowerValueP` likewise leaves `localBindings`
unchanged. -/
theorem lowerValueP_unaryOp_localBindings
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name op operand : String) (rt : Option String) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
      outerProtected localBindings constInts sm name (.unaryOp op operand rt)).2.2
      = localBindings := by
  unfold Stack.Lower.lowerValueP; rfl

/-- **Wave 27 Deliverable A.**  Build a 3-binding consume-arith inductive
(`t0 = p0 ⊙ p1; t1 = t0 ⊙ p2; t2 = ⊙ t1`, all consume d0d1 / unary-d0)
from the ENTRY `agreesTagged` alone.

`vOut0 / vOut1 / vOut2` are the per-binding result values; the opcode
hypotheses pin them to the genuine `runOpcode` / `runOps` outputs (the
operator facts), and the inductive's stack-final is `stkFinal` carrying
`vOut2` on top.  No intermediate `agreesTagged` is taken — both are
transported by `agreesTagged_consume_top_two` / `_one`. -/
theorem structuralArithConsumeBody_d0d1d0_of_entry_agreesTagged
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (constInts : List (String × Int))
    (sm : StackMap) (localBindings : List String)
    (n0 n1 n2 : String) (s0 s1 s2 : Option RunarVerification.ANF.SourceLoc)
    (op0 op1 op2 : String) (rt0 rt1 rt2 : Option String)
    (p0 p1 p2 : String) (k0 k1 k2 : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (va vb vc vOut0 vOut1 : Int)
    -- Entry alignment: the two operand values resolve to bigints via the
    -- entry `agreesTagged` + the operand lookups (no separate explicit
    -- entry-stack-shape hypothesis is needed — the alignment carries it).
    (hAgrees : agreesTagged ((p0, k0) :: (p1, k1) :: (p2, k2) :: tsm_rest)
                 anfSt stkSt)
    (hLookupA : lookupAnfByKind anfSt (p0, k0) = some (.vBigint va))
    (hLookupB : lookupAnfByKind anfSt (p1, k1) = some (.vBigint vb))
    (hLookupC : lookupAnfByKind anfSt (p2, k2) = some (.vBigint vc))
    -- Lowering-shape facts: each binding is the d0d1 / unary-d0 consume layout.
    (hD0_p0 : sm.depth? p0 = some 0) (hD0_p1 : sm.depth? p1 = some 1)
    (hLU_p0 : Stack.Lower.isLastUse lastUses p0 0 = true)
    (hLU_p1 : Stack.Lower.isLastUse lastUses p1 0 = true)
    (hNB0 : (op0 == "!==" && rt0 == some "bytes") = false)
    (hD1_n0 : (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
                [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1.depth? n0
                = some 0)
    (hD1_p2 : (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
                [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1.depth? p2
                = some 1)
    (hLU_n0 : Stack.Lower.isLastUse lastUses n0 1 = true)
    (hLU_p2 : Stack.Lower.isLastUse lastUses p2 1 = true)
    (hNB1 : (op1 == "!==" && rt1 == some "bytes") = false)
    (hD2_n1 : (Stack.Lower.lowerValueP progMethods props budget 1 lastUses []
                localBindings constInts
                (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
                  [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1
                n1 (.binOp op1 n0 p2 rt1)).2.1.depth? n1 = some 0)
    (hLU_n1 : Stack.Lower.isLastUse lastUses n1 2 = true)
    -- Freshness for the two consumed-result binding names (SSA): each new
    -- temp is fresh in the operand-free tail it transports into.
    (hFresh0 : freshIn n0 (untagSm ((p2, k2) :: tsm_rest)))
    (hFresh1 : freshIn n1 (untagSm tsm_rest))
    -- Operator-arithmetic facts (the genuine per-opcode runtime witnesses).
    (hOpc0 :
      ∀ (rs : List RunarVerification.ANF.Eval.Value),
        stkSt.stack = .vBigint va :: .vBigint vb :: rs →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode op0 rt0)
            ({stkSt with stack := .vBigint vb :: .vBigint va :: rs})
          = .ok ({stkSt with stack := rs}.push (.vBigint vOut0)))
    (hOpc1 :
      ∀ (rs : List RunarVerification.ANF.Eval.Value),
        (({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) : StackState).stack
            = .vBigint vOut0 :: .vBigint vc :: rs →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode op1 rt1)
            ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
              stack := .vBigint vc :: .vBigint vOut0 :: rs})
          = .ok ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
                  stack := rs}.push (.vBigint vOut1)))
    -- The binding-1 post-consume state, named once to tame nesting.
    (stkFinal : StackState)
    (hRun2 :
      runOps [StackOp.opcode (Stack.Lower.unaryOpcode op2)]
          ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
              stack :=
                ({stkSt with stack := stkSt.stack.tail.tail}.push
                  (.vBigint vOut0)).stack.tail.tail}.push (.vBigint vOut1))
        = .ok stkFinal) :
    structuralArithConsumeBody progMethods props budget lastUses [] constInts
      [ANFBinding.mk n0 (.binOp op0 p0 p1 rt0) s0,
       ANFBinding.mk n1 (.binOp op1 n0 p2 rt1) s1,
       ANFBinding.mk n2 (.unaryOp op2 n1 rt2) s2]
      sm 0 localBindings stkSt
      (Stack.Lower.lowerValueP progMethods props budget 2 lastUses []
        localBindings constInts
        (Stack.Lower.lowerValueP progMethods props budget 1 lastUses []
          localBindings constInts
          (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
            [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1
          n1 (.binOp op1 n0 p2 rt1)).2.1
        n2 (.unaryOp op2 n1 rt2)).2.1
      stkFinal := by
  -- ===== Binding 0 (t0 = p0 op0 p1) — d0d1 consume. =====
  -- Operand witness from the entry alignment + opcode fact.
  have hRun0 :
      runOps (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
                [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).1 stkSt
        = .ok ({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) :=
    build_consume_binOp_witness_d0d1 progMethods props budget 0 lastUses
      localBindings constInts sm n0 op0 p0 p1 rt0 va vb k0 k1 ((p2, k2) :: tsm_rest)
      anfSt stkSt
      (.vBigint vOut0) hD0_p0 hD0_p1 hLU_p0 hLU_p1 hNB0 hAgrees hLookupA hLookupB hOpc0
  -- Derive the INTERMEDIATE agreesTagged for binding 1 from the entry.
  have hAgrees1 :
      agreesTagged ((n0, .binding) :: (p2, k2) :: tsm_rest)
        (anfSt.addBinding n0 (.vBigint vOut0))
        ({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) :=
    agreesTagged_consume_top_two p0 p1 k0 k1 ((p2, k2) :: tsm_rest) n0 anfSt stkSt
      (.vBigint vOut0) hAgrees hFresh0
  -- Derive the INTERMEDIATE operand lookups for binding 1.
  have hLookupT0 :
      lookupAnfByKind (anfSt.addBinding n0 (.vBigint vOut0)) (n0, .binding)
        = some (.vBigint vOut0) :=
    lookupAnfByKind_addBinding_self anfSt n0 (.vBigint vOut0)
  have hLookupP2' :
      lookupAnfByKind (anfSt.addBinding n0 (.vBigint vOut0)) (p2, k2)
        = some (.vBigint vc) := by
    -- p2 lives below the consumed operands; its lookup is stable under
    -- the new binding (distinct kind / name handled by the entry alignment).
    -- The entry alignment already resolved p2 to vc against `anfSt`; the
    -- `addBinding n0` only shadows the binding namespace.
    cases k2 with
    | param =>
        show (anfSt.addBinding n0 (.vBigint vOut0)).lookupParam p2 = some (.vBigint vc)
        unfold State.addBinding State.lookupParam
        simp only []
        have : anfSt.lookupParam p2 = some (.vBigint vc) := hLookupC
        unfold State.lookupParam at this
        exact this
    | prop =>
        show (anfSt.addBinding n0 (.vBigint vOut0)).lookupProp p2 = some (.vBigint vc)
        unfold State.addBinding State.lookupProp
        simp only []
        have : anfSt.lookupProp p2 = some (.vBigint vc) := hLookupC
        unfold State.lookupProp at this
        exact this
    | binding =>
        have hNe_p2_n0 : p2 ≠ n0 := by
          intro hEq
          apply hFresh0
          unfold untagSm
          rw [hEq]; simp
        rw [lookupAnfByKind_addBinding_of_ne anfSt n0 p2 (.vBigint vOut0) hNe_p2_n0]
        exact hLookupC
  -- ===== Binding 1 (t1 = t0 op1 p2) — d0d1 consume. =====
  have hRun1 :
      runOps (Stack.Lower.lowerValueP progMethods props budget 1 lastUses
                [] localBindings constInts
                (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
                  [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1
                n1 (.binOp op1 n0 p2 rt1)).1
            ({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0))
        = .ok ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
                stack :=
                  ({stkSt with stack := stkSt.stack.tail.tail}.push
                    (.vBigint vOut0)).stack.tail.tail}.push (.vBigint vOut1)) :=
    build_consume_binOp_witness_d0d1 progMethods props budget 1 lastUses
      localBindings constInts
      (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
        [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1
      n1 op1 n0 p2 rt1 vOut0 vc .binding k2 tsm_rest
      (anfSt.addBinding n0 (.vBigint vOut0))
      ({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0))
      (.vBigint vOut1) hD1_n0 hD1_p2 hLU_n0 hLU_p2 hNB1 hAgrees1 hLookupT0 hLookupP2' hOpc1
  -- Derive the INTERMEDIATE agreesTagged for binding 2 from binding 1's
  -- post-state.  The unary-d0 builder does not consume `agreesTagged`
  -- (it needs only depth + last-use + the opcode run), but transporting
  -- the alignment here demonstrates the lockstep stays closed past the
  -- second consume — the third binding's operand `n1` is the live top.
  have _hAgrees2 :
      agreesTagged ((n1, .binding) :: tsm_rest)
        ((anfSt.addBinding n0 (.vBigint vOut0)).addBinding n1 (.vBigint vOut1))
        ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
          stack :=
            ({stkSt with stack := stkSt.stack.tail.tail}.push
              (.vBigint vOut0)).stack.tail.tail}.push (.vBigint vOut1)) :=
    agreesTagged_consume_top_two n0 p2 .binding k2 tsm_rest n1
      (anfSt.addBinding n0 (.vBigint vOut0))
      ({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0))
      (.vBigint vOut1) hAgrees1 hFresh1
  -- ===== Binding 2 (t2 = op2 t1) — unary-d0 consume. =====
  have hRunWit2 :
      runOps (Stack.Lower.lowerValueP progMethods props budget 2 lastUses
                [] localBindings constInts
                (Stack.Lower.lowerValueP progMethods props budget 1 lastUses []
                  localBindings constInts
                  (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
                    [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1
                  n1 (.binOp op1 n0 p2 rt1)).2.1
                n2 (.unaryOp op2 n1 rt2)).1
            ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
              stack :=
                ({stkSt with stack := stkSt.stack.tail.tail}.push
                  (.vBigint vOut0)).stack.tail.tail}.push (.vBigint vOut1))
        = .ok stkFinal :=
    build_consume_unaryOp_witness_d0 progMethods props budget 2 lastUses
      localBindings constInts
      (Stack.Lower.lowerValueP progMethods props budget 1 lastUses []
        localBindings constInts
        (Stack.Lower.lowerValueP progMethods props budget 0 lastUses
          [] localBindings constInts sm n0 (.binOp op0 p0 p1 rt0)).2.1
        n1 (.binOp op1 n0 p2 rt1)).2.1
      n2 op2 n1 rt2
      ({({stkSt with stack := stkSt.stack.tail.tail}.push (.vBigint vOut0)) with
        stack :=
          ({stkSt with stack := stkSt.stack.tail.tail}.push
            (.vBigint vOut0)).stack.tail.tail}.push (.vBigint vOut1))
      _ hD2_n1 hLU_n1 hRun2
  -- ===== Assemble the inductive bottom-up. =====
  -- The `consBinOp` constructor threads the rest's `localBindings` as
  -- `(lowerValueP … binOp).2.2`; rewrite those projections back to the
  -- literal `localBindings` (the binOp / unaryOp arms leave it unchanged)
  -- so the pre-built per-binding witnesses unify.
  refine structuralArithConsumeBody.consBinOp hRun0 ?_
  rw [lowerValueP_binOp_localBindings]
  refine structuralArithConsumeBody.consBinOp hRun1 ?_
  rw [lowerValueP_binOp_localBindings]
  exact structuralArithConsumeBody.consUnaryOp hRunWit2 structuralArithConsumeBody.nil

/-! ### Wave 27 Deliverable B — MANDATORY lockstep smoke (entry-only)

The consumability proof.  We instantiate Deliverable A
(`structuralArithConsumeBody_d0d1d0_of_entry_agreesTagged`) on the
wave-19 concrete consume-arith body (`[t0=p0+p1; t1=t0-p2; t2=-t1]`)
from a **BARE entry `agreesTagged`** over the three params — NO
intermediate `agreesTagged` and NO intermediate operand lookups supplied
by hand (the wave-20 smoke supplied `hAgrees1` / `hLookupT0` / `hLookupP2`
explicitly; this one derives them inside the lockstep).  We obtain the
full `structuralArithConsumeBody`, then feed it to the wave-19 M2
capstone to conclude `runMethod … isSome`.

Each per-binding INTERMEDIATE `agreesTagged` and operand bigint lookup is
DERIVED by `agreesTagged_consume_top_two` (transport across the
consume-and-push) inside Deliverable A.  The only inputs are the entry
alignment, the entry operand lookups, the entry stack shape (used only to
build the operator facts), and the per-opcode arithmetic witnesses — the
§2.1-sanctioned input-side context.  This is the lockstep wave 26 could
not close. -/
theorem wave27_lockstep_capstone_smoke
    (contractName : String) (initialStack : StackState)
    (a b c : Int) (rest : List RunarVerification.ANF.Eval.Value)
    (tsm_rest : TaggedStackMap) (anfSt0 : State)
    (hStk : initialStack.stack = .vBigint a :: .vBigint b :: .vBigint c :: rest)
    (hAgrees0 : agreesTagged
        (("p0", .param) :: ("p1", .param) :: ("p2", .param) :: tsm_rest) anfSt0 initialStack)
    (hLookupP0 : lookupAnfByKind anfSt0 ("p0", .param) = some (.vBigint a))
    (hLookupP1 : lookupAnfByKind anfSt0 ("p1", .param) = some (.vBigint b))
    (hLookupP2 : lookupAnfByKind anfSt0 ("p2", .param) = some (.vBigint c))
    -- SSA freshness: the temp names `t0`/`t1` do not clash with the residual
    -- stack-map tail `tsm_rest` (an input-side invariant — the body's SSA
    -- temps are fresh against whatever sits below the method's params).
    (hFreshT0 : freshIn "t0" (untagSm (("p2", .param) :: tsm_rest)))
    (hFreshT1 : freshIn "t1" (untagSm tsm_rest)) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := ([] : List ANFProperty),
            methods := [wave19SmokeMethod] })
        wave19SmokeMethod.name initialStack).toOption.isSome := by
  -- Operator-arithmetic witnesses (built from the entry stack shape).
  have hOpc0 :
      ∀ (rs : List RunarVerification.ANF.Eval.Value),
        initialStack.stack = .vBigint a :: .vBigint b :: rs →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode "+" none)
            ({initialStack with stack := .vBigint b :: .vBigint a :: rs})
          = .ok ({initialStack with stack := rs}.push (.vBigint (a + b))) := by
    intro rs hEq
    have hRestEq : rs = .vBigint c :: rest := by
      rw [hStk] at hEq; simp only [List.cons.injEq, true_and] at hEq; exact hEq.symm
    rw [hRestEq]
    exact Stack.Sim.runOpcode_ADD_intInt
      ({initialStack with stack := .vBigint b :: .vBigint a :: .vBigint c :: rest})
      a b (.vBigint c :: rest) rfl
  have hOpc1 :
      ∀ (rs : List RunarVerification.ANF.Eval.Value),
        (({initialStack with stack := initialStack.stack.tail.tail}.push
            (.vBigint (a + b))) : StackState).stack
            = .vBigint (a + b) :: .vBigint c :: rs →
        Stack.Eval.runOpcode (Stack.Lower.binopOpcode "-" none)
            ({({initialStack with stack := initialStack.stack.tail.tail}.push
                (.vBigint (a + b))) with stack := .vBigint c :: .vBigint (a + b) :: rs})
          = .ok ({({initialStack with stack := initialStack.stack.tail.tail}.push
                (.vBigint (a + b))) with stack := rs}.push (.vBigint ((a + b) - c))) := by
    intro rs hEq
    -- The binding-1 entry stack is `vBigint (a+b) :: vBigint c :: rest`.
    have hMid : (({initialStack with stack := initialStack.stack.tail.tail}.push
        (.vBigint (a + b))) : StackState).stack
          = .vBigint (a + b) :: .vBigint c :: rest := by
      show (.vBigint (a + b) :: (initialStack.stack.tail.tail)) = _
      rw [hStk]; rfl
    have hRestEq : rs = rest := by
      rw [hMid] at hEq; simp only [List.cons.injEq, true_and] at hEq; exact hEq.symm
    rw [hRestEq]
    exact Stack.Sim.runOpcode_SUB_intInt
      ({({initialStack with stack := initialStack.stack.tail.tail}.push
          (.vBigint (a + b))) with stack := .vBigint c :: .vBigint (a + b) :: rest})
      (a + b) c rest rfl
  -- Binding-1 post-consume state (the unary builder's input).
  have hRun2 :
      runOps [StackOp.opcode (Stack.Lower.unaryOpcode "-")]
          ({({initialStack with stack := initialStack.stack.tail.tail}.push (.vBigint (a + b))) with
              stack :=
                ({initialStack with stack := initialStack.stack.tail.tail}.push
                  (.vBigint (a + b))).stack.tail.tail}.push (.vBigint ((a + b) - c)))
        = .ok ({({({initialStack with stack := initialStack.stack.tail.tail}.push
              (.vBigint (a + b))) with
              stack :=
                ({initialStack with stack := initialStack.stack.tail.tail}.push
                  (.vBigint (a + b))).stack.tail.tail}.push (.vBigint ((a + b) - c))) with
              stack :=
                (({({initialStack with stack := initialStack.stack.tail.tail}.push
                    (.vBigint (a + b))) with
                    stack :=
                      ({initialStack with stack := initialStack.stack.tail.tail}.push
                        (.vBigint (a + b))).stack.tail.tail}.push
                    (.vBigint ((a + b) - c)))).stack.tail}.push (.vBigint (-((a + b) - c)))) := by
    show runOps [StackOp.opcode "OP_NEGATE"] _ = _
    rw [Stack.Sim.run_OP_NEGATE_int _ ((a + b) - c)
          (({({initialStack with stack := initialStack.stack.tail.tail}.push
              (.vBigint (a + b))) with
              stack :=
                ({initialStack with stack := initialStack.stack.tail.tail}.push
                  (.vBigint (a + b))).stack.tail.tail}.push
              (.vBigint ((a + b) - c)))).stack.tail rfl]
  -- ===== Build the inductive from the BARE entry agreesTagged. =====
  -- The lemma produces the inductive over the wave-19 literal body /
  -- params / localBindings; the capstone consumes it over
  -- `wave19SmokeMethod.{body,params}` (defeq to those literals).
  have hArith :=
    structuralArithConsumeBody_d0d1d0_of_entry_agreesTagged
      [wave19SmokeMethod] ([] : List ANFProperty) Stack.Lower.defaultInlineBudget
      (Stack.Lower.computeLastUses wave19SmokeBody)
      (Stack.Lower.collectConstInts wave19SmokeBody)
      ["p0", "p1", "p2"] ["t0", "t1", "t2"]
      "t0" "t1" "t2" none none none
      "+" "-" "-" none none none
      "p0" "p1" "p2" .param .param .param tsm_rest
      anfSt0 initialStack a b c (a + b) ((a + b) - c)
      hAgrees0 hLookupP0 hLookupP1 hLookupP2
      (by decide)                                      -- hD0_p0
      (by decide)                                      -- hD0_p1
      (by rw [wave19_computeLastUses]; decide)         -- hLU_p0
      (by rw [wave19_computeLastUses]; decide)         -- hLU_p1
      (by decide)                                      -- hNB0
      (by rw [wave19_sm0]; decide)                     -- hD1_n0
      (by rw [wave19_sm0]; decide)                     -- hD1_p2
      (by rw [wave19_computeLastUses]; decide)         -- hLU_n0
      (by rw [wave19_computeLastUses]; decide)         -- hLU_p2
      (by decide)                                      -- hNB1
      (by rw [wave19_sm0, wave19_sm1]; decide)         -- hD2_n1
      (by rw [wave19_computeLastUses]; decide)         -- hLU_n1
      hFreshT0 hFreshT1
      hOpc0 hOpc1 _ hRun2
  -- ===== Apply the wave-19 capstone. =====
  have hUniq :
      ∀ m', m' ∈ [wave19SmokeMethod] → m'.isPublic = true →
        (m'.name == wave19SmokeMethod.name) = true → m' = wave19SmokeMethod := by
    intro m' hm' _ _
    simp only [List.mem_singleton] at hm'
    exact hm'
  exact runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome
    contractName ([] : List ANFProperty) [wave19SmokeMethod] wave19SmokeMethod initialStack
    _ _ List.mem_cons_self rfl hUniq hArith
    wave19_noPreimage wave19_noCode wave19_noTerminalAssert wave19_noDeserialize

/-! ### Wave 28 Deliverable A — general (arbitrary-length) consume-arith lockstep

Wave 27's `structuralArithConsumeBody_d0d1d0_of_entry_agreesTagged` builds
the inductive only for the EXACT 3-binding `d0d1 + d0d1 + unary-d0`
layout.  Wave 28 generalises the ASSEMBLY to ARBITRARY-LENGTH bodies by
induction over the body, reusing the same general substrate
(`agreesTagged_consume_top_two` / `_one` for the transport, the
`stageC_*_consume_core` singletons for the operational witness).

**Fragment restriction (part of the predicate, documented here):**

* **Emittable opcodes only.**  Each binOp is `OP_ADD` / `OP_SUB` /
  `OP_MUL` (ops `"+"`, `"-"`, `"*"`); each unaryOp is `OP_NEGATE` (op
  `"-"`).  These are the bigint-result arithmetic ops whose `runOpcode`
  singletons (`runOpcode_ADD_intInt` etc.) close uniformly.  The op set
  is pinned by the `emittableArithStep` decode below — anything else is
  outside the fragment.
* **No `(≥2, ≥2)` binding (linear arith chain).**  Each binOp has its
  left operand at depth 0 and right operand at depth 1 — the
  `structuralArithConsumeValueBool` SHAPE the wave-20 builders witness.
  The uncovered `(≥2, ≥2)` consume hole (no `loadRefLive`-consume
  depth-general singleton; documented at `build_consume_binOp_witness`)
  is therefore OUT of the fragment by construction: a body carrying a
  `(≥2, ≥2)` binding fails the SHAPE Bool and stays on the axiom.

This is the generalisation that unlocks wave 29's first axiom retirement. -/

/-- The per-binding result value for an emittable arith op applied to two
bigint operands `a` (left, depth 0) and `b` (right, depth 1).  Only the
emittable binOps (`"+"`, `"-"`, `"*"`) are defined; everything else maps
to `0` and is never reached because the step predicate gates the op. -/
def emittableBinOpResult (op : String) (a b : Int) : Int :=
  match op with
  | "+" => a + b
  | "-" => a - b
  | "*" => a * b
  | _   => 0

/-- The per-binding result value for an emittable unary arith op
(`"-"` ⇒ negate). -/
def emittableUnaryOpResult (op : String) (a : Int) : Int :=
  match op with
  | "-" => -a
  | _   => 0

/-- An emittable arith binOp opcode fires uniformly on a bigint stack:
for `op ∈ {"+","-","*"}` (and `rt` not the `!==`/bytes special form,
which these ops never are), `runOpcode (binopOpcode op rt)` on
`b :: a :: rest` pushes `emittableBinOpResult op a b`. -/
theorem runOpcode_emittableBinOp
    (op : String) (rt : Option String) (s : StackState) (a b : Int)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*") :
    Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt) s
      = .ok ({s with stack := rest}.push (.vBigint (emittableBinOpResult op a b))) := by
  rcases hEmit with h | h | h
  · subst h
    show Stack.Eval.runOpcode "OP_ADD" s = _
    rw [Stack.Sim.runOpcode_ADD_intInt s a b rest hStk]; rfl
  · subst h
    show Stack.Eval.runOpcode "OP_SUB" s = _
    rw [Stack.Sim.runOpcode_SUB_intInt s a b rest hStk]; rfl
  · subst h
    show Stack.Eval.runOpcode "OP_MUL" s = _
    rw [Stack.Sim.runOpcode_MUL_intInt s a b rest hStk]; rfl

/-- An emittable unary arith op (`"-"` ⇒ `OP_NEGATE`) fires uniformly on
a bigint stack. -/
theorem runOps_emittableUnaryOp
    (op : String) (s : StackState) (a : Int)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hStk : s.stack = .vBigint a :: rest)
    (hEmit : op = "-") :
    runOps [StackOp.opcode (Stack.Lower.unaryOpcode op)] s
      = .ok ({s with stack := rest}.push (.vBigint (emittableUnaryOpResult op a))) := by
  subst hEmit
  show runOps [StackOp.opcode "OP_NEGATE"] s = _
  rw [Stack.Sim.run_OP_NEGATE_int s a rest hStk]; rfl

/-- **Wave 28 — all-bigint tagged alignment.**

The lockstep invariant: every slot of `tsm` resolves (under
`lookupAnfByKind`) to a `.vBigint`.  This is the "linear arith chain"
type-invariant — it lets each binding read its operands as bigints
directly from the moving `agreesTagged`, and the emittable-op result
(`emittableBinOpResult` / `emittableUnaryOpResult`, both bigint) keeps it
true at the post-state.  Defined recursively over `tsm`, paralleling
`taggedStackAligned`. -/
def taggedAllBigint (anfSt : State) : TaggedStackMap → Prop
  | []        => True
  | s :: rest => (∃ i : Int, lookupAnfByKind anfSt s = some (.vBigint i)) ∧ taggedAllBigint anfSt rest

/-- The head slot of an all-bigint alignment resolves to a bigint. -/
theorem taggedAllBigint_head
    (anfSt : State) (s : String × SlotKind) (rest : TaggedStackMap)
    (h : taggedAllBigint anfSt (s :: rest)) :
    ∃ i : Int, lookupAnfByKind anfSt s = some (.vBigint i) := h.1

/-- The second slot of a two-deep all-bigint alignment resolves to a bigint. -/
theorem taggedAllBigint_second
    (anfSt : State) (s0 s1 : String × SlotKind) (rest : TaggedStackMap)
    (h : taggedAllBigint anfSt (s0 :: s1 :: rest)) :
    ∃ i : Int, lookupAnfByKind anfSt s1 = some (.vBigint i) := h.2.1

/-- **Wave 28 — `taggedAllBigint` stability under a fresh `addBinding`.**

If every slot of `tsm` resolves to a bigint and `bn` is fresh in the
untagged `tsm`, then every slot still resolves to the SAME bigint after
`addBinding bn (.vBigint i)`: params / props are untouched by
`addBinding`, and earlier bindings keep their value at a DISTINCT name.
This is the deeper-slot stability the consume transports need. -/
theorem taggedAllBigint_addBinding_of_fresh
    (anfSt : State) (bn : String) (i : Int) :
    ∀ (tsm : TaggedStackMap), taggedAllBigint anfSt tsm → freshIn bn (untagSm tsm) →
      taggedAllBigint (anfSt.addBinding bn (.vBigint i)) tsm := by
  intro tsm
  induction tsm with
  | nil => intro _ _; exact True.intro
  | cons hd tl ih =>
      intro hAll hFresh
      obtain ⟨⟨j, hj⟩, hTail⟩ := hAll
      have hFreshHd : bn ≠ hd.fst := by
        intro hEq; apply hFresh; unfold untagSm; rw [hEq]; exact List.mem_cons_self
      have hFreshTl : freshIn bn (untagSm tl) := by
        intro hMem; apply hFresh; unfold untagSm; exact List.mem_cons_of_mem _ hMem
      refine ⟨⟨j, ?_⟩, ih hTail hFreshTl⟩
      cases hk : hd.snd with
      | param =>
          have hHd2 : hd = (hd.fst, .param) := by rw [← hk]
          rw [hHd2]
          show (anfSt.addBinding bn (.vBigint i)).lookupParam hd.fst = some (.vBigint j)
          unfold State.addBinding State.lookupParam
          simp only []
          have hp : anfSt.lookupParam hd.fst = some (.vBigint j) := by
            have hjj := hj; rw [hHd2] at hjj
            unfold lookupAnfByKind State.lookupParam at hjj; exact hjj
          unfold State.lookupParam at hp; exact hp
      | prop =>
          have hHd2 : hd = (hd.fst, .prop) := by rw [← hk]
          rw [hHd2]
          show (anfSt.addBinding bn (.vBigint i)).lookupProp hd.fst = some (.vBigint j)
          unfold State.addBinding State.lookupProp
          simp only []
          have hp : anfSt.lookupProp hd.fst = some (.vBigint j) := by
            have hjj := hj; rw [hHd2] at hjj
            unfold lookupAnfByKind State.lookupProp at hjj; exact hjj
          unfold State.lookupProp at hp; exact hp
      | binding =>
          have hHd2 : hd = (hd.fst, .binding) := by rw [← hk]
          rw [hHd2]
          have hNe : hd.fst ≠ bn := fun hEq => hFreshHd hEq.symm
          rw [lookupAnfByKind_addBinding_of_ne anfSt bn hd.fst (.vBigint i) hNe]
          have hjj := hj; rw [hHd2] at hjj; exact hjj

/-- The transport of `taggedAllBigint` across a `consume_top_two`: the
consumed top two slots are gone, the new binding `bn` heads the tail with
a bigint value, and the deeper slots are stable (above lemma). -/
theorem taggedAllBigint_consume_top_two
    (anfSt : State) (l r : String) (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (bn : String) (i : Int)
    (hAll : taggedAllBigint anfSt ((l, k_l) :: (r, k_r) :: tsm_rest))
    (hFresh : freshIn bn (untagSm tsm_rest)) :
    taggedAllBigint (anfSt.addBinding bn (.vBigint i)) ((bn, .binding) :: tsm_rest) := by
  obtain ⟨_hHead, _hSecond, hTail⟩ := hAll
  exact ⟨⟨i, lookupAnfByKind_addBinding_self anfSt bn (.vBigint i)⟩,
    taggedAllBigint_addBinding_of_fresh anfSt bn i tsm_rest hTail hFresh⟩

/-- The unary peer transport: dropping ONE top slot of an all-bigint
alignment and pushing a fresh bigint binding keeps it all-bigint. -/
theorem taggedAllBigint_consume_top_one
    (anfSt : State) (operand : String) (k_op : SlotKind) (tsm_rest : TaggedStackMap)
    (bn : String) (i : Int)
    (hAll : taggedAllBigint anfSt ((operand, k_op) :: tsm_rest))
    (hFresh : freshIn bn (untagSm tsm_rest)) :
    taggedAllBigint (anfSt.addBinding bn (.vBigint i)) ((bn, .binding) :: tsm_rest) := by
  obtain ⟨_hHead, hTail⟩ := hAll
  exact ⟨⟨i, lookupAnfByKind_addBinding_self anfSt bn (.vBigint i)⟩,
    taggedAllBigint_addBinding_of_fresh anfSt bn i tsm_rest hTail hFresh⟩

/-- **Wave 28 — d0d1 consume binOp stack-map advance.**

For a binOp at the d0d1 consume layout (`l@0`, `r@1`, both last-use,
`outerProtected = []`, not the `!==`/bytes form), the threaded
`(lowerValueP …).2.1` advances to `name :: sm.tail.tail`: both operands
are consumed off the top, the result is bound where they sat.  Derived by
reduction of `loadRefLive` / `bringToTop` / `popN`. -/
theorem lowerValueP_binOp_d0d1_smOut
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name op l r : String) (rt : Option String)
    (hDepthL : sm.depth? l = some 0)
    (hDepthR : sm.depth? r = some 1)
    (hLastUseL : Stack.Lower.isLastUse lastUses l currentIndex = true)
    (hLastUseR : Stack.Lower.isLastUse lastUses r currentIndex = true) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm name (.binOp op l r rt)).2.1
      = name :: sm.tail.tail := by
  match sm, hDepthL, hDepthR with
  | [], hDepthL, _ => simp [Stack.Lower.StackMap.depth?] at hDepthL
  | [_a], _, hDepthR => simp [Stack.Lower.StackMap.depth?] at hDepthR
  | a :: b :: rest, hDepthL, hDepthR =>
      unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLive Stack.Lower.bringToTop
      simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
        hLastUseL, hLastUseR, hDepthL, hDepthR, if_true]
      show ((Stack.Lower.StackMap.popN (b :: a :: rest) 2).push name : StackMap)
        = name :: (a :: b :: rest).tail.tail
      simp only [Stack.Lower.StackMap.popN, Stack.Lower.StackMap.push, List.tail_cons]

/-- **Wave 28 — d0 consume unaryOp stack-map advance.**

For a unaryOp at the d0 consume layout (`operand@0`, last-use,
`outerProtected = []`), the threaded `(lowerValueP …).2.1` advances to
`name :: sm.tail`: the single operand is consumed off the top, the result
bound where it sat. -/
theorem lowerValueP_unaryOp_d0_smOut
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (name op operand : String) (rt : Option String)
    (hDepth : sm.depth? operand = some 0)
    (hLastUse : Stack.Lower.isLastUse lastUses operand currentIndex = true) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm name (.unaryOp op operand rt)).2.1
      = name :: sm.tail := by
  match sm, hDepth with
  | [], hDepth => simp [Stack.Lower.StackMap.depth?] at hDepth
  | a :: tl, hDepth =>
      unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLive Stack.Lower.bringToTop
      simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
        hLastUse, hDepth, if_true]
      show ((Stack.Lower.StackMap.popN (a :: tl) 1).push name : StackMap)
        = name :: (a :: tl).tail
      simp only [Stack.Lower.StackMap.popN, Stack.Lower.StackMap.push, List.tail_cons]

/-- **Wave 28 — tagged-map decomposition at depths (0, 1).**

If the untagged map equals `sm`, `l` is at depth 0 and `r` at depth 1
in `sm`, then `tsm` decomposes as `(l, k_l) :: (r, k_r) :: tsm_rest` and
`untagSm tsm_rest = sm.tail.tail`.  The head two slots are `l` and `r`
because `depth?` is `findIdx?`: depth 0 pins the head, depth 1 pins the
second (with the head distinct from `r`). -/
theorem tsm_decompose_d0d1
    (tsm : TaggedStackMap) (sm : StackMap) (l r : String)
    (hUntag : untagSm tsm = sm)
    (hDepthL : sm.depth? l = some 0)
    (hDepthR : sm.depth? r = some 1) :
    ∃ (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap),
      tsm = (l, k_l) :: (r, k_r) :: tsm_rest ∧ untagSm tsm_rest = sm.tail.tail := by
  match tsm, hUntag with
  | [], hUntag =>
      rw [← hUntag] at hDepthL; simp [untagSm, Stack.Lower.StackMap.depth?] at hDepthL
  | [(_n0, _k0)], hUntag =>
      rw [← hUntag] at hDepthR
      simp [untagSm, Stack.Lower.StackMap.depth?] at hDepthR
  | (n0, k0) :: (n1, k1) :: tsm_rest, hUntag =>
      -- `untagSm` gives `sm = n0 :: n1 :: untagSm tsm_rest`.
      have hsm : sm = n0 :: n1 :: untagSm tsm_rest := by
        rw [← hUntag]; simp only [untagSm]
      -- Depth 0 ⇒ head matches `l`.
      have hHead : n0 = l := by
        rw [hsm] at hDepthL
        unfold Stack.Lower.StackMap.depth? at hDepthL
        rw [List.findIdx?_cons] at hDepthL
        by_cases hc : (n0 == l) = true
        · exact (beq_iff_eq.mp hc)
        · simp only [hc, Bool.false_eq_true, if_false, Option.map_eq_some_iff] at hDepthL
          obtain ⟨_w, _, hEq⟩ := hDepthL
          omega
      -- Depth 1 ⇒ second matches `r` (head distinct from `r`).
      have hSecond : n1 = r := by
        rw [hsm] at hDepthR
        unfold Stack.Lower.StackMap.depth? at hDepthR
        rw [List.findIdx?_cons] at hDepthR
        by_cases hc : (n0 == r) = true
        · rw [if_pos hc] at hDepthR; exact absurd hDepthR (by decide)
        · simp only [hc, Bool.false_eq_true, if_false, Option.map_eq_some_iff] at hDepthR
          obtain ⟨w, hw, hEq⟩ := hDepthR
          have hw0 : w = 0 := by omega
          subst hw0
          rw [List.findIdx?_cons] at hw
          by_cases hc1 : (n1 == r) = true
          · exact (beq_iff_eq.mp hc1)
          · simp only [hc1, Bool.false_eq_true, if_false, Option.map_eq_some_iff] at hw
            obtain ⟨_w2, _, hEq2⟩ := hw
            omega
      subst hHead; subst hSecond
      exact ⟨k0, k1, tsm_rest, rfl, by rw [hsm]; rfl⟩

/-- **Wave 28 — tagged-map decomposition at depth 0 (unary).** -/
theorem tsm_decompose_d0
    (tsm : TaggedStackMap) (sm : StackMap) (operand : String)
    (hUntag : untagSm tsm = sm)
    (hDepth : sm.depth? operand = some 0) :
    ∃ (k_op : SlotKind) (tsm_rest : TaggedStackMap),
      tsm = (operand, k_op) :: tsm_rest ∧ untagSm tsm_rest = sm.tail := by
  match tsm, hUntag with
  | [], hUntag =>
      rw [← hUntag] at hDepth; simp [untagSm, Stack.Lower.StackMap.depth?] at hDepth
  | (n0, k0) :: tsm_rest, hUntag =>
      have hsm : sm = n0 :: untagSm tsm_rest := by
        rw [← hUntag]; simp only [untagSm]
      have hHead : n0 = operand := by
        rw [hsm] at hDepth
        unfold Stack.Lower.StackMap.depth? at hDepth
        rw [List.findIdx?_cons] at hDepth
        by_cases hc : (n0 == operand) = true
        · exact (beq_iff_eq.mp hc)
        · simp only [hc, Bool.false_eq_true, if_false, Option.map_eq_some_iff] at hDepth
          obtain ⟨_w, _, hEq⟩ := hDepth
          omega
      subst hHead
      exact ⟨k0, tsm_rest, rfl, by rw [hsm]; rfl⟩

/-! ### Wave 28 Deliverable A — the general lockstep -/

/-- **Wave 28 — emittable no-`(≥2,≥2)` arith-chain readiness.**

The fragment predicate, threaded over the body like
`structuralArithConsumeBodyBool`.  At each binding it requires:

* the binding is an EMITTABLE binOp (`"+"`/`"-"`/`"*"`) at the d0d1
  consume SHAPE, or an EMITTABLE unaryOp (`"-"`) at the d0 consume SHAPE
  (these SHAPE checks are exactly `structuralArithConsumeValueBool`, which
  pins l@0 / r@1 — the `(≥2,≥2)` hole is excluded by construction); and
* the binding's NAME is SSA-fresh in the post-consume residual stack map
  (`sm.tail.tail` for binOp, `sm.tail` for unaryOp).

It threads the advanced `sm` (`name :: residual`) and `currentIndex + 1`
to the tail.  Anything else (non-emittable op, non-arith value) is `False`
— outside the fragment, stays on the axiom. -/
def emittableArithChainReady
    (lastUses : List (String × Nat)) :
    List ANFBinding → StackMap → Nat → Prop
  | [], _sm, _currentIndex => True
  | (.mk name (.binOp op l r rt) _) :: rest, sm, currentIndex =>
      (op = "+" ∨ op = "-" ∨ op = "*") ∧
      structuralArithConsumeValueBool lastUses [] sm currentIndex (.binOp op l r rt) = true ∧
      freshIn name sm.tail.tail ∧
      emittableArithChainReady lastUses rest (name :: sm.tail.tail) (currentIndex + 1)
  | (.mk name (.unaryOp op operand rt) _) :: rest, sm, currentIndex =>
      op = "-" ∧
      structuralArithConsumeValueBool lastUses [] sm currentIndex (.unaryOp op operand rt) = true ∧
      freshIn name sm.tail ∧
      emittableArithChainReady lastUses rest (name :: sm.tail) (currentIndex + 1)
  | _ :: _, _sm, _currentIndex => False

/-- **Wave 28 Deliverable A — the GENERAL (arbitrary-length) lockstep.**

By induction over `body`, build the full `structuralArithConsumeBody`
inductive from a BARE entry `agreesTagged` over `tsm` (= `untagSm`-coherent
with the lowerer's `sm`), the all-bigint invariant `taggedAllBigint`, and
the emittable no-`(≥2,≥2)` readiness predicate.

Every per-binding INTERMEDIATE `agreesTagged`, operand bigint value, and
opcode arithmetic fact is DERIVED inside the induction:

* the moving `agreesTagged tsm` is transported across each consume by
  `agreesTagged_consume_top_two` / `_one`;
* the all-bigint invariant is transported by
  `taggedAllBigint_consume_top_two` / `_one`, so both operands read off
  as `.vBigint` from the moving alignment;
* the opcode fact is supplied uniformly by `runOpcode_emittableBinOp` /
  `runOps_emittableUnaryOp` (emittable arith ops only);
* the stack-map advance is `lowerValueP_binOp_d0d1_smOut` /
  `lowerValueP_unaryOp_d0_smOut`, keeping `untagSm tsm' = sm'`.

The result value of each binding is `emittableBinOpResult` /
`emittableUnaryOpResult` of its operands — both bigint, preserving the
invariant.  `localBindings` is threaded unchanged (the binOp / unaryOp
arms leave it fixed). -/
theorem structuralArithConsumeBody_of_entry_agreesTagged
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (constInts : List (String × Int)) :
    ∀ (body : List ANFBinding) (sm : StackMap) (localBindings : List String)
      (currentIndex : Nat) (tsm : TaggedStackMap) (anfSt : State) (stkSt : StackState),
      untagSm tsm = sm →
      agreesTagged tsm anfSt stkSt →
      taggedAllBigint anfSt tsm →
      emittableArithChainReady lastUses body sm currentIndex →
      ∃ (sm' : StackMap) (stkFinal : StackState),
        structuralArithConsumeBody progMethods props budget lastUses [] constInts
          body sm currentIndex localBindings stkSt sm' stkFinal := by
  intro body
  induction body with
  | nil =>
      intro sm localBindings currentIndex tsm anfSt stkSt _hUntag _hAgrees _hAll _hReady
      exact ⟨sm, stkSt, structuralArithConsumeBody.nil⟩
  | cons hd rest ih =>
      intro sm localBindings currentIndex tsm anfSt stkSt hUntag hAgrees hAll hReady
      obtain ⟨name, v, src⟩ := hd
      cases v with
      | binOp op l r rt =>
          simp only [emittableArithChainReady] at hReady
          obtain ⟨hEmit, hShape, hFresh, hRest⟩ := hReady
          -- Decode the SHAPE Bool's depth facts.
          have hShapeCopy := hShape
          simp only [structuralArithConsumeValueBool, Bool.and_eq_true] at hShapeCopy
          obtain ⟨⟨⟨⟨⟨⟨hDl, hDr⟩, _⟩, _⟩, _⟩, _⟩, _⟩ := hShapeCopy
          have hDl : sm.depth? l = some 0 := of_decide_eq_true hDl
          have hDr : sm.depth? r = some 1 := of_decide_eq_true hDr
          -- Decompose `tsm = (l,k_l)::(r,k_r)::tsm_rest`.
          obtain ⟨k_l, k_r, tsm_rest, hTsmEq, hUntagRest⟩ :=
            tsm_decompose_d0d1 tsm sm l r hUntag hDl hDr
          subst hTsmEq
          -- Operand bigint values from the all-bigint invariant.
          obtain ⟨a, hLookupL⟩ := taggedAllBigint_head anfSt (l, k_l) _ hAll
          obtain ⟨b, hLookupR⟩ := taggedAllBigint_second anfSt (l, k_l) (r, k_r) _ hAll
          -- The result value and post-state.
          let out : RunarVerification.ANF.Eval.Value :=
            .vBigint (emittableBinOpResult op a b)
          -- The opcode fact, uniform over emittable arith ops.
          have hOpcode :
              ∀ (restStk : List RunarVerification.ANF.Eval.Value),
                stkSt.stack = .vBigint a :: .vBigint b :: restStk →
                Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt)
                    ({stkSt with stack := .vBigint b :: .vBigint a :: restStk})
                  = .ok ({stkSt with stack := restStk}.push out) := by
            intro restStk _hStk
            exact runOpcode_emittableBinOp op rt
              ({stkSt with stack := .vBigint b :: .vBigint a :: restStk}) a b restStk rfl hEmit
          -- Freshness in the residual tail (rewrite `sm.tail.tail`).
          have hFreshRest : freshIn name (untagSm tsm_rest) := by
            rw [hUntagRest]; exact hFresh
          -- Transport the alignment + all-bigint to the post-consume state.
          have hAgrees1 :
              agreesTagged ((name, .binding) :: tsm_rest) (anfSt.addBinding name out)
                ({stkSt with stack := stkSt.stack.tail.tail}.push out) :=
            agreesTagged_consume_top_two l r k_l k_r tsm_rest name anfSt stkSt out
              hAgrees hFreshRest
          have hAll1 :
              taggedAllBigint (anfSt.addBinding name out) ((name, .binding) :: tsm_rest) :=
            taggedAllBigint_consume_top_two anfSt l r k_l k_r tsm_rest name
              (emittableBinOpResult op a b) hAll hFreshRest
          -- The advanced lowerer stack map.
          have hSmOut :
              (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                  [] localBindings constInts sm name (.binOp op l r rt)).2.1
                = name :: sm.tail.tail :=
            lowerValueP_binOp_d0d1_smOut progMethods props budget currentIndex lastUses
              localBindings constInts sm name op l r rt hDl hDr
              (by
                have hShapeCopy2 := hShape
                simp only [structuralArithConsumeValueBool, Bool.and_eq_true] at hShapeCopy2
                exact hShapeCopy2.1.1.1.2)
              (by
                have hShapeCopy2 := hShape
                simp only [structuralArithConsumeValueBool, Bool.and_eq_true] at hShapeCopy2
                exact hShapeCopy2.1.2)
          -- The coherence `untagSm ((name,.binding)::tsm_rest) = name :: sm.tail.tail`.
          have hUntag1 : untagSm ((name, .binding) :: tsm_rest) = name :: sm.tail.tail := by
            simp only [untagSm]; rw [hUntagRest]
          -- Apply the IH on `rest` at the advanced state.
          obtain ⟨sm', stkFinal, hTail⟩ :=
            ih (name :: sm.tail.tail) localBindings (currentIndex + 1)
              ((name, .binding) :: tsm_rest) (anfSt.addBinding name out)
              ({stkSt with stack := stkSt.stack.tail.tail}.push out)
              hUntag1 hAgrees1 hAll1
              (by
                -- `emittableArithChainReady` tail at `name :: sm.tail.tail`.
                exact hRest)
          -- Build the cons via the reflection lemma.
          refine ⟨sm', stkFinal, ?_⟩
          have hReflect :
              structuralArithConsumeBody progMethods props budget lastUses [] constInts
                (.mk name (.binOp op l r rt) src :: rest) sm currentIndex localBindings
                stkSt sm' stkFinal := by
            refine structuralArithConsumeBodyBool_reflect_consBinOp
              progMethods props budget currentIndex lastUses localBindings constInts
              sm name src op l r rt a b k_l k_r tsm_rest anfSt stkSt stkFinal sm' out rest
              hShape hAgrees hLookupL hLookupR hOpcode ?_
            -- `hTail` is over `(lowerValueP …).2.1` and the post-state; rewrite
            -- the threaded stack map + the post-state to the reflection's shape.
            rw [hSmOut, lowerValueP_binOp_localBindings]
            -- The reflection's post-state is `{stkSt with stack := tail.tail}.push out`.
            exact hTail
          exact hReflect
      | unaryOp op operand rt =>
          simp only [emittableArithChainReady] at hReady
          obtain ⟨hEmit, hShape, hFresh, hRest⟩ := hReady
          have hShapeCopy := hShape
          simp only [structuralArithConsumeValueBool, Bool.and_eq_true] at hShapeCopy
          obtain ⟨⟨hD, _⟩, hLu⟩ := hShapeCopy
          have hD : sm.depth? operand = some 0 := of_decide_eq_true hD
          obtain ⟨k_op, tsm_rest, hTsmEq, hUntagRest⟩ :=
            tsm_decompose_d0 tsm sm operand hUntag hD
          subst hTsmEq
          obtain ⟨a, hLookupOp⟩ := taggedAllBigint_head anfSt (operand, k_op) _ hAll
          let out : RunarVerification.ANF.Eval.Value :=
            .vBigint (emittableUnaryOpResult op a)
          have hFreshRest : freshIn name (untagSm tsm_rest) := by
            rw [hUntagRest]; exact hFresh
          -- The operand value at the stack top, from the alignment.
          have hStkTop : stkSt.stack = .vBigint a :: stkSt.stack.tail := by
            have hAlign : taggedStackAligned ((operand, k_op) :: tsm_rest) anfSt stkSt.stack :=
              hAgrees.1
            match hcase : stkSt.stack with
            | [] => rw [hcase] at hAlign; simp [taggedStackAligned] at hAlign
            | v0 :: restStk =>
                rw [hcase] at hAlign
                unfold taggedStackAligned at hAlign
                obtain ⟨hHead, _⟩ := hAlign
                rw [hLookupOp] at hHead
                have hv0 : v0 = .vBigint a := (Option.some.injEq _ _).mp hHead.symm
                rw [hv0, List.tail_cons]
          have hRun :
              runOps [StackOp.opcode (Stack.Lower.unaryOpcode op)] stkSt
                = .ok ({stkSt with stack := stkSt.stack.tail}.push out) :=
            runOps_emittableUnaryOp op stkSt a stkSt.stack.tail hStkTop hEmit
          have hAgrees1 :
              agreesTagged ((name, .binding) :: tsm_rest) (anfSt.addBinding name out)
                ({stkSt with stack := stkSt.stack.tail}.push out) :=
            agreesTagged_consume_top_one operand k_op tsm_rest name anfSt stkSt out
              hAgrees hFreshRest
          have hAll1 :
              taggedAllBigint (anfSt.addBinding name out) ((name, .binding) :: tsm_rest) :=
            taggedAllBigint_consume_top_one anfSt operand k_op tsm_rest name
              (emittableUnaryOpResult op a) hAll hFreshRest
          have hSmOut :
              (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                  [] localBindings constInts sm name (.unaryOp op operand rt)).2.1
                = name :: sm.tail :=
            lowerValueP_unaryOp_d0_smOut progMethods props budget currentIndex lastUses
              localBindings constInts sm name op operand rt hD hLu
          have hUntag1 : untagSm ((name, .binding) :: tsm_rest) = name :: sm.tail := by
            simp only [untagSm]; rw [hUntagRest]
          obtain ⟨sm', stkFinal, hTail⟩ :=
            ih (name :: sm.tail) localBindings (currentIndex + 1)
              ((name, .binding) :: tsm_rest) (anfSt.addBinding name out)
              ({stkSt with stack := stkSt.stack.tail}.push out)
              hUntag1 hAgrees1 hAll1 hRest
          refine ⟨sm', stkFinal, ?_⟩
          refine structuralArithConsumeBodyBool_reflect_consUnaryOp
            progMethods props budget currentIndex lastUses localBindings constInts
            sm name src op operand rt stkSt
            ({stkSt with stack := stkSt.stack.tail}.push out) stkFinal sm' rest
            hShape hRun ?_
          rw [hSmOut, lowerValueP_unaryOp_localBindings]
          exact hTail
      | loadParam _ => simp only [emittableArithChainReady] at hReady
      | loadProp _ => simp only [emittableArithChainReady] at hReady
      | loadConst _ => simp only [emittableArithChainReady] at hReady
      | call _ _ => simp only [emittableArithChainReady] at hReady
      | methodCall _ _ _ => simp only [emittableArithChainReady] at hReady
      | ifVal _ _ _ => simp only [emittableArithChainReady] at hReady
      | loop _ _ _ => simp only [emittableArithChainReady] at hReady
      | assert _ => simp only [emittableArithChainReady] at hReady
      | updateProp _ _ => simp only [emittableArithChainReady] at hReady
      | getStateScript => simp only [emittableArithChainReady] at hReady
      | checkPreimage _ => simp only [emittableArithChainReady] at hReady
      | deserializeState _ => simp only [emittableArithChainReady] at hReady
      | addOutput _ _ _ => simp only [emittableArithChainReady] at hReady
      | addRawOutput _ _ => simp only [emittableArithChainReady] at hReady
      | addDataOutput _ _ => simp only [emittableArithChainReady] at hReady
      | arrayLiteral _ => simp only [emittableArithChainReady] at hReady
      | rawScript _ _ _ => simp only [emittableArithChainReady] at hReady

/-! ### Wave 28 Deliverable B — MANDATORY length>3 smoke (entry-only)

The anti-vacuity proof for the GENERAL assembly.  We instantiate
Deliverable A (`structuralArithConsumeBody_of_entry_agreesTagged`) on a
CONCRETE **5-binding** linear arith chain, mixed ADD / SUB / MUL /
NEGATE / ADD, from a BARE entry `agreesTagged` over the FIVE params — NO
per-binding intermediate `agreesTagged`, NO intermediate operand lookups
supplied by hand (every intermediate is DERIVED inside the induction by
`agreesTagged_consume_top_two` / `_one` + the all-bigint transport).  We
obtain the full `structuralArithConsumeBody`, then fire the wave-19 M2
capstone to conclude `runMethod … isSome`.  This proves the general
assembly closes for length > 3.

```
method chain5 (p0 p1 p2 p3 p4 : bigint) {
  t0 = p0 + p1     -- ADD,    consume d0d1
  t1 = t0 - p2     -- SUB,    consume d0d1
  t2 = t1 * p3     -- MUL,    consume d0d1
  t3 = -t2         -- NEGATE, consume d0
  t4 = t3 + p4     -- ADD,    consume d0d1
}
``` -/

/-- Concrete 5-binding consume-arith chain for the wave-28 smoke. -/
private def wave28SmokeBody : List ANFBinding :=
  [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
   ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
   ANFBinding.mk "t2" (.binOp "*" "t1" "p3" none) none,
   ANFBinding.mk "t3" (.unaryOp "-" "t2" none) none,
   ANFBinding.mk "t4" (.binOp "+" "t3" "p4" none) none]

/-- Concrete method carrying `wave28SmokeBody`.  Params declared in
reverse so `(params.map name).reverse = ["p0", "p1", "p2", "p3", "p4"]`. -/
private def wave28SmokeMethod : ANFMethod :=
  { name := "chain5"
    params := [ANFParam.mk "p4" .bigint, ANFParam.mk "p3" .bigint,
               ANFParam.mk "p2" .bigint, ANFParam.mk "p1" .bigint,
               ANFParam.mk "p0" .bigint]
    body := wave28SmokeBody
    isPublic := true }

private theorem wave28_paramsRev :
    (wave28SmokeMethod.params.map (fun p => p.name)).reverse
      = ["p0", "p1", "p2", "p3", "p4"] := by
  unfold wave28SmokeMethod; rfl

private theorem wave28_localBindings :
    wave28SmokeBody.map (fun bd => bd.name) = ["t0", "t1", "t2", "t3", "t4"] := by
  unfold wave28SmokeBody; rfl

private theorem wave28_noPreimage :
    Stack.Lower.bindingsUseCheckPreimage wave28SmokeMethod.body = false := by
  show Stack.Lower.bindingsUseCheckPreimage wave28SmokeBody = false
  simp only [wave28SmokeBody, Stack.Lower.bindingsUseCheckPreimage, Bool.or_false]

private theorem wave28_noCode :
    Stack.Lower.bindingsUseCodePart wave28SmokeMethod.body = false := by
  show Stack.Lower.bindingsUseCodePart wave28SmokeBody = false
  simp only [wave28SmokeBody, Stack.Lower.bindingsUseCodePart, Bool.or_false]

private theorem wave28_noTerminalAssert :
    Stack.Lower.bodyEndsInAssert wave28SmokeMethod.body = false := by
  show Stack.Lower.bodyEndsInAssert wave28SmokeBody = false
  unfold wave28SmokeBody Stack.Lower.bodyEndsInAssert; rfl

private theorem wave28_noDeserialize :
    Stack.Lower.bindingsUseDeserializeState wave28SmokeMethod.body = false := by
  show Stack.Lower.bindingsUseDeserializeState wave28SmokeBody = false
  simp only [wave28SmokeBody, Stack.Lower.bindingsUseDeserializeState, Bool.or_false]

/-- The emittable no-`(≥2,≥2)` readiness predicate reduces to `True` on
the 5-binding smoke body under the COMPUTED method-lowering arguments.
Discharged by structural reduction (no `native_decide`): each binding's
SHAPE Bool + freshness by `decide` over the threaded stack map. -/
private theorem wave28_chainReady :
    emittableArithChainReady (Stack.Lower.computeLastUses wave28SmokeBody)
      wave28SmokeBody ["p0", "p1", "p2", "p3", "p4"] 0 := by
  unfold wave28SmokeBody
  refine ⟨Or.inl rfl, by decide, by unfold freshIn; decide, ?_⟩
  refine ⟨Or.inr (Or.inl rfl), by decide, by unfold freshIn; decide, ?_⟩
  refine ⟨Or.inr (Or.inr rfl), by decide, by unfold freshIn; decide, ?_⟩
  refine ⟨rfl, by decide, by unfold freshIn; decide, ?_⟩
  refine ⟨Or.inl rfl, by decide, by unfold freshIn; decide, ?_⟩
  exact True.intro

/-- **Wave 28 Deliverable B — the length>3 lockstep capstone smoke.**

From a BARE entry `agreesTagged` over the FIVE params (plus the all-bigint
invariant + SSA freshness — all input-side, §2.1), the general lockstep
builds the full `structuralArithConsumeBody` for the 5-binding chain, and
the wave-19 M2 capstone discharges `runMethod … isSome`.  Every
per-binding intermediate is DERIVED. -/
theorem wave28_general_lockstep_capstone_smoke
    (contractName : String) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap) (anfSt0 : State)
    (hUntag : untagSm tsm = ["p0", "p1", "p2", "p3", "p4"])
    (hAgrees0 : agreesTagged tsm anfSt0 initialStack)
    (hAllBigint : taggedAllBigint anfSt0 tsm) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := ([] : List ANFProperty),
            methods := [wave28SmokeMethod] })
        wave28SmokeMethod.name initialStack).toOption.isSome := by
  -- Build the inductive from the BARE entry agreesTagged via the general lockstep.
  obtain ⟨sm', stkFinal, hArith⟩ :=
    structuralArithConsumeBody_of_entry_agreesTagged
      [wave28SmokeMethod] ([] : List ANFProperty) Stack.Lower.defaultInlineBudget
      (Stack.Lower.computeLastUses wave28SmokeBody)
      (Stack.Lower.collectConstInts wave28SmokeBody)
      wave28SmokeBody ["p0", "p1", "p2", "p3", "p4"]
      (wave28SmokeBody.map (fun bd => bd.name)) 0
      tsm anfSt0 initialStack hUntag hAgrees0 hAllBigint wave28_chainReady
  -- Apply the wave-19 M2 capstone.
  have hUniq :
      ∀ m', m' ∈ [wave28SmokeMethod] → m'.isPublic = true →
        (m'.name == wave28SmokeMethod.name) = true → m' = wave28SmokeMethod := by
    intro m' hm' _ _
    simp only [List.mem_singleton] at hm'
    exact hm'
  exact runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome
    contractName ([] : List ANFProperty) [wave28SmokeMethod] wave28SmokeMethod initialStack
    sm' stkFinal List.mem_cons_self rfl hUniq hArith
    wave28_noPreimage wave28_noCode wave28_noTerminalAssert wave28_noDeserialize

/-! ### Wave 30 (option B) — the both-fail leg / failure lockstep

Wave 28 closes the SUCCESS branch of the consume-arith fragment: under
`taggedAllBigint` (every aligned slot a bigint) the lockstep builds the
full `structuralArithConsumeBody` and both evaluators succeed.  The
wave-29 BLOCK is that the M2 capstone needs `taggedAllBigint`, which the
retirement dispatch cannot supply (not decidable on a symbolic
`initialAnf`, not derivable from `agreesTagged` / `WF`).

Option B removes the dependency by handling the NON-bigint case directly.
`taggedAllBigint` (all SLOTS bigint) is sufficient-but-not-necessary for
success — a non-bigint slot the body never reads is harmless — so the
correct structure is a per-binding FAILURE LOCKSTEP: at the first binding
whose operand value is not a bigint, BOTH evaluators fail at the same
binding, so the success bits still match (`False ↔ False`).

The three substrate pieces, all add-only:

* **ANF-side failure** (`evalBindings_binOp_nonBigint_isNone` /
  `_unary_`): an emittable arith binding whose operand resolves to a
  non-bigint value makes `evalValue` `.error` (the `evalBinOp` /
  `evalUnaryOp` match falls through to a catch-all `.error` on non-bigint),
  and `evalBindings` of the whole `binding :: rest` body inherits the
  error (`isNone`) regardless of `rest`.
* **Stack-side failure** (`runOps_binopOpcode_nonInt_isNone` /
  `_unaryOpcode_`): the lowered emittable arith opcode on a stack whose
  relevant top operand is non-int makes `runOpcode` (= `liftIntBin` /
  `liftIntUnary`) `.error`, and `runOps` of the whole op list inherits the
  error (`isNone`) regardless of the trailing ops.
* **The failure lockstep** (`successAgrees_arith_consume_first_binOp_fail`
  / `_unary_`): under `agreesTagged` the top stack value equals the head
  operand value on the ANF side; when that value is non-bigint both sides
  fail at the first binding, so `successAgrees` holds as `False ↔ False`.

The values used here are `RunarVerification.ANF.Eval.Value`; the same
type backs both the ANF state and the runtime stack.  `.vBytes` / `.vOpaque`
/ `.vThis` are the non-bigint, non-bool witnesses that fail BOTH
`evalBinOp` (catch-all) and `Stack.Eval.asInt?` (`none`). -/

/-- A reusable `popN s 2` reduction for a two-deep stack.  `Stack.Sim`'s
`popN_two_local` is `private`, and `Stack.Peephole.popN_two_cons` is not
in this module's import closure, so we prove the (one-line) reduction
locally for the failure lemmas below. -/
private theorem popN_two_consA3
    (s : StackState) (b a : RunarVerification.ANF.Eval.Value)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hs : s.stack = b :: a :: rest) :
    Stack.Eval.popN s 2 = .ok ([b, a], { s with stack := rest }) := by
  unfold Stack.Eval.popN StackState.pop?
  rw [hs]
  simp only [Stack.Eval.popN, StackState.pop?]

/-- A reusable `pop? s` reduction for a one-deep stack (the unary case). -/
private theorem pop_one_consA3
    (s : StackState) (a : RunarVerification.ANF.Eval.Value)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hs : s.stack = a :: rest) :
    s.pop? = some (a, { s with stack := rest }) := by
  unfold StackState.pop?
  rw [hs]

/-! #### ANF-side failure -/

/-- **Wave 30 — ANF-side `binOp` failure on a non-bigint left operand.**

For an emittable arith binOp (`"+"` / `"-"` / `"*"`) whose LEFT operand
resolves to a non-bigint, non-bool value, `evalBinOp` falls through to its
catch-all `.error` arm, so `evalValue` is `.error`, and `evalBindings` of
the whole `binding :: rest` body is `.error` (`toOption.isNone`) — the
error short-circuits the `do`-bind before `rest` is ever reached. -/
theorem evalBindings_binOp_nonBigint_left_isNone
    (anfSt : State) (name op l r : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (bl br : RunarVerification.ANF.Eval.Value)
    (rest : List ANFBinding)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*")
    (hl : anfSt.resolveRef l = some bl)
    (hr : anfSt.resolveRef r = some br)
    (hNonBigintL : ∀ i : Int, bl ≠ .vBigint i) :
    (RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.binOp op l r rt) src :: rest)).toOption.isNone := by
  -- The left operand is non-bigint / non-bool ⇒ `evalBinOp` catch-all `.error`.
  have hBinOp : ∃ e, RunarVerification.ANF.Eval.evalBinOp op bl br rt = .error e := by
    cases bl with
    | vBigint i => exact absurd rfl (hNonBigintL i)
    | vBool b =>
        rcases hEmit with h | h | h <;> subst h <;>
          (cases br <;> exact ⟨_, rfl⟩)
    | vBytes b =>
        rcases hEmit with h | h | h <;> subst h <;>
          (cases br <;> exact ⟨_, rfl⟩)
    | vOpaque b =>
        rcases hEmit with h | h | h <;> subst h <;>
          (cases br <;> exact ⟨_, rfl⟩)
    | vThis =>
        rcases hEmit with h | h | h <;> subst h <;>
          (cases br <;> exact ⟨_, rfl⟩)
  obtain ⟨e, hBinOp⟩ := hBinOp
  have hVal : RunarVerification.ANF.Eval.evalValue anfSt (.binOp op l r rt) = .error e := by
    simp only [RunarVerification.ANF.Eval.evalValue,
      RunarVerification.ANF.Eval.lookupRef, hl, hr, bind, Except.bind, hBinOp]
  show (RunarVerification.ANF.Eval.evalBindings anfSt
      (.mk name (.binOp op l r rt) src :: rest)).toOption.isNone
  simp only [RunarVerification.ANF.Eval.evalBindings, hVal, bind, Except.bind]
  rfl

/-- **Wave 30 — ANF-side `unaryOp` failure on a non-bigint operand.**

For the emittable arith unaryOp (`"-"` = NEGATE) whose operand resolves
to a non-bigint value, `evalUnaryOp` falls through to its catch-all
`.error` arm (the `"-"` arm requires `.vBigint`), so `evalBindings` of the
whole body is `.error` (`toOption.isNone`). -/
theorem evalBindings_unary_nonBigint_isNone
    (anfSt : State) (name operand : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (ov : RunarVerification.ANF.Eval.Value)
    (rest : List ANFBinding)
    (hOperand : anfSt.resolveRef operand = some ov)
    (hNonBigint : ∀ i : Int, ov ≠ .vBigint i) :
    (RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.unaryOp "-" operand rt) src :: rest)).toOption.isNone := by
  have hUnary : ∃ e, RunarVerification.ANF.Eval.evalUnaryOp "-" ov rt = .error e := by
    cases ov with
    | vBigint i => exact absurd rfl (hNonBigint i)
    | vBool b => exact ⟨_, rfl⟩
    | vBytes b => exact ⟨_, rfl⟩
    | vOpaque b => exact ⟨_, rfl⟩
    | vThis => exact ⟨_, rfl⟩
  obtain ⟨e, hUnary⟩ := hUnary
  have hVal : RunarVerification.ANF.Eval.evalValue anfSt (.unaryOp "-" operand rt) = .error e := by
    simp only [RunarVerification.ANF.Eval.evalValue,
      RunarVerification.ANF.Eval.lookupRef, hOperand, bind, Except.bind, hUnary]
  show (RunarVerification.ANF.Eval.evalBindings anfSt
      (.mk name (.unaryOp "-" operand rt) src :: rest)).toOption.isNone
  simp only [RunarVerification.ANF.Eval.evalBindings, hVal, bind, Except.bind]
  rfl

/-! #### Stack-side failure -/

/-- The three non-bigint, non-bool stack witnesses (`.vBytes` / `.vOpaque`
/ `.vThis`) all give `Stack.Eval.asInt? = none`, the failure trigger for
`liftIntBin` / `liftIntUnary`.  An ANF-side non-bigint value is one of
these three exactly when it is not a `.vBool` either; the failure-leg
caller restricts to that case (a `.vBool` is `asInt?`-coercible on the
stack, so it would NOT fail the stack op — it is excluded from the leg). -/
theorem asInt_none_of_vBytes (bs : ByteArray) :
    Stack.Eval.asInt? (.vBytes bs) = none := rfl
theorem asInt_none_of_vOpaque (bs : ByteArray) :
    Stack.Eval.asInt? (.vOpaque bs) = none := rfl
theorem asInt_none_of_vThis :
    Stack.Eval.asInt? (.vThis) = none := rfl

/-- **Wave 30 — `liftIntBin` fails when the top operand is non-int.**

`liftIntBin` pops two (`[b, a]`, `b` = top), then requires both
`asInt? a` and `asInt? b` to be `some`.  When the top `b` is non-int
(`asInt? b = none`) the inner match falls to the `.error` arm regardless
of `a`. -/
theorem liftIntBin_nonInt_top_isError
    (s : StackState) (f : Int → Int → RunarVerification.ANF.Eval.Value)
    (b a : RunarVerification.ANF.Eval.Value)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hStk : s.stack = b :: a :: rest)
    (hNonInt : Stack.Eval.asInt? b = none) :
    ∃ e, Stack.Eval.liftIntBin s f = .error e := by
  unfold Stack.Eval.liftIntBin
  rw [popN_two_consA3 s b a rest hStk]
  simp only [hNonInt]
  cases Stack.Eval.asInt? a <;> exact ⟨_, rfl⟩

/-- **Wave 30 — `liftIntUnary` fails when the operand is non-int.** -/
theorem liftIntUnary_nonInt_isError
    (s : StackState) (f : Int → RunarVerification.ANF.Eval.Value)
    (v : RunarVerification.ANF.Eval.Value)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hStk : s.stack = v :: rest)
    (hNonInt : Stack.Eval.asInt? v = none) :
    ∃ e, Stack.Eval.liftIntUnary s f = .error e := by
  unfold Stack.Eval.liftIntUnary
  rw [pop_one_consA3 s v rest hStk]
  simp only [hNonInt]
  exact ⟨_, rfl⟩

/-- For the three emittable binops the lowered opcode is one of
`OP_ADD` / `OP_SUB` / `OP_MUL`, each `liftIntBin`-shaped, so it fails on a
non-int top.  Stated as a `runOpcode` error so it composes with `runOps`. -/
theorem runOpcode_binopOpcode_emittable_nonInt_top_isError
    (op : String) (rt : Option String) (s : StackState)
    (b a : RunarVerification.ANF.Eval.Value)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*")
    (hStk : s.stack = b :: a :: rest)
    (hNonInt : Stack.Eval.asInt? b = none) :
    ∃ e, Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt) s = .error e := by
  rcases hEmit with h | h | h <;> subst h
  · rw [show Stack.Lower.binopOpcode "+" rt = "OP_ADD" from rfl,
        Stack.Sim.runOpcode_ADD_def]
    exact liftIntBin_nonInt_top_isError s _ b a rest hStk hNonInt
  · rw [show Stack.Lower.binopOpcode "-" rt = "OP_SUB" from rfl,
        Stack.Sim.runOpcode_SUB_def]
    exact liftIntBin_nonInt_top_isError s _ b a rest hStk hNonInt
  · rw [show Stack.Lower.binopOpcode "*" rt = "OP_MUL" from rfl,
        Stack.Sim.runOpcode_MUL_def]
    exact liftIntBin_nonInt_top_isError s _ b a rest hStk hNonInt

/-- The emittable unary opcode is `OP_NEGATE` (`liftIntUnary`-shaped). -/
theorem runOpcode_unaryOpcode_emittable_nonInt_isError
    (s : StackState) (v : RunarVerification.ANF.Eval.Value)
    (rest : List RunarVerification.ANF.Eval.Value)
    (hStk : s.stack = v :: rest)
    (hNonInt : Stack.Eval.asInt? v = none) :
    ∃ e, Stack.Eval.runOpcode (Stack.Lower.unaryOpcode "-") s = .error e := by
  rw [show Stack.Lower.unaryOpcode "-" = "OP_NEGATE" from rfl,
      Stack.Sim.runOpcode_NEGATE_def]
  exact liftIntUnary_nonInt_isError s _ v rest hStk hNonInt

/-- `runOps` short-circuits to `.error` (`isNone`) when the FIRST op is an
opcode that errors on the current stack, regardless of the trailing ops.
This is the stack-side dual of the ANF `do`-bind short-circuit. -/
theorem runOps_opcode_error_head_isNone
    (code : String) (rest : List StackOp) (s : StackState)
    (e : RunarVerification.ANF.Eval.EvalError)
    (hErr : Stack.Eval.runOpcode code s = .error e) :
    (runOps (.opcode code :: rest) s).toOption.isNone := by
  -- `.opcode code` is not an `.ifOp`, so `runOps` reduces via `stepNonIf`.
  show (runOps (.opcode code :: rest) s).toOption.isNone
  unfold runOps
  rw [Stack.Eval.stepNonIf, hErr]
  rfl

/-- **Wave 30 — stack-side `binOp` failure, whole op list.**

When the emittable arith op is the head opcode and the top stack operand
is non-int, `runOps` of the full op list is `.error` (`isNone`). -/
theorem runOps_binopOpcode_emittable_nonInt_top_isNone
    (op : String) (rt : Option String) (rest : List StackOp) (s : StackState)
    (b a : RunarVerification.ANF.Eval.Value)
    (stkRest : List RunarVerification.ANF.Eval.Value)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*")
    (hStk : s.stack = b :: a :: stkRest)
    (hNonInt : Stack.Eval.asInt? b = none) :
    (runOps (.opcode (Stack.Lower.binopOpcode op rt) :: rest) s).toOption.isNone := by
  obtain ⟨e, hErr⟩ :=
    runOpcode_binopOpcode_emittable_nonInt_top_isError op rt s b a stkRest hEmit hStk hNonInt
  exact runOps_opcode_error_head_isNone (Stack.Lower.binopOpcode op rt) rest s e hErr

/-- **Wave 30 — stack-side `unaryOp` failure, whole op list.** -/
theorem runOps_unaryOpcode_emittable_nonInt_isNone
    (rest : List StackOp) (s : StackState)
    (v : RunarVerification.ANF.Eval.Value)
    (stkRest : List RunarVerification.ANF.Eval.Value)
    (hStk : s.stack = v :: stkRest)
    (hNonInt : Stack.Eval.asInt? v = none) :
    (runOps (.opcode (Stack.Lower.unaryOpcode "-") :: rest) s).toOption.isNone := by
  obtain ⟨e, hErr⟩ :=
    runOpcode_unaryOpcode_emittable_nonInt_isError s v stkRest hStk hNonInt
  exact runOps_opcode_error_head_isNone (Stack.Lower.unaryOpcode "-") rest s e hErr

/-! #### The failure lockstep — both sides fail at the first binding

`agreesTagged` ties the stack top to the head operand's ANF value: the
positional alignment means `stkSt.stack`'s top equals the value the head
slot resolves to.  When the head operand is non-bigint AND non-bool, both
evaluators fail at the first binding (the ANF `evalBinOp` catch-all and
the stack `liftIntBin` non-int check), so `successAgrees` is `False ↔ False`.

The leg restricts the non-bigint value to be ALSO non-bool: a `.vBool`
operand fails `evalBinOp` (the `"+"`/`"-"`/`"*"` arms need `.vBigint`) but
NOT the stack op (`Stack.Eval.asInt?` coerces `.vBool` to 0/1).  Such a
value would make the two sides DISAGREE — but it cannot arise in the
fragment: the consume-arith bindings only thread bigint results, and the
entry params of an arith method are bigint-typed, so a `.vBool` operand is
outside `emittableArithChainReady`'s reachable states.  The non-bool
restriction is exactly the both-fail witness class (`.vBytes` / `.vOpaque`
/ `.vThis`). -/

/-- A non-bigint, non-bool ANF value gives `Stack.Eval.asInt? = none`
(the stack-side failure trigger): the only `asInt?`-coercible non-bigint
value is `.vBool`, which is excluded. -/
theorem asInt_none_of_nonBigint_nonBool
    (v : RunarVerification.ANF.Eval.Value)
    (hNonBigint : ∀ i : Int, v ≠ .vBigint i)
    (hNonBool : ∀ b : Bool, v ≠ .vBool b) :
    Stack.Eval.asInt? v = none := by
  cases v with
  | vBigint i => exact absurd rfl (hNonBigint i)
  | vBool b => exact absurd rfl (hNonBool b)
  | vBytes b => rfl
  | vOpaque b => rfl
  | vThis => rfl

/-- The head operand value pinned by `agreesTagged` on a two-deep
alignment: the stack decomposes as `v0 :: v1 :: restStk` with `v0` the
value the head slot `(l, k_l)` resolves to via `lookupAnfByKind`. -/
theorem agreesTagged_head_two_stack_value
    (l r : String) (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt) :
    ∃ v0 v1 restStk,
      stkSt.stack = v0 :: v1 :: restStk ∧ lookupAnfByKind anfSt (l, k_l) = some v0 := by
  have hAlign : taggedStackAligned ((l, k_l) :: (r, k_r) :: tsm_rest)
      anfSt stkSt.stack := hAgrees.1
  match hCases : stkSt.stack with
  | [] =>
      rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
      exact absurd hAlign (by simp)
  | [_] =>
      rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      unfold taggedStackAligned at hTail
      exact absurd hTail (by simp)
  | v0 :: v1 :: restStk =>
      refine ⟨v0, v1, restStk, rfl, ?_⟩
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      exact hAlign.1

/-- The head operand value pinned by `agreesTagged` on a one-deep
alignment (unary case). -/
theorem agreesTagged_head_one_stack_value
    (operand : String) (k_op : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (hAgrees : agreesTagged ((operand, k_op) :: tsm_rest) anfSt stkSt) :
    ∃ v0 restStk,
      stkSt.stack = v0 :: restStk ∧ lookupAnfByKind anfSt (operand, k_op) = some v0 := by
  have hAlign : taggedStackAligned ((operand, k_op) :: tsm_rest)
      anfSt stkSt.stack := hAgrees.1
  match hCases : stkSt.stack with
  | [] =>
      rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
      exact absurd hAlign (by simp)
  | v0 :: restStk =>
      refine ⟨v0, restStk, rfl, ?_⟩
      rw [hCases] at hAlign
      unfold taggedStackAligned at hAlign
      exact hAlign.1

/-- **Wave 30 — failure lockstep at the first binary binding.**

Under `agreesTagged`, the stack top equals the head operand value the
`(l, k_l)` slot resolves to via `lookupAnfByKind`.  The operand
CORRESPONDENCE — that the ANF evaluator's `resolveRef l` reads the SAME
slot value — is supplied as `hHeadCorr` (`resolveRef l = lookupAnfByKind
(l, k_l)`).  This holds in the consume-arith fragment: at the binding
where the head operand is first read, `l` is a param / earlier-temp with
no shadowing binding, so `resolveRef` and the kind-specific lookup agree.
When that shared value is non-bigint AND non-bool, BOTH evaluators fail at
this first binding, so `successAgrees` holds as `False ↔ False`. -/
theorem successAgrees_arith_consume_first_binOp_fail
    (anfSt : State) (stkSt : StackState)
    (name op l r : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfRest : List ANFBinding) (stkRest : List StackOp)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*")
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt)
    (hHeadCorr : anfSt.resolveRef l = lookupAnfByKind anfSt (l, k_l))
    (hNonBigint : ∀ (i : Int) (v : RunarVerification.ANF.Eval.Value),
      lookupAnfByKind anfSt (l, k_l) = some v → v ≠ .vBigint i)
    (hNonBool : ∀ (b : Bool) (v : RunarVerification.ANF.Eval.Value),
      lookupAnfByKind anfSt (l, k_l) = some v → v ≠ .vBool b)
    (br : RunarVerification.ANF.Eval.Value)
    (hResolveR : anfSt.resolveRef r = some br) :
    -- Definitionally `successAgrees a b` (= `a.toOption.isSome ↔ b.toOption.isSome`);
    -- `successAgrees` itself lives in `Pipeline`, which post-dates this module, so
    -- we state the unfolded iff (the retirement dispatch consumes it through the
    -- `successAgrees` definitional unfold).
    ((RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.binOp op l r rt) src :: anfRest)).toOption.isSome
      ↔ (runOps (.opcode (Stack.Lower.binopOpcode op rt) :: stkRest) stkSt).toOption.isSome) := by
  -- Stack top = the head slot value `v0` from the alignment.
  obtain ⟨v0, v1, restStk, hStk, hLookup⟩ :=
    agreesTagged_head_two_stack_value l r k_l k_r tsm_rest anfSt stkSt hAgrees
  have hResolveL : anfSt.resolveRef l = some v0 := by rw [hHeadCorr]; exact hLookup
  have hNB : ∀ i : Int, v0 ≠ .vBigint i := fun i => hNonBigint i v0 hLookup
  have hNBool : ∀ b : Bool, v0 ≠ .vBool b := fun b => hNonBool b v0 hLookup
  have hNonInt : Stack.Eval.asInt? v0 = none :=
    asInt_none_of_nonBigint_nonBool v0 hNB hNBool
  -- ANF side fails.
  have hANF :
      (RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.binOp op l r rt) src :: anfRest)).toOption.isNone :=
    evalBindings_binOp_nonBigint_left_isNone anfSt name op l r rt src v0 br anfRest
      hEmit hResolveL hResolveR hNB
  -- Stack side fails.
  have hStack :
      (runOps (.opcode (Stack.Lower.binopOpcode op rt) :: stkRest) stkSt).toOption.isNone :=
    runOps_binopOpcode_emittable_nonInt_top_isNone op rt stkRest stkSt v0 v1 restStk
      hEmit hStk hNonInt
  -- Both sides `isNone`, so the iff is `False ↔ False`.
  rw [Option.isNone_iff_eq_none] at hANF hStack
  simp only [hANF, hStack, Option.isSome_none]

/-- **Wave 30 — failure lockstep at the first unary (NEGATE) binding.**
Conclusion is the unfolded `successAgrees` iff (see the binOp peer). -/
theorem successAgrees_arith_consume_first_unary_fail
    (anfSt : State) (stkSt : StackState)
    (name operand : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (k_op : SlotKind) (tsm_rest : TaggedStackMap)
    (anfRest : List ANFBinding) (stkRest : List StackOp)
    (hAgrees : agreesTagged ((operand, k_op) :: tsm_rest) anfSt stkSt)
    (hHeadCorr : anfSt.resolveRef operand = lookupAnfByKind anfSt (operand, k_op))
    (hNonBigint : ∀ (i : Int) (v : RunarVerification.ANF.Eval.Value),
      lookupAnfByKind anfSt (operand, k_op) = some v → v ≠ .vBigint i)
    (hNonBool : ∀ (b : Bool) (v : RunarVerification.ANF.Eval.Value),
      lookupAnfByKind anfSt (operand, k_op) = some v → v ≠ .vBool b) :
    ((RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.unaryOp "-" operand rt) src :: anfRest)).toOption.isSome
      ↔ (runOps (.opcode (Stack.Lower.unaryOpcode "-") :: stkRest) stkSt).toOption.isSome) := by
  obtain ⟨v0, restStk, hStk, hLookup⟩ :=
    agreesTagged_head_one_stack_value operand k_op tsm_rest anfSt stkSt hAgrees
  have hResolve : anfSt.resolveRef operand = some v0 := by rw [hHeadCorr]; exact hLookup
  have hNB : ∀ i : Int, v0 ≠ .vBigint i := fun i => hNonBigint i v0 hLookup
  have hNBool : ∀ b : Bool, v0 ≠ .vBool b := fun b => hNonBool b v0 hLookup
  have hNonInt : Stack.Eval.asInt? v0 = none :=
    asInt_none_of_nonBigint_nonBool v0 hNB hNBool
  have hANF :
      (RunarVerification.ANF.Eval.evalBindings anfSt
        (.mk name (.unaryOp "-" operand rt) src :: anfRest)).toOption.isNone :=
    evalBindings_unary_nonBigint_isNone anfSt name operand rt src v0 anfRest hResolve hNB
  have hStack :
      (runOps (.opcode (Stack.Lower.unaryOpcode "-") :: stkRest) stkSt).toOption.isNone :=
    runOps_unaryOpcode_emittable_nonInt_isNone stkRest stkSt v0 restStk hStk hNonInt
  rw [Option.isNone_iff_eq_none] at hANF hStack
  simp only [hANF, hStack, Option.isSome_none]

/-! ### Wave 30 — MANDATORY smoke tests (both branches)

The NEW PIECE is the non-bigint BOTH-FAIL smoke: a concrete emittable-arith
body with a non-bigint operand, entry `agreesTagged`, where BOTH
`evalBindings` and the stack `runOps` are `isNone`, so the success bits
match (`False ↔ False`).  We prove BOTH `isNone` facts CONCRETELY and then
fire `successAgrees_arith_consume_first_binOp_fail` to assemble the iff.

The bigint branch is the existing wave-28 success path
(`wave28_general_lockstep_capstone_smoke`, both sides `isSome`); a thin
re-statement is recorded at the end so both branches are pinned in this
module. -/

/-- Concrete ANF state for the non-bigint smoke: param `p0` is a
NON-bigint (`.vBytes #[1]`), `p1` a bigint.  No bindings (so `resolveRef`
agrees with the param lookup at the head). -/
private def wave30NonBigintAnf : State :=
  { params := [("p0", .vBytes (ByteArray.mk #[1])), ("p1", .vBigint 5)] }

/-- Concrete runtime stack aligned with `wave30NonBigintAnf`: top is the
non-bigint `.vBytes #[1]` (= `p0`), second is `.vBigint 5` (= `p1`). -/
private def wave30NonBigintStk : StackState :=
  { stack := [.vBytes (ByteArray.mk #[1]), .vBigint 5] }

/-- Entry alignment for the non-bigint smoke (params `p0`, `p1`). -/
private theorem wave30_nonBigint_agreesTagged :
    agreesTagged [("p0", .param), ("p1", .param)]
      wave30NonBigintAnf wave30NonBigintStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("p0", .param), ("p1", .param)]
    wave30NonBigintAnf wave30NonBigintStk.stack
  refine ⟨?_, ?_, ?_⟩
  · show lookupAnfByKind wave30NonBigintAnf ("p0", .param)
        = some (.vBytes (ByteArray.mk #[1]))
    rfl
  · show lookupAnfByKind wave30NonBigintAnf ("p1", .param) = some (.vBigint 5)
    rfl
  · trivial

/-- **Wave 30 — the non-bigint BOTH-FAIL smoke (THE NEW PIECE).**

The concrete body is a single emittable-arith binding `t0 = p0 + p1`
whose left operand `p0` is the non-bigint `.vBytes #[1]`.  We show:

1. the ANF side `evalBindings` is `isNone` (the `evalBinOp "+"` catch-all
   fires on the `.vBytes` operand);
2. the stack side `runOps [OP_ADD]` is `isNone` (`liftIntBin` rejects the
   non-int top, `Stack.Eval.asInt? (.vBytes _) = none`); and
3. therefore the `successAgrees` iff holds as `False ↔ False`.

All three are DISCHARGED CONCRETELY — (1) and (2) standalone, then (3)
via `successAgrees_arith_consume_first_binOp_fail`. -/
theorem wave30_nonBigint_both_fail_smoke :
    -- (1) ANF side fails.
    (RunarVerification.ANF.Eval.evalBindings wave30NonBigintAnf
        [.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isNone
    -- (2) Stack side fails.
    ∧ (runOps [.opcode (Stack.Lower.binopOpcode "+" none)]
        wave30NonBigintStk).toOption.isNone
    -- (3) The success bits agree (`False ↔ False`).
    ∧ ((RunarVerification.ANF.Eval.evalBindings wave30NonBigintAnf
          [.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isSome
        ↔ (runOps [.opcode (Stack.Lower.binopOpcode "+" none)]
            wave30NonBigintStk).toOption.isSome) := by
  have hNonBigint : ∀ i : Int,
      (RunarVerification.ANF.Eval.Value.vBytes (ByteArray.mk #[1])) ≠ .vBigint i := by
    intro i h; exact absurd h (by simp)
  -- (1) ANF side: standalone failure lemma.
  have hANF :
      (RunarVerification.ANF.Eval.evalBindings wave30NonBigintAnf
        [.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isNone :=
    evalBindings_binOp_nonBigint_left_isNone wave30NonBigintAnf "t0" "+" "p0" "p1" none none
      (.vBytes (ByteArray.mk #[1])) (.vBigint 5) []
      (Or.inl rfl) rfl rfl hNonBigint
  -- (2) Stack side: standalone failure lemma.
  have hStack :
      (runOps [.opcode (Stack.Lower.binopOpcode "+" none)]
        wave30NonBigintStk).toOption.isNone :=
    runOps_binopOpcode_emittable_nonInt_top_isNone "+" none []
      wave30NonBigintStk (.vBytes (ByteArray.mk #[1])) (.vBigint 5) []
      (Or.inl rfl) rfl rfl
  refine ⟨hANF, hStack, ?_⟩
  -- (3) Assemble via the failure lockstep theorem.
  exact successAgrees_arith_consume_first_binOp_fail
    wave30NonBigintAnf wave30NonBigintStk "t0" "+" "p0" "p1" none none
    .param .param [] [] []
    (Or.inl rfl) wave30_nonBigint_agreesTagged rfl
    (fun i v hv => by
      have hvEq : v = .vBytes (ByteArray.mk #[1]) := by
        have hp : lookupAnfByKind wave30NonBigintAnf ("p0", .param)
            = some (.vBytes (ByteArray.mk #[1])) := rfl
        rw [hp] at hv; exact (Option.some.inj hv).symm
      subst hvEq; exact hNonBigint i)
    (fun b v hv => by
      have hvEq : v = .vBytes (ByteArray.mk #[1]) := by
        have hp : lookupAnfByKind wave30NonBigintAnf ("p0", .param)
            = some (.vBytes (ByteArray.mk #[1])) := rfl
        rw [hp] at hv; exact (Option.some.inj hv).symm
      subst hvEq; intro h; exact absurd h (by simp))
    (.vBigint 5) rfl

/-- **Wave 30 — the bigint BOTH-SUCCEED branch (confirmation).**

The success branch is the wave-28 capstone unchanged: from a BARE entry
`agreesTagged` over bigint params plus `taggedAllBigint`, the lockstep
builds `structuralArithConsumeBody` and `runMethod … isSome`.  We restate
it here so both legs of the wave-30 dichotomy are pinned in one module.
This is the leg the failure lockstep COMPLEMENTS: all-bigint reads ⇒ both
succeed; first non-bigint read ⇒ both fail. -/
theorem wave30_bigint_both_succeed_branch
    (contractName : String) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap) (anfSt0 : State)
    (hUntag : untagSm tsm = ["p0", "p1", "p2", "p3", "p4"])
    (hAgrees0 : agreesTagged tsm anfSt0 initialStack)
    (hAllBigint : taggedAllBigint anfSt0 tsm) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := ([] : List ANFProperty),
            methods := [wave28SmokeMethod] })
        wave28SmokeMethod.name initialStack).toOption.isSome :=
  wave28_general_lockstep_capstone_smoke contractName initialStack tsm anfSt0
    hUntag hAgrees0 hAllBigint

/-! ### Wave 32 — per-binding SUCCESS lockstep (the substrate gate-closer)

The success-direction analogue of wave 30's failure step.  Wave 30 closed
the BOTH-FAIL leg (head operand non-bigint ⇒ both `isNone`).  Wave 32
closes the BOTH-SUCCEED leg with the SAME per-binding HEAD-only hypothesis
class: when the head operands of the current emittable-arith binding both
resolve to bigints (HEAD only, NOT whole-state `taggedAllBigint`), BOTH
evaluators advance by exactly one binding, and `agreesTagged` is
re-established at the new state for the IH.

The pieces:
* the ANF cons-step (`evalBindings_binOp_bigint_cons_step`, wave 32 A);
* the stack cons-step (`runOps_binopOpcode_bigint_cons_step`, wave 32 B);
* the result-agreement (ANF surface-op result = stack opcode result); and
* the `agreesTagged` transport (`agreesTagged_consume_top_two`, wave 27).

This is the lemma the walk induction (next wave) composes with wave 30's
failure step to get the unconditional `successAgrees` over arbitrary
emittable-arith bodies — head-bigint per binding, never whole-state. -/

/-- Both top-two stack values pinned by a two-deep `agreesTagged`
alignment.  Strengthens `agreesTagged_head_two_stack_value` to also pin
the SECOND value to the `(r, k_r)` slot — needed because the success
lockstep reads BOTH operands as bigints. -/
theorem agreesTagged_head_two_stack_values_full
    (l r : String) (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt) :
    ∃ v0 v1 restStk,
      stkSt.stack = v0 :: v1 :: restStk
        ∧ lookupAnfByKind anfSt (l, k_l) = some v0
        ∧ lookupAnfByKind anfSt (r, k_r) = some v1 := by
  have hAlign : taggedStackAligned ((l, k_l) :: (r, k_r) :: tsm_rest)
      anfSt stkSt.stack := hAgrees.1
  match hCases : stkSt.stack with
  | [] =>
      rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
      exact absurd hAlign (by simp)
  | [_] =>
      rw [hCases] at hAlign; unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      unfold taggedStackAligned at hTail
      exact absurd hTail (by simp)
  | v0 :: v1 :: restStk =>
      refine ⟨v0, v1, restStk, rfl, ?_, ?_⟩
      · rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        exact hAlign.1
      · rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        obtain ⟨_, hTail⟩ := hAlign
        unfold taggedStackAligned at hTail
        exact hTail.1

/-- The ANF surface-op result equals the stack opcode result for the three
emittable arith binops (`a` second-from-top, `b` top).  Bridges
`arithBinResultBigint` (ANF, surface `op`) and `binOpcodeResultInt`
(stack, `binopOpcode op rt`). -/
theorem arithBinResult_eq_binOpcodeResult
    (op : String) (rt : Option String) (a b : Int)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*") :
    RunarVerification.ANF.Eval.arithBinResultBigint op a b
      = RunarVerification.Stack.Eval.binOpcodeResultInt (Stack.Lower.binopOpcode op rt) a b := by
  rcases hEmit with h | h | h <;> subst h <;> rfl

/-- The unary peer result-agreement: ANF `arithUnaryResultBigint "-" a` =
the stack `OP_NEGATE` push value `-a`. -/
theorem arithUnaryResult_eq_negate (a : Int) :
    RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a = -a := rfl

/-- The pushed result of an emittable arith binOp's per-binding chunk.

The lowered d0d1 chunk is `[.swap, .opcode (binopOpcode op rt)]`: the swap
reorders the `agreesTagged` stack (top `l`-value = `a`, second `r`-value =
`b`) into opcode order (top `b`, second `a`), so the opcode pushes
`a ⊙ b` — the SAME value the ANF surface op (`arithBinResultBigint op a b`)
produces.  Discharges the `hOpcode` hypothesis of
`build_consume_binOp_witness_d0d1` uniformly for emittable ops. -/
theorem build_consume_emittable_binOp_opcodeFact
    (op : String) (rt : Option String) (stkSt : StackState) (a b : Int)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*") :
    ∀ (restStk : List RunarVerification.ANF.Eval.Value),
      stkSt.stack = .vBigint a :: .vBigint b :: restStk →
      Stack.Eval.runOpcode (Stack.Lower.binopOpcode op rt)
          ({stkSt with stack := .vBigint b :: .vBigint a :: restStk})
        = .ok ({stkSt with stack := restStk}.push
            (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))) := by
  intro restStk _hStk
  have hOp := runOpcode_emittableBinOp op rt
    ({stkSt with stack := .vBigint b :: .vBigint a :: restStk}) a b restStk rfl hEmit
  -- `emittableBinOpResult op a b = arithBinResultBigint op a b` (emittable).
  have hRes : emittableBinOpResult op a b
      = RunarVerification.ANF.Eval.arithBinResultBigint op a b := by
    rcases hEmit with h | h | h <;> subst h <;> rfl
  rw [hRes] at hOp
  exact hOp

/-- **Wave 32 — per-binding SUCCESS lockstep at a binary binding.**

The success-direction analogue of wave 30's failure step, stated over the
REAL per-binding lowered op chunk `(lowerValueP …).1` (the d0d1 chunk
`[.swap, .opcode (binopOpcode op rt)]`) ++ trailing `restOps` — NOT a bare
opcode (the bare opcode gets the operand order wrong for non-commutative
ops; the swap in the chunk fixes it).

Under `agreesTagged` over `(l, k_l) :: (r, k_r) :: tsm_rest`, the stack top
two equal the operand values the head slots resolve to.  Given BOTH head
operands resolve to `.vBigint` (HEAD-only, via `lookupAnfByKind`; the ANF
`resolveRef` reading the SAME slots is `hHeadCorrL` / `hHeadCorrR`), `op`
emittable, the d0d1 consume layout (depth/last-use facts), and SSA
freshness, BOTH evaluators advance by exactly one binding:

* the success bits agree (literally equal — both sides reduce to the same
  `runOps`/`evalBindings` continuation on the post-state), and
* `agreesTagged` holds at the post-consume state for the IH, with the new
  binding `name ↦ .vBigint (arithBinResultBigint op a b)`.

Needs ONLY head-operand bigint-ness, never whole-state `taggedAllBigint`.
The chunk-`++`-`restOps` packaging is `runOps_append` + the wave-27
operational chunk witness (`build_consume_binOp_witness_d0d1`). -/
theorem agrees_success_step_binOp
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (anfSt : State) (stkSt : StackState)
    (name op l r : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (k_l k_r : SlotKind) (tsm_rest : TaggedStackMap)
    (anfRest : List ANFBinding) (restOps : List StackOp)
    (a b : Int)
    (hEmit : op = "+" ∨ op = "-" ∨ op = "*")
    (hDepthL : sm.depth? l = some 0)
    (hDepthR : sm.depth? r = some 1)
    (hLastUseL : Stack.Lower.isLastUse lastUses l currentIndex = true)
    (hLastUseR : Stack.Lower.isLastUse lastUses r currentIndex = true)
    (hNotBytes : (op == "!==" && rt == some "bytes") = false)
    (hAgrees : agreesTagged ((l, k_l) :: (r, k_r) :: tsm_rest) anfSt stkSt)
    (hHeadCorrL : anfSt.resolveRef l = lookupAnfByKind anfSt (l, k_l))
    (hHeadCorrR : anfSt.resolveRef r = lookupAnfByKind anfSt (r, k_r))
    (hBigintL : lookupAnfByKind anfSt (l, k_l) = some (.vBigint a))
    (hBigintR : lookupAnfByKind anfSt (r, k_r) = some (.vBigint b))
    (hFresh : freshIn name (untagSm tsm_rest)) :
    -- The PRE-state success-relation TRANSPORTS to the POST-state one:
    -- the head binding's success is unconditional (both operands bigint),
    -- so the whole-body success bits agree IFF the tail continuations'
    -- success bits agree.  The walk induction (next wave) discharges the
    -- POST iff via the IH; here we expose the one-step transport + the
    -- preserved `agreesTagged`.
    ( ( (RunarVerification.ANF.Eval.evalBindings anfSt
            (.mk name (.binOp op l r rt) src :: anfRest)).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.binOp op l r rt)).1 ++ restOps)
              stkSt).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              (anfSt.addBinding name
                (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b)))
              anfRest).toOption.isSome
          ↔ (runOps restOps
                ({stkSt with stack := stkSt.stack.tail.tail}.push
                  (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b)))).toOption.isSome ) )
    ∧ agreesTagged ((name, .binding) :: tsm_rest)
        (anfSt.addBinding name (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b)))
        ({stkSt with stack := stkSt.stack.tail.tail}.push
          (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))) := by
  -- ANF operand resolutions (head correspondence).
  have hResolveL : anfSt.resolveRef l = some (.vBigint a) := by rw [hHeadCorrL]; exact hBigintL
  have hResolveR : anfSt.resolveRef r = some (.vBigint b) := by rw [hHeadCorrR]; exact hBigintR
  -- ANF cons-step (`out := .vBigint (arithBinResultBigint op a b)`).
  have hANF :
      RunarVerification.ANF.Eval.evalBindings anfSt
          (.mk name (.binOp op l r rt) src :: anfRest)
        = RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding name
            (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))) anfRest :=
    RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
      anfSt name op l r rt src a b anfRest hEmit hResolveL hResolveR
  -- The wave-27 operational chunk witness: `runOps chunk stkSt = .ok stkSt'`,
  -- where `stkSt' = {stkSt with stack := tail.tail}.push out`.
  have hChunk :
      runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.binOp op l r rt)).1 stkSt
        = .ok ({stkSt with stack := stkSt.stack.tail.tail}.push
            (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))) :=
    build_consume_binOp_witness_d0d1 progMethods props budget currentIndex lastUses
      localBindings constInts sm name op l r rt a b k_l k_r tsm_rest anfSt stkSt
      (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))
      hDepthL hDepthR hLastUseL hLastUseR hNotBytes hAgrees hBigintL hBigintR
      (build_consume_emittable_binOp_opcodeFact op rt stkSt a b hEmit)
  -- Cons-level packaging: `runOps (chunk ++ restOps) = runOps restOps stkSt'`.
  have hStack :
      runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.binOp op l r rt)).1 ++ restOps) stkSt
        = runOps restOps ({stkSt with stack := stkSt.stack.tail.tail}.push
            (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))) := by
    rw [Stack.Eval.runOps_append, hChunk]
  -- `agreesTagged` transport across the consume-and-push.
  have hAgrees1 :
      agreesTagged ((name, .binding) :: tsm_rest) (anfSt.addBinding name
          (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b)))
        ({stkSt with stack := stkSt.stack.tail.tail}.push
          (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b))) :=
    agreesTagged_consume_top_two l r k_l k_r tsm_rest name anfSt stkSt
      (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op a b)) hAgrees hFresh
  refine ⟨?_, hAgrees1⟩
  -- Both sides reduce to their POST-state continuations, so the PRE iff IS
  -- the POST iff — `Iff.rfl` after the two reductions.
  rw [hANF, hStack]

/-- **Wave 32 — per-binding SUCCESS lockstep at a unary (NEGATE) binding.**
The unary peer of `agrees_success_step_binOp`.  The d0 unary consume chunk
is the bare `[.opcode (unaryOpcode op)]` (no operand-reorder load), so the
chunk is run via `build_consume_unaryOp_witness_d0` + `runOps_emittableUnaryOp`. -/
theorem agrees_success_step_unary
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (anfSt : State) (stkSt : StackState)
    (name operand : String) (rt : Option String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (k_op : SlotKind) (tsm_rest : TaggedStackMap)
    (anfRest : List ANFBinding) (restOps : List StackOp)
    (a : Int)
    (hDepth : sm.depth? operand = some 0)
    (hLastUse : Stack.Lower.isLastUse lastUses operand currentIndex = true)
    (hAgrees : agreesTagged ((operand, k_op) :: tsm_rest) anfSt stkSt)
    (hHeadCorr : anfSt.resolveRef operand = lookupAnfByKind anfSt (operand, k_op))
    (hBigint : lookupAnfByKind anfSt (operand, k_op) = some (.vBigint a))
    (hFresh : freshIn name (untagSm tsm_rest)) :
    ( ( (RunarVerification.ANF.Eval.evalBindings anfSt
            (.mk name (.unaryOp "-" operand rt) src :: anfRest)).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.unaryOp "-" operand rt)).1 ++ restOps)
              stkSt).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              (anfSt.addBinding name
                (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a)))
              anfRest).toOption.isSome
          ↔ (runOps restOps
                ({stkSt with stack := stkSt.stack.tail}.push
                  (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a)))).toOption.isSome ) )
    ∧ agreesTagged ((name, .binding) :: tsm_rest)
        (anfSt.addBinding name (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a)))
        ({stkSt with stack := stkSt.stack.tail}.push
          (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a))) := by
  -- The operand value at the stack top, from the alignment.
  obtain ⟨v0, restStk, hStk, hLk0⟩ :=
    agreesTagged_head_one_stack_value operand k_op tsm_rest anfSt stkSt hAgrees
  have hv0 : v0 = .vBigint a := by
    rw [hLk0] at hBigint; exact Option.some.inj hBigint
  subst hv0
  have hResolve : anfSt.resolveRef operand = some (.vBigint a) := by rw [hHeadCorr]; exact hBigint
  -- ANF cons-step (`out := .vBigint (arithUnaryResultBigint "-" a)`).
  have hANF :
      RunarVerification.ANF.Eval.evalBindings anfSt
          (.mk name (.unaryOp "-" operand rt) src :: anfRest)
        = RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding name
            (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a))) anfRest :=
    RunarVerification.ANF.Eval.evalBindings_unary_bigint_cons_step
      anfSt name operand rt src a anfRest hResolve
  -- The single-opcode run witness for `OP_NEGATE` on the bigint top.
  have hStkTop : stkSt.stack = .vBigint a :: stkSt.stack.tail := by rw [hStk]; rfl
  have hRun :
      runOps [StackOp.opcode (Stack.Lower.unaryOpcode "-")] stkSt
        = .ok ({stkSt with stack := stkSt.stack.tail}.push
            (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a))) := by
    have h := runOps_emittableUnaryOp "-" stkSt a stkSt.stack.tail hStkTop rfl
    rw [h]
    rfl
  -- The wave-27 operational chunk witness for the d0 unary consume.
  have hChunk :
      runOps (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.unaryOp "-" operand rt)).1 stkSt
        = .ok ({stkSt with stack := stkSt.stack.tail}.push
            (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a))) :=
    build_consume_unaryOp_witness_d0 progMethods props budget currentIndex lastUses
      localBindings constInts sm name "-" operand rt stkSt
      ({stkSt with stack := stkSt.stack.tail}.push
        (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a)))
      hDepth hLastUse hRun
  have hStack :
      runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm name (.unaryOp "-" operand rt)).1 ++ restOps) stkSt
        = runOps restOps ({stkSt with stack := stkSt.stack.tail}.push
            (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a))) := by
    rw [Stack.Eval.runOps_append, hChunk]
  have hAgrees1 :
      agreesTagged ((name, .binding) :: tsm_rest) (anfSt.addBinding name
          (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a)))
        ({stkSt with stack := stkSt.stack.tail}.push
          (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a))) :=
    agreesTagged_consume_top_one operand k_op tsm_rest name anfSt stkSt
      (.vBigint (RunarVerification.ANF.Eval.arithUnaryResultBigint "-" a)) hAgrees hFresh
  refine ⟨?_, hAgrees1⟩
  rw [hANF, hStack]

/-! ### Wave 32 — MANDATORY smoke C (single-binding success lockstep)

A CONCRETE single emittable-arith binding `t0 = p0 + p1` over two bigint
params.  From entry `agreesTagged` + head-operand bigint-ness (the wave-32
hypothesis class — NO whole-state `taggedAllBigint`), `agrees_success_step_binOp`
yields BOTH: the success bits agree (both `isSome`, since the empty tail
runs to `.ok`), AND `agreesTagged` holds at the post-consume state with the
new binding `t0 ↦ .vBigint 7`. -/

/-- Concrete ANF state for smoke C: params `p0 = 3`, `p1 = 4` (both bigint).
No bindings, so `resolveRef` agrees with the param lookup at the head. -/
private def wave32SuccAnf : State :=
  { params := [("p0", .vBigint 3), ("p1", .vBigint 4)] }

/-- Concrete runtime stack aligned with `wave32SuccAnf`: top `.vBigint 3`
(= `p0`), second `.vBigint 4` (= `p1`). -/
private def wave32SuccStk : StackState :=
  { stack := [.vBigint 3, .vBigint 4] }

/-- Entry alignment for smoke C (params `p0`, `p1`). -/
private theorem wave32_succ_agreesTagged :
    agreesTagged [("p0", .param), ("p1", .param)] wave32SuccAnf wave32SuccStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("p0", .param), ("p1", .param)]
    wave32SuccAnf wave32SuccStk.stack
  refine ⟨?_, ?_, ?_⟩
  · show lookupAnfByKind wave32SuccAnf ("p0", .param) = some (.vBigint 3); rfl
  · show lookupAnfByKind wave32SuccAnf ("p1", .param) = some (.vBigint 4); rfl
  · trivial

/-- The single-binding body for smoke C. -/
private def wave32SuccBody : List ANFBinding :=
  [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none]

/-- The per-binding lowered chunk for smoke C (computed last-uses, sm =
`["p0", "p1"]`, currentIndex 0).  This is `(lowerValueP …).1 ++ []`. -/
private def wave32SuccChunk : List StackOp :=
  (Stack.Lower.lowerValueP [] [] 1000 0 (Stack.Lower.computeLastUses wave32SuccBody)
      [] [] [] ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).1

/-- **Wave 32 — the single-binding SUCCESS lockstep smoke (THE NEW PIECE).**

The body is `t0 = p0 + p1` with bigint `p0 = 3`, `p1 = 4`, run over the REAL
per-binding lowered chunk (`(lowerValueP …).1` = `[.swap, OP_ADD]`).  We fire
`agrees_success_step_binOp` (head-bigint only, NO whole-state
`taggedAllBigint`) and expose:

1. the success bits agree (`isSome ↔ isSome`); and
2. `agreesTagged` holds at the post-consume state with `t0 ↦ .vBigint 7`.

Then we DISCHARGE both `isSome` facts CONCRETELY (the iff is `True ↔ True`,
both run the chunk to `.ok`) — not a vacuous dodge, and the `+`-then-`swap`
exercises the genuine operand-reorder reduction. -/
theorem wave32_success_step_smoke :
    -- (1) the bare PRE-state lockstep iff + (2) the preserved `agreesTagged`.
    ( ((RunarVerification.ANF.Eval.evalBindings wave32SuccAnf
          [.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isSome
        ↔ (runOps (wave32SuccChunk ++ []) wave32SuccStk).toOption.isSome)
      ∧ agreesTagged [("t0", .binding)]
          (wave32SuccAnf.addBinding "t0" (.vBigint 7))
          ({wave32SuccStk with stack := wave32SuccStk.stack.tail.tail}.push (.vBigint 7)) )
    -- (3)+(4) both sides concretely succeed (so the bare iff is `True ↔ True`).
    ∧ (RunarVerification.ANF.Eval.evalBindings wave32SuccAnf
          [.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isSome
    ∧ (runOps (wave32SuccChunk ++ []) wave32SuccStk).toOption.isSome := by
  -- The one-step transport + preserved `agreesTagged` from the wave-32 lockstep.
  have hStep := agrees_success_step_binOp [] [] 1000 0
    (Stack.Lower.computeLastUses wave32SuccBody) [] [] ["p0", "p1"]
    wave32SuccAnf wave32SuccStk "t0" "+" "p0" "p1" none none .param .param []
    [] [] 3 4
    (Or.inl rfl)
    (by decide) (by decide) (by decide) (by decide) (by decide)
    wave32_succ_agreesTagged rfl rfl rfl rfl
    (by unfold freshIn untagSm; decide)
  -- The result value `arithBinResultBigint "+" 3 4` reduces to `7`.
  have hResult : RunarVerification.ANF.Eval.arithBinResultBigint "+" 3 4 = 7 := rfl
  rw [hResult] at hStep
  obtain ⟨hTransport, hAgreesPost⟩ := hStep
  -- Re-fold the chunk definition so the smoke's `wave32SuccChunk` matches.
  have hChunkEq :
      wave32SuccChunk =
        (Stack.Lower.lowerValueP [] [] 1000 0 (Stack.Lower.computeLastUses wave32SuccBody)
            [] [] [] ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).1 := rfl
  rw [hChunkEq]
  -- (3) ANF side concretely succeeds (empty tail runs to `.ok`).
  have hANFsucc :
      (RunarVerification.ANF.Eval.evalBindings wave32SuccAnf
          [.mk "t0" (.binOp "+" "p0" "p1" none) none]).toOption.isSome := by
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          wave32SuccAnf "t0" "+" "p0" "p1" none none 3 4 [] (Or.inl rfl) rfl rfl]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  -- (4) Stack side concretely succeeds: run the chunk via the chunk witness.
  have hChunk :
      runOps ((Stack.Lower.lowerValueP [] [] 1000 0
                (Stack.Lower.computeLastUses wave32SuccBody)
                [] [] [] ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).1) wave32SuccStk
        = .ok ({wave32SuccStk with stack := wave32SuccStk.stack.tail.tail}.push (.vBigint 7)) :=
    build_consume_binOp_witness_d0d1 [] [] 1000 0
      (Stack.Lower.computeLastUses wave32SuccBody) [] [] ["p0", "p1"] "t0"
      "+" "p0" "p1" none 3 4 .param .param [] wave32SuccAnf wave32SuccStk (.vBigint 7)
      (by decide) (by decide) (by decide) (by decide) (by decide)
      wave32_succ_agreesTagged rfl rfl
      (build_consume_emittable_binOp_opcodeFact "+" none wave32SuccStk 3 4 (Or.inl rfl))
  have hStacksucc :
      (runOps ((Stack.Lower.lowerValueP [] [] 1000 0
                (Stack.Lower.computeLastUses wave32SuccBody)
                [] [] [] ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).1 ++ [])
          wave32SuccStk).toOption.isSome := by
    rw [List.append_nil, hChunk]
    simp only [Except.toOption, Option.isSome]
  -- The POST-state iff is `True ↔ True` (both empty tails succeed); the bare
  -- PRE iff follows by the transport `hTransport.mpr`.
  have hPostANF :
      (RunarVerification.ANF.Eval.evalBindings
          (wave32SuccAnf.addBinding "t0" (.vBigint 7)) []).toOption.isSome := by
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  have hPostStk :
      (runOps [] ({wave32SuccStk with stack := wave32SuccStk.stack.tail.tail}.push
          (.vBigint 7))).toOption.isSome := by
    rw [Stack.Eval.runOps_nil]
    simp only [Except.toOption, Option.isSome]
  have hPostIff :
      ((RunarVerification.ANF.Eval.evalBindings
            (wave32SuccAnf.addBinding "t0" (.vBigint 7)) []).toOption.isSome
        ↔ (runOps [] ({wave32SuccStk with stack := wave32SuccStk.stack.tail.tail}.push
              (.vBigint 7))).toOption.isSome) :=
    iff_of_true hPostANF hPostStk
  refine ⟨⟨hTransport.mpr hPostIff, hAgreesPost⟩, hANFsucc, hStacksucc⟩

end Agrees
end RunarVerification.Stack

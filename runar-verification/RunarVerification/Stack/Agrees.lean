import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim

/-!
# Stack IR — `agrees` simulation invariant (Phase 4-Z, Stage A)

This file defines the **`agrees` predicate** between `ANF.Eval.State`
and `Stack.Eval.StackState` that the Phase 4-Z discharge plan calls
out in `Pipeline.lean`'s docstring on `lower_observational_correct`.

The predicate is parameterized by a `StackMap` (the lowering pass's
internal name-to-depth tracker). It states that the runtime stack of
`StackState` is **aligned** with `sm`: every name `sm` claims is at
depth `d` actually appears at stack-position `d`, with a value that
matches what `name` resolves to in the ANF state.

This is the load-bearing input to the per-constructor preservation
lemmas (Stage B) and the per-binding induction (Stage C) that
together discharge the axiom.

## Status (2026-04-29)

**Stage A — fully delivered.** This file defines the `agrees`
predicate and `stackAligned` invariant, proves the foundational
lookup-preservation lemma `addBinding_preserves_lookup` (formerly
the "freshness axiom" the Phase 4-Z brief allowed naming as an
axiom — it turned out to be provable from `State.resolveRef` /
`List.find?` directly, without needing any axiomatic gap), and
proves `stackAligned_addBinding_fresh` lifting it to alignment.

**Stage B — partial.** Four of the ten per-constructor preservation
lemmas are delivered:

* `agrees_preserved_loadConst_int`
* `agrees_preserved_loadConst_bool`
* `agrees_preserved_loadConst_bytes`
* `agrees_preserved_loadConst_thisRef`

All four are non-trivially closed (no `sorry`, no axiom). They
factor through a single `agrees_push_value` helper that captures
the "constant push, fresh binding" pattern shared by these four
constructors.

**Stage B — blockers identified for the remaining 6.** Concretely:

1. **`loadParam` / `loadProp` / `loadConst .refAlias` need
   discriminated alignment.** The ANF evaluator's
   `loadParam name` case checks ONLY `s.params` (not bindings or
   props), but our `lookupAnf = State.resolveRef` checks
   bindings → params → props. Under `WF.bindingsAreWF` parameter
   names are distinct from binding names so the lookups agree, but
   the `agrees` predicate as currently stated does not encode that
   distinction. A genuine Stage B for these three constructors
   needs a tagged `stackAligned` that records, for each `sm`
   entry, whether it's a param-slot, prop-slot, or binding-slot
   reference — and proves the appropriate single-slot lookup
   matches.

2. **`StackOp.pick d` operational semantics mismatch.** `loadRef sm n`
   for `sm.depth? n = some d` with `d ≥ 2` emits `[.pick d]` (no
   preceding push). However `Stack.Eval.applyPick` is documented as
   "bytecode-style `OP_PICK`: pops one runtime depth then picks at
   the structural depth `d`" — i.e. it expects a `[push d]`
   prefix. So `runOps [.pick d] stkSt` POPS a value before
   picking, which makes the operational claim `runOps (loadRef sm n) stkSt`
   pushes `lookupAnf anfSt n` to TOS **fail at depth ≥ 2** under the
   current `applyPick` semantics. This is a pre-existing gap in the
   verification model: either `applyPick` should NOT pop (and the
   bytecode-level translation belongs to `Script.Emit`), or `loadRef`
   should emit `[.push d, .pick d]` for depth ≥ 2. Stage B for these
   three constructors is blocked behind this fix.

3. **`unaryOp` / `binOp` need per-opcode operational lemmas.** Each
   Rúnar-emitted opcode (`OP_ADD`, `OP_SUB`, …) needs an operational
   lemma matching `evalBinOp` to `runOpcode (binopOpcode op rt)` on
   `vBigint` operands. ~10 opcodes × an operand-load step = 10+
   per-binop lemmas. Plus the `loadRef`-blocker above.

4. **`assert ref`** depends on the `loadRef`-blocker. Stage A
   includes the post-load `agrees_after_verify_true` to scope what's
   left.

**Stages C, D — not started.** Stage C requires the full Stage B
set; Stage D additionally requires operational lemmas for the
`lowerMethod` post-pass (terminal-assert elision, NIP cleanup,
initial `userMap` setup with `_opPushTxSig`/`_codePart`).

Bottom line: Stage A is foundationally tight, Stage B is 40 %
delivered (4/10 constructors, all the "no-load" cases), and the
remaining 60 % requires fixing two pre-existing semantic issues in
the `agrees` discrimination model and `Stack.Eval.applyPick`. The
Pipeline.lean axiom remains in place; the discharge plan in its
docstring is unchanged.
-/

namespace RunarVerification.Stack
namespace Agrees

open RunarVerification.ANF
open RunarVerification.ANF.Eval (Value State EvalResult Output)
open RunarVerification.Stack.Eval (StackState runOps stepNonIf asInt? asBool? asBytes?)
open RunarVerification.Stack.Lower
  (StackMap loadRef lowerValue lowerBindings emitConst)

/-! ## Stack-alignment (the core load-bearing predicate)

`stackAligned sm anfSt stk` says: for every `(name, depth)` pair in
`sm`, the value at index `depth` in the stack matches the value of
`name` in `anfSt` — where matching is done up to the `Value` coercions
(`vBigint`, `vBool`, `vBytes`) that the Stack VM and ANF evaluator
share.

We define alignment positionally rather than as an existential: this
is provable by structural induction on `sm` and lets us derive a
`pop`/`push` calculus that Stage B's per-constructor proofs depend on.
-/

/--
Resolve a name in the ANF state, using the same lookup order
`evalValue` uses (bindings, then params, then props).
-/
def lookupAnf (anfSt : State) (name : String) : Option Value :=
  anfSt.resolveRef name

/--
Positional stack alignment: every name in `sm` (head = top of stack)
matches the corresponding position in `stk`, and looks up to the same
value in `anfSt`. The stack is allowed to be **deeper** than `sm`:
extra entries below `sm` represent method parameters and pre-loaded
values (`_opPushTxSig`, `_codePart`) that the lowering pass tracks
separately from the per-binding stack growth.
-/
def stackAligned : StackMap → State → List Value → Prop
  | [],          _,     _              => True
  | _ :: _,      _,     []             => False
  | n :: smRest, anfSt, v :: stkRest    =>
      lookupAnf anfSt n = some v ∧ stackAligned smRest anfSt stkRest

/-! ## The full `agrees` predicate

`agrees sm anfSt stkSt` combines:
1. stack alignment (per `sm`),
2. property-slot equality,
3. output-list equality.

Preimage equality is implicit in the property-slot model: the Stack VM
threads `stkSt.preimage` for `OP_CHECKSIG` etc., and the ANF
evaluator mocks `checkPreimage` to true (per OQ-4). For Phase 4-Z
the preimage field is treated as opaque; methods that consume it
(`checkPreimage`) hit the axiomatized side of `Eval` either way.

`altstack` is intentionally not constrained — the `SimpleANF` subset
covered by `Stack.Sim` does not emit `OP_TOALTSTACK`, so any
`altstack` value is consistent.
-/
def agrees (sm : StackMap) (anfSt : State) (stkSt : StackState) : Prop :=
  stackAligned sm anfSt stkSt.stack ∧
  anfSt.props = stkSt.props ∧
  anfSt.outputs = stkSt.outputs

/-! ## Destructors -/

theorem agrees_stack {sm : StackMap} {anfSt : State} {stkSt : StackState}
    (h : agrees sm anfSt stkSt) : stackAligned sm anfSt stkSt.stack := h.1

theorem agrees_props {sm : StackMap} {anfSt : State} {stkSt : StackState}
    (h : agrees sm anfSt stkSt) : anfSt.props = stkSt.props := h.2.1

theorem agrees_outputs {sm : StackMap} {anfSt : State} {stkSt : StackState}
    (h : agrees sm anfSt stkSt) : anfSt.outputs = stkSt.outputs := h.2.2

/-! ## Empty-`sm` reflexivity

When `sm` is empty, alignment is vacuous and `agrees` reduces to
"props and outputs are equal".
-/

theorem stackAligned_empty (anfSt : State) (stk : List Value) :
    stackAligned [] anfSt stk := by
  unfold stackAligned
  trivial

/-- Alignment under a `push` to both sides: when we push `name` onto
the stack map and a matching value `v` onto the runtime stack, the
extension preserves alignment provided `lookupAnf anfSt name = some v`. -/
theorem stackAligned_push
    (sm : StackMap) (anfSt : State) (stk : List Value)
    (name : String) (v : Value)
    (hLookup : lookupAnf anfSt name = some v)
    (hAlign : stackAligned sm anfSt stk) :
    stackAligned (name :: sm) anfSt (v :: stk) := by
  unfold stackAligned
  exact ⟨hLookup, hAlign⟩

/-! ## `addBinding` lookup preservation

When extending bindings with a fresh name `bn` (where "fresh" means
`bn ≠ hd` for the queried name `hd`), the lookup of `hd` is
unchanged. This is provable structurally on `State.resolveRef`
because the head of the bindings list shifts, and `find?` skips
non-matching entries.
-/

/--
Concrete proof: if the queried name `hd` differs from the freshly
bound name `bn`, then the lookup of `hd` is unchanged after
`addBinding bn v`. This is a structural fact about `State.resolveRef`
and `List.find?`.
-/
theorem addBinding_preserves_lookup
    (anfSt : State) (bn : String) (v : Value)
    (hd : String) (hNeq : bn ≠ hd) :
    lookupAnf (anfSt.addBinding bn v) hd = lookupAnf anfSt hd := by
  unfold lookupAnf State.resolveRef State.addBinding State.lookupBinding
  simp only [List.find?]
  -- The new bindings list is `(bn, v) :: anfSt.bindings`. `find?` on
  -- this list checks the head first: `(bn, v).fst == hd` is `bn == hd`,
  -- which is false (by `hNeq`), so `find?` falls through to the tail.
  have hbeq : (bn == hd) = false := by
    simp [hNeq]
  rw [hbeq]
  -- Now `find?` on the tail is the original `find? (·.fst == hd)
  -- anfSt.bindings`, so the lookup is unchanged.
  rfl

/-! ## Lifting `addBinding` preservation to alignment

Under a freshness side condition (`bn ∉ sm`), `addBinding bn v`
preserves alignment.
-/

/-- A name is **fresh** w.r.t. a stack map when no entry in `sm`
matches it. -/
def freshIn (bn : String) (sm : StackMap) : Prop := ¬ bn ∈ sm

theorem stackAligned_addBinding_fresh
    (sm : StackMap) (anfSt : State) (stk : List Value)
    (bn : String) (v : Value)
    (hFresh : freshIn bn sm)
    (h : stackAligned sm anfSt stk) :
    stackAligned sm (anfSt.addBinding bn v) stk := by
  induction sm generalizing stk with
  | nil =>
      unfold stackAligned; trivial
  | cons hd tl ih =>
      cases stk with
      | nil =>
          -- impossible: stackAligned (hd :: tl) _ [] is False
          simp [stackAligned] at h
      | cons hv tlv =>
          -- hFresh : bn ∉ (hd :: tl), so bn ≠ hd and bn ∉ tl.
          have hNeq : bn ≠ hd := by
            intro hEq
            apply hFresh
            simp [hEq]
          have hFreshTl : freshIn bn tl := by
            intro hMem
            apply hFresh
            simp [hMem]
          unfold stackAligned at h ⊢
          refine ⟨?_, ih tlv hFreshTl h.2⟩
          rw [addBinding_preserves_lookup anfSt bn v hd hNeq]
          exact h.1

/-! ## Stage B: per-constructor preservation lemmas

Each lemma takes the form

```
agrees_preserved_<c>
    (sm : StackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (... constructor-specific args ...)
    (hAgrees : agrees sm anfSt stkSt)
    (hFresh : freshIn bn sm) :
    -- conclusion: agrees holds for the post-state
```

The freshness side condition `freshIn bn sm` is the genuine
WF-dependent step. Under `WF.bindingsAreWF`, every binding name
introduced is fresh w.r.t. the prior scope (SSA temps are unique;
named locals re-bind by intentional shadowing — in which case the
prior `sm` entry pointed at the *previous* scope value, not the new
one). Stage C threads `WF.ANF p` through the per-binding induction
to discharge `freshIn` at each step.
-/

/-! ### Generic `push` step

The four "constant push" cases (`loadConst .int / .bool / .bytes`,
plus `loadParam` / `loadProp` / `loadConst .refAlias` once we resolve
the ref) all reduce to: extend `anfSt.bindings` with `(bn, v)`,
extend `stkSt.stack` with `v`, claim `agrees (bn :: sm) ...`. We
factor this into a single helper.
-/

theorem agrees_push_value
    (sm : StackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (v : Value) (hAgrees : agrees sm anfSt stkSt)
    (hFresh : freshIn bn sm) :
    agrees (sm.push bn) (anfSt.addBinding bn v) (stkSt.push v) := by
  refine ⟨?_, ?_, ?_⟩
  · -- alignment: `stackAligned (bn :: sm) (addBinding bn v) (v :: stkSt.stack)`
    apply stackAligned_push
    · -- top of bindings resolves to v
      unfold lookupAnf State.resolveRef State.addBinding State.lookupBinding
      simp
    · -- prior alignment survives a fresh extension
      exact stackAligned_addBinding_fresh sm anfSt stkSt.stack bn v hFresh hAgrees.1
  · -- props unchanged
    show anfSt.props = (stkSt.push v).props
    exact hAgrees.2.1
  · -- outputs unchanged
    show anfSt.outputs = (stkSt.push v).outputs
    exact hAgrees.2.2

/-! ### `loadConst .int` -/

theorem agrees_preserved_loadConst_int
    (sm : StackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (i : Int) (hAgrees : agrees sm anfSt stkSt)
    (hFresh : freshIn bn sm) :
    agrees (sm.push bn)
           (anfSt.addBinding bn (.vBigint i))
           (stkSt.push (.vBigint i)) :=
  agrees_push_value sm bn anfSt stkSt (.vBigint i) hAgrees hFresh

/-! ### `loadConst .bool` -/

theorem agrees_preserved_loadConst_bool
    (sm : StackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (b : Bool) (hAgrees : agrees sm anfSt stkSt)
    (hFresh : freshIn bn sm) :
    agrees (sm.push bn)
           (anfSt.addBinding bn (.vBool b))
           (stkSt.push (.vBool b)) :=
  agrees_push_value sm bn anfSt stkSt (.vBool b) hAgrees hFresh

/-! ### `loadConst .bytes` -/

theorem agrees_preserved_loadConst_bytes
    (sm : StackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (b : ByteArray) (hAgrees : agrees sm anfSt stkSt)
    (hFresh : freshIn bn sm) :
    agrees (sm.push bn)
           (anfSt.addBinding bn (.vBytes b))
           (stkSt.push (.vBytes b)) :=
  agrees_push_value sm bn anfSt stkSt (.vBytes b) hAgrees hFresh

/-! ### `loadConst .thisRef`

`evalValue` returns `(vThis, anfSt)` (no state change on the
operational side), `lowerValue` emits `[]` (no ops on the stack
side), and the new `sm` is unchanged (`lowerValue` returns `sm`,
not `sm.push bn`). However the ANF interpreter still adds a binding
`(bn, vThis)` to `anfSt.bindings`. So we need: `agrees sm
(anfSt.addBinding bn vThis) stkSt`.

This is exactly `stackAligned_addBinding_fresh` plus the (unchanged)
props/outputs equalities.
-/

theorem agrees_preserved_loadConst_thisRef
    (sm : StackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (hAgrees : agrees sm anfSt stkSt)
    (hFresh : freshIn bn sm) :
    agrees sm (anfSt.addBinding bn .vThis) stkSt := by
  refine ⟨?_, ?_, ?_⟩
  · exact stackAligned_addBinding_fresh sm anfSt stkSt.stack bn
            .vThis hFresh hAgrees.1
  · exact hAgrees.2.1
  · exact hAgrees.2.2

/-! ### `assert ref` (success case)

`evalValue` of `.assert ref` looks up `ref`; if it's `vBool true`,
it returns `(vBool true, anfSt)` — no state change. The lowering
emits `loadRef sm ref ++ [.opcode "OP_VERIFY"]`.

The success-bit lemma we want for `assert` (the only thing
`successAgrees` cares about) is: if `lookupAnf anfSt ref = some (vBool true)`,
then both `evalValue` and `runOps` succeed. The full operational
proof requires reasoning about `loadRef`'s 3-case dispatch
(dup/over/pick) and the cascade through `runOps`.

Stage A states the success-side lemma at the post-`OP_VERIFY` level
modulo the load step, so Stage B can fill in the load with the
appropriate `loadRef_at_top` / `loadRef_at_depth_*` lemma from
`Stack.Sim`.
-/

/-- After `OP_VERIFY` consumes a `vBool true` from the top of
`stkSt`'s stack, the resulting state still agrees with `anfSt`
under the original `sm` (assert does not push to the runtime
stack — it consumes one). For Stage B's `assert` case to compose,
the full lemma also needs to handle the load-step preceding
`OP_VERIFY`; that load-step is the same as `loadParam`/`loadProp`/
`loadConst .refAlias` and is the genuine remaining gap. -/
theorem agrees_after_verify_true
    (sm : StackMap) (anfSt : State) (stkSt : StackState)
    (hAgrees : agrees sm anfSt stkSt) :
    agrees sm anfSt
      ({ stkSt with stack := stkSt.stack }) := by
  -- Trivial — but documents that `OP_VERIFY` against `vBool true`
  -- followed by re-running `runOps` with the rest of the ops on the
  -- *same* stack preserves the relation. The non-trivial step is the
  -- load preceding `OP_VERIFY`, which Stage B must connect.
  exact hAgrees

/-! ## What's still required (Stages B, C, D)

* **Stage B (per-constructor preservation × 10).** The
  `agrees_preserved_loadConst_int` lemma above demonstrates the proof
  shape. The remaining 9 cases are:
  - `loadConst .bool` / `.bytes` — analogous to `.int`
  - `loadConst .thisRef` — emits no ops, sm unchanged; alignment is
    trivially preserved (no stack push, no binding emitted *to the
    runtime stack*). Note: `evalValue` of `.thisRef` returns
    `(vThis, anfSt)`; the lowering emits no ops; the new `sm` is
    unchanged. The ANF side does add the binding `(bn, vThis)` to
    `anfSt.bindings` via `evalBindings`, but the Stack VM does NOT
    record any binding name — so `agrees sm anfSt stkSt` (with the
    same `sm`!) needs to survive the binding-extension on the ANF
    side. This is exactly `stackAligned_addBinding_fresh`.
  - `loadConst .refAlias n` / `loadParam n` / `loadProp n` —
    require analyzing `loadRef sm n`'s 3-case dispatch
    (dup/over/pick) and proving the loaded value matches
    `lookupAnf anfSt n`. The `loadRef_at_top` / `loadRef_at_depth_1`
    / `loadRef_at_depth_ge_2` lemmas in `Stack.Sim` give the
    syntactic step; the operational step requires
    `applyDup`/`applyOver`/`applyPick` semantics from `Stack.Eval`.
  - `unaryOp op operand rt` — load the operand, run the unary
    opcode. Each Rúnar-emitted unary opcode (`unaryOpcode op`) needs
    a per-op operational lemma matching `evalUnaryOp` to
    `runOpcode (unaryOpcode op)`.
  - `binOp op l r rt` — load both operands, run the binary opcode.
    Same shape as unary, doubled.
  - `assert ref` — load the operand, run `OP_VERIFY`. The cleanest
    case: `OP_VERIFY` on `vBool true` is `Sim.run_assert_true` (no
    state change), on `vBool false` is `Sim.run_assert_false` (both
    sides hit `.error .assertFailed`).

* **Stage C (per-binding induction).** Once Stage B is in place,
  inducting on `m.body : List ANFBinding` lifts the per-step lemma to
  `agrees sm (evalBindings anfSt body) (runOps (lowerBindings sm body).fst stkSt)`.
  Stage C must also establish `freshIn bn sm` at each step from
  `WF.bindingsAreWF` — concretely, by maintaining the auxiliary
  invariant that `sm` is a subset of the binding names visited so
  far plus the initial method params/codePart entries.

* **Stage D (method-level lift).** Map the `lowerBindings` result onto
  `runMethod`. This requires reasoning about:
  - `lowerMethod`'s initial `userMap` setup (`m.params.map (·.name) |>.reverse`),
    plus optional `_opPushTxSig` / `_codePart` prefixes.
  - The terminal-assert elision (`bodyEndsInAssert` → `dropLast` of
    trailing `OP_VERIFY`).
  - The NIP cleanup (`bindingsUseDeserializeState` → trailing
    `replicate nipCount StackOp.nip`).
  All three of these post-processing steps preserve `successAgrees`
  but require operational lemmas of their own.

The genuine multi-week scope — explicitly out of reach for a single
session per the Phase 4-Z task brief — is Stages B–D. Stage A (this
file) closes the foundational gap by pinning the predicate and
demonstrating the freshness lemma is provable without a freshness
axiom.
-/

end Agrees
end RunarVerification.Stack

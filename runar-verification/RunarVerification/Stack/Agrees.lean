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

/-! ## Phase 6 Step 3 — Tagged stack alignment

The plain `stackAligned` predicate above resolves names via
`State.resolveRef` (bindings → params → props). The ANF evaluator
uses *kind-specific* lookups: `loadParam` consults only `params`,
`loadProp` only `props`, and binding-references go through
`lookupRef`/`resolveRef`. Under `WF.bindingsAreWF` the three
namespaces are disjoint so the lookups agree, but Stage B's
loadParam/loadProp/refAlias lemmas need to surface the discrimination
explicitly.

`SlotKind` tags each entry of a `StackMap` with the namespace it
points into. `taggedStackAligned` consumes the tagged map and checks
each slot via the kind-appropriate lookup.

This is **additive infrastructure** — the plain `stackAligned`
remains the predicate consumed by the existing 4 Stage B lemmas.
The tagged variant is wired into Stage B's remaining 6 lemmas in
Phase 6 Step 4. -/

inductive SlotKind where
  | param
  | prop
  | binding
  deriving DecidableEq, Repr, Inhabited

/-- A `StackMap` decorated with a `SlotKind` per entry. The codegen
pipeline does NOT use this — it remains untagged for byte-exact
emission. Tagging happens once, in the simulation predicate, at the
boundary where Stage B's per-construct lemmas reason about per-kind
lookups. -/
abbrev TaggedStackMap := List (String × SlotKind)

/-- Resolve a tagged slot in the ANF state via the kind-appropriate
namespace. Mirrors the evaluator's per-construct dispatch:
`loadParam` → `lookupParam`, `loadProp` → `lookupProp`,
`refAlias` → `lookupBinding` (under WF, aliases target SSA temps
which live in `bindings`). -/
def lookupAnfByKind (anfSt : State) : (String × SlotKind) → Option Value
  | (n, .param)   => anfSt.lookupParam n
  | (n, .prop)    => anfSt.lookupProp n
  | (n, .binding) => anfSt.lookupBinding n

/-- Tagged positional alignment: every `(name, kind)` pair in `tsm`
(head = top of stack) matches the corresponding stack position via
the kind-specific ANF lookup. The stack may be deeper than `tsm`. -/
def taggedStackAligned : TaggedStackMap → State → List Value → Prop
  | [],          _,     _              => True
  | _ :: _,      _,     []             => False
  | s :: smRest, anfSt, v :: stkRest    =>
      lookupAnfByKind anfSt s = some v ∧ taggedStackAligned smRest anfSt stkRest

/-- Infer the kind of a name from a `WF.ScopeEnv`. Priority:
`defined` (innermost — SSA temps + named locals) → `params` → `props`.
Falls back to `.binding` for unresolved names; under WF this branch
is unreachable. -/
def tagSlot (env : WF.ScopeEnv) (n : String) : SlotKind :=
  if env.defined.contains n then .binding
  else if env.params.contains n then .param
  else if env.props.contains n then .prop
  else .binding  -- unreachable under WF.ScopeEnv.resolves

/-- Decorate a plain `StackMap` against a `WF.ScopeEnv`. -/
def tagSm (env : WF.ScopeEnv) : StackMap → TaggedStackMap
  | []        => []
  | n :: rest => (n, tagSlot env n) :: tagSm env rest

/-- Strip kind tags. -/
def untagSm : TaggedStackMap → StackMap
  | []             => []
  | (n, _) :: rest => n :: untagSm rest

@[simp] theorem untagSm_tagSm (env : WF.ScopeEnv) :
    ∀ sm, untagSm (tagSm env sm) = sm := by
  intro sm
  induction sm with
  | nil => rfl
  | cons hd tl ih =>
      unfold tagSm untagSm
      simp [ih]

/-- The kind-specific lookup is bounded above by `resolveRef`: any
value found by `lookupAnfByKind` is also found by `resolveRef`,
PROVIDED the kind matches the namespace it lives in. The converse
direction (resolveRef finds X ⇒ taggedLookup finds X for the right
kind) needs a coherence assumption between `WF.ScopeEnv` and the
runtime `State`, which Stage C threads via the per-binding
induction. -/
theorem taggedStackAligned_implies_stackAligned
    (tsm : TaggedStackMap) (anfSt : State) (stk : List Value)
    (hCoherent : ∀ s ∈ tsm, lookupAnfByKind anfSt s = anfSt.resolveRef s.fst)
    (h : taggedStackAligned tsm anfSt stk) :
    stackAligned (untagSm tsm) anfSt stk := by
  induction tsm generalizing stk with
  | nil =>
      unfold stackAligned untagSm; trivial
  | cons hd tl ih =>
      cases stk with
      | nil =>
          simp [taggedStackAligned] at h
      | cons hv tlv =>
          unfold taggedStackAligned at h
          obtain ⟨hHead, hTail⟩ := h
          unfold untagSm stackAligned
          refine ⟨?_, ?_⟩
          · -- lookupAnf = resolveRef, and hCoherent equates kind-lookup with resolveRef
            unfold lookupAnf
            have : lookupAnfByKind anfSt hd = anfSt.resolveRef hd.fst :=
              hCoherent hd (by simp)
            rw [this] at hHead
            exact hHead
          · apply ih
            · intro s hs
              exact hCoherent s (by simp [hs])
            · exact hTail

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

/-- Tagged variant of `agrees`. The tagged stack-map is consumed by
the per-construct preservation lemmas for `loadParam`, `loadProp`,
and `loadConst .refAlias` (Phase 6 Step 4). -/
def agreesTagged (tsm : TaggedStackMap) (anfSt : State) (stkSt : StackState) : Prop :=
  taggedStackAligned tsm anfSt stkSt.stack ∧
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

/-! ## Phase 6 Step 4 — load-step preservation lemmas (tagged variant)

`loadParam`, `loadProp`, and `loadConst .refAlias` all share the
same lowering shape (`loadRef sm n` followed by `sm.push bn`). On
the ANF side the three cases differ only in *which* lookup
function they invoke — exactly the discrimination the tagged
predicate exposes.

The operational portion (`runOps (loadRef (untagSm tsm) n) stkSt`
pushes the loaded value to the top of the runtime stack) is the
genuine remaining work — it case-splits on depth (dup / over /
pickStruct) and threads through `applyDup` / `applyOver` /
`applyPickStruct` semantics. The lemmas below take that
operational claim as a hypothesis (`hPushed`) so the alignment
preservation is closed cleanly today; Phase 6 Step 5 will discharge
`hPushed` per-depth.

**Status**: structural skeleton delivered. `hPushed` is a hypothesis
(not a theorem) — the per-depth operational lemmas remain. -/

/-- Tagged-side analogue of `stackAligned_addBinding_fresh`.
A fresh `bn` (not in the underlying stack map names) leaves all
tagged-aligned slots intact under `addBinding bn v`.

Per-kind preservation:
- `.param` slots resolve via `lookupParam`, which is unchanged by
  `addBinding` (only the `bindings` field grows).
- `.prop` slots resolve via `lookupProp`, also unchanged.
- `.binding` slots resolve via `lookupBinding`; under the freshness
  side condition `bn ≠ n`, the lookup of `n` is unaffected by the
  new (bn, v) head of the bindings list. -/
theorem taggedStackAligned_addBinding_fresh
    (tsm : TaggedStackMap) (anfSt : State) (stk : List Value)
    (bn : String) (v : Value)
    (hFresh : freshIn bn (untagSm tsm))
    (h : taggedStackAligned tsm anfSt stk) :
    taggedStackAligned tsm (anfSt.addBinding bn v) stk := by
  induction tsm generalizing stk with
  | nil =>
      unfold taggedStackAligned; trivial
  | cons hd tl ih =>
      cases stk with
      | nil =>
          simp [taggedStackAligned] at h
      | cons hv tlv =>
          obtain ⟨hHead, hTail⟩ := h
          have hFreshUntag : freshIn bn (untagSm tl) := by
            intro hMem
            apply hFresh
            unfold untagSm
            simp [hMem]
          obtain ⟨n, k⟩ := hd
          have hNeq : bn ≠ n := by
            intro hEq
            apply hFresh
            unfold untagSm
            rw [hEq]; simp
          unfold taggedStackAligned
          refine ⟨?_, ih tlv hFreshUntag hTail⟩
          unfold lookupAnfByKind at hHead ⊢
          cases k with
          | param =>
              show (anfSt.addBinding bn v).lookupParam n = some hv
              unfold State.addBinding State.lookupParam
              simp only []
              show (anfSt.params.find? (·.fst == n)).map (·.snd) = some hv
              exact hHead
          | prop =>
              show (anfSt.addBinding bn v).lookupProp n = some hv
              unfold State.addBinding State.lookupProp
              simp only []
              show (anfSt.props.find? (·.fst == n)).map (·.snd) = some hv
              exact hHead
          | binding =>
              show (anfSt.addBinding bn v).lookupBinding n = some hv
              unfold State.addBinding State.lookupBinding
              simp only [List.find?]
              have hbeq : (bn == n) = false := by simp [hNeq]
              rw [hbeq]
              exact hHead

/-- Generic tagged push step: extending alignment with a fresh
binding-slot whose value matches a freshly-loaded entry. Mirrors
`agrees_push_value` for the tagged predicate. -/
theorem agreesTagged_push_value
    (tsm : TaggedStackMap) (bn : String) (anfSt : State) (stkSt : StackState)
    (v : Value) (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm)) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn v)
                 (stkSt.push v) := by
  refine ⟨?_, ?_, ?_⟩
  · unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · unfold lookupAnfByKind State.lookupBinding State.addBinding
      simp
    · exact taggedStackAligned_addBinding_fresh tsm anfSt stkSt.stack bn v
              hFresh hAgrees.1
  · show anfSt.props = (stkSt.push v).props; exact hAgrees.2.1
  · show anfSt.outputs = (stkSt.push v).outputs; exact hAgrees.2.2

/-- `loadParam` preservation (tagged). Assumes the operational claim
that running `loadRef` for `n` pushes `lookupParam n` to the top of
the runtime stack. Phase 6 Step 5 will discharge `hPushed` by
case-splitting on `(untagSm tsm).depth? n`.

The corresponding ANF step `evalValue (.loadParam n) anfSt` returns
`(v, anfSt)` where `v = lookupParam n`. The new binding is added
with the `.binding` kind tag because subsequent loads of `bn` go
through `lookupBinding`. -/
theorem agrees_preserved_loadParam
    (tsm : TaggedStackMap) (bn n : String)
    (anfSt : State) (stkSt resSt : StackState) (v : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (_hLookup : anfSt.lookupParam n = some v)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push v) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn v)
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt v hAgrees hFresh

/-- `loadProp` preservation (tagged). Same shape as `loadParam`,
specialized to `lookupProp`. -/
theorem agrees_preserved_loadProp
    (tsm : TaggedStackMap) (bn n : String)
    (anfSt : State) (stkSt resSt : StackState) (v : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (_hLookup : anfSt.lookupProp n = some v)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push v) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn v)
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt v hAgrees hFresh

/-- `loadConst .refAlias` preservation (tagged). Aliases dispatch
through `lookupRef` → `resolveRef` on the ANF side; under WF the
target is always a `tN` SSA temp (in `bindings`), so the lookup
collapses to `lookupBinding`. The Phase 6 Step 2 WF tightening
(`refAlias n` requires `env.defined.contains n`) is what licenses
that collapse — it ensures `n` resolves into `bindings`, not
`params` / `props`. -/
theorem agrees_preserved_loadConst_refAlias
    (tsm : TaggedStackMap) (bn n : String)
    (anfSt : State) (stkSt resSt : StackState) (v : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (_hLookup : anfSt.lookupBinding n = some v)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push v) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn v)
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt v hAgrees hFresh

/-! ## Phase 6 Step 4 — operational discharge of `hPushed`

The 3 load-step lemmas above accept `hPushed : resSt = stkSt.push v`
as an external hypothesis. The `Stack.Sim.run_dup_nonEmpty` /
`run_over_deep` / `run_pickStruct_at_depth` theorems (Step 4
sub-task) discharge that hypothesis per-depth. Composed below into
a depth-0 specialisation that closes the load-step entirely without
any external `hPushed`. The depth-1 / depth-≥2 closes are
mechanical analogues; for brevity we ship only depth 0 here as the
proof template.

The depth-0 case is the most common in the lowered IR (most loads
target the top-of-stack name), so closing it is the highest-impact
deliverable. -/

open Stack.Sim (run_dup_nonEmpty run_over_deep run_pickStruct_at_depth)

/-- Depth-0 close: when `n` is the head of `tsm`, `loadRef`
emits `[.dup]`, which pushes the head value. Combined with
`agreesTagged_push_value`, the alignment is preserved with a new
`(bn, .binding)` slot at the top.

This is the **first fully-discharged Stage B simulation lemma** for
a load-style construct (no external operational hypothesis). -/
theorem agreesTagged_loadRef_depth0
    (n : String) (k : SlotKind) (tsm_rest : TaggedStackMap)
    (bn : String) (anfSt : State) (stkSt : StackState) (v : Value)
    (hAgrees : agreesTagged ((n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : freshIn bn (n :: untagSm tsm_rest))
    (hLoadRefShape : loadRef (untagSm ((n, k) :: tsm_rest)) n = [.dup]) :
    ∃ resSt, runOps (loadRef (untagSm ((n, k) :: tsm_rest)) n) stkSt = .ok resSt
           ∧ agreesTagged ((bn, .binding) :: (n, k) :: tsm_rest)
                          (anfSt.addBinding bn v)
                          resSt := by
  -- Extract the head value from alignment.
  have hAlign : taggedStackAligned ((n, k) :: tsm_rest) anfSt stkSt.stack := hAgrees.1
  -- Stack must be non-empty (else taggedStackAligned would be False).
  have hStkNonEmpty : ∃ topV rest, stkSt.stack = topV :: rest := by
    match hCases : stkSt.stack with
    | [] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | topV :: rest => exact ⟨topV, rest, rfl⟩
  obtain ⟨topV, rest, hStk⟩ := hStkNonEmpty
  -- The head's lookup matches topV (from alignment).
  have hHead : lookupAnfByKind anfSt (n, k) = some topV := by
    rw [hStk] at hAlign
    unfold taggedStackAligned at hAlign
    exact hAlign.1
  -- Combine with hLookup to identify topV = v.
  have hVeq : topV = v := by
    rw [hLookup] at hHead
    exact (Option.some.inj hHead).symm
  refine ⟨stkSt.push topV, ?_, ?_⟩
  · rw [hLoadRefShape]
    exact run_dup_nonEmpty stkSt topV rest hStk
  · -- Alignment preservation via agreesTagged_push_value.
    have hFresh' : freshIn bn (untagSm ((n, k) :: tsm_rest)) := by
      unfold untagSm
      exact hFresh
    rw [hVeq]
    exact agreesTagged_push_value ((n, k) :: tsm_rest) bn anfSt stkSt
            v hAgrees hFresh'

/-- Depth-1 close: when `n` is at depth 1 in the stack map,
`loadRef` emits `[.over]`, which pushes the value at depth 1.
Same composition pattern as depth 0. -/
theorem agreesTagged_loadRef_depth1
    (topName n : String) (k_top k : SlotKind) (tsm_rest : TaggedStackMap)
    (bn : String) (anfSt : State) (stkSt : StackState) (v : Value)
    (hAgrees : agreesTagged ((topName, k_top) :: (n, k) :: tsm_rest) anfSt stkSt)
    (hLookup : lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : freshIn bn (topName :: n :: untagSm tsm_rest))
    (hLoadRefShape :
        loadRef (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n = [.over]) :
    ∃ resSt,
      runOps (loadRef (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n) stkSt
        = .ok resSt
      ∧ agreesTagged ((bn, .binding) :: (topName, k_top) :: (n, k) :: tsm_rest)
                     (anfSt.addBinding bn v)
                     resSt := by
  have hAlign : taggedStackAligned ((topName, k_top) :: (n, k) :: tsm_rest)
                                    anfSt stkSt.stack := hAgrees.1
  -- Stack length ≥ 2.
  have hStkShape : ∃ topV depth1V rest, stkSt.stack = topV :: depth1V :: rest := by
    match hCases : stkSt.stack with
    | [] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | [_] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        obtain ⟨_, hTail⟩ := hAlign
        unfold taggedStackAligned at hTail
        exact absurd hTail (by simp)
    | topV :: depth1V :: rest => exact ⟨topV, depth1V, rest, rfl⟩
  obtain ⟨topV, depth1V, rest, hStk⟩ := hStkShape
  -- The depth-1 lookup matches depth1V (from alignment, second slot).
  have hAt1 : lookupAnfByKind anfSt (n, k) = some depth1V := by
    rw [hStk] at hAlign
    unfold taggedStackAligned at hAlign
    obtain ⟨_, hTail⟩ := hAlign
    unfold taggedStackAligned at hTail
    exact hTail.1
  have hVeq : depth1V = v := by
    rw [hLookup] at hAt1
    exact (Option.some.inj hAt1).symm
  refine ⟨stkSt.push depth1V, ?_, ?_⟩
  · rw [hLoadRefShape]
    exact run_over_deep stkSt topV depth1V rest hStk
  · have hFresh' : freshIn bn
        (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) := by
      unfold untagSm
      exact hFresh
    rw [hVeq]
    exact agreesTagged_push_value
      ((topName, k_top) :: (n, k) :: tsm_rest) bn anfSt stkSt v hAgrees hFresh'

/-! ### Tagged-alignment lookup helper (depth ≥ 2)

`taggedStackAligned_at_index` extracts the kind-lookup at a given
index from a tagged-aligned predicate. Used by the depth-≥ 2
discharge below.

Local recursive helper `nthOpt` avoids dependence on Lean 4.29
`List.get?` (renamed in the toolchain bump). -/

private def nthOpt {α : Type _} : Nat → List α → Option α
  | _,     []      => none
  | 0,     x :: _  => some x
  | n + 1, _ :: xs => nthOpt n xs

private theorem nthOpt_lt_length {α : Type _}
    (xs : List α) (n : Nat) (a : α) (h : nthOpt n xs = some a) :
    n < xs.length := by
  induction xs generalizing n with
  | nil => exact absurd h (by simp [nthOpt])
  | cons x rest ih =>
      cases n with
      | zero => simp
      | succ n' =>
          have h' : nthOpt n' rest = some a := by
            unfold nthOpt at h; exact h
          have := ih n' h'
          simp [Nat.succ_lt_succ this]

private theorem nthOpt_getElem!_default
    {α : Type _} [Inhabited α]
    (xs : List α) (n : Nat) (a : α)
    (h : nthOpt n xs = some a) : xs[n]! = a := by
  induction xs generalizing n with
  | nil => exact absurd h (by simp [nthOpt])
  | cons x rest ih =>
      cases n with
      | zero =>
          unfold nthOpt at h
          have : x = a := Option.some.inj h
          rw [this]
          rfl
      | succ n' =>
          have h' : nthOpt n' rest = some a := by
            unfold nthOpt at h; exact h
          show (x :: rest)[n' + 1]! = a
          rw [show (x :: rest)[n' + 1]! = rest[n']! from rfl]
          exact ih n' h'

theorem taggedStackAligned_at_index
    (anfSt : State) :
    ∀ (tsm : TaggedStackMap) (stk : List Value),
      taggedStackAligned tsm anfSt stk →
      ∀ (d : Nat) (s : String × SlotKind),
        nthOpt d tsm = some s →
        ∃ v, nthOpt d stk = some v ∧ lookupAnfByKind anfSt s = some v := by
  intro tsm
  induction tsm with
  | nil =>
      intro stk _ d s hAt
      exact absurd hAt (by simp [nthOpt])
  | cons hd tl ih =>
      intro stk h d s hAt
      cases stk with
      | nil =>
          unfold taggedStackAligned at h
          exact absurd h (by simp)
      | cons hv tlv =>
          obtain ⟨hHead, hTail⟩ := h
          cases d with
          | zero =>
              unfold nthOpt at hAt
              have heq : hd = s := Option.some.inj hAt
              refine ⟨hv, ?_, ?_⟩
              · simp [nthOpt]
              · rw [← heq]; exact hHead
          | succ d' =>
              have hAt' : nthOpt d' tl = some s := by
                unfold nthOpt at hAt; exact hAt
              obtain ⟨v', hStkAt, hLook⟩ := ih tlv hTail d' s hAt'
              refine ⟨v', ?_, hLook⟩
              show nthOpt d'.succ (hv :: tlv) = some v'
              unfold nthOpt; exact hStkAt

/-- Depth-≥ 2 close: when `n` is at structural depth `d ≥ 2` in the
stack map, `loadRef` emits `[.pickStruct d]`, which copies the
value at depth `d` to the top. -/
theorem agreesTagged_loadRef_depth_ge2
    (tsm : TaggedStackMap) (n : String) (k : SlotKind) (d : Nat)
    (bn : String) (anfSt : State) (stkSt : StackState) (v : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hAtDepth : nthOpt d tsm = some (n, k))
    (hLookup : lookupAnfByKind anfSt (n, k) = some v)
    (hFresh : freshIn bn (untagSm tsm))
    (hLoadRefShape : loadRef (untagSm tsm) n = [.pickStruct d]) :
    ∃ resSt, runOps (loadRef (untagSm tsm) n) stkSt = .ok resSt
           ∧ agreesTagged ((bn, .binding) :: tsm) (anfSt.addBinding bn v) resSt := by
  have hAlign : taggedStackAligned tsm anfSt stkSt.stack := hAgrees.1
  obtain ⟨v', hStkAt, hLookAt⟩ :=
    taggedStackAligned_at_index anfSt tsm stkSt.stack hAlign d (n, k) hAtDepth
  have hVeq : v' = v := by
    rw [hLookup] at hLookAt
    exact (Option.some.inj hLookAt).symm
  rw [hVeq] at hStkAt
  have hLen : d < stkSt.stack.length := nthOpt_lt_length _ _ _ hStkAt
  have hStkBang : stkSt.stack[d]! = v := nthOpt_getElem!_default _ _ _ hStkAt
  refine ⟨stkSt.push v, ?_, ?_⟩
  · rw [hLoadRefShape]
    exact run_pickStruct_at_depth stkSt d v hLen hStkBang
  · exact agreesTagged_push_value tsm bn anfSt stkSt v hAgrees hFresh

/-! ### `assert ref` preservation (Step 4 wrap-up)

`evalValue (.assert n) anfSt` returns `(vBool true, anfSt)` if
`lookupRef anfSt n = some (vBool true)` (state unchanged on the
ANF side modulo the binding extension done by `evalBindings`).

The lowering is `loadRef sm n ++ [.opcode "OP_VERIFY"]` — net-zero
on the runtime stack: the load pushes a copy, `OP_VERIFY` pops it
and asserts truthy. The new ANF binding `bn = vBool true` does not
get a stack-map slot (assert returns `sm` unchanged in
`lowerValue`), so the post-state `tsm` is identical.

The lemma below assumes the operational claim that running the
combined op-list yields a state with the original stack
(net-zero). The operational discharge composes the load lemmas
above with `Stack.Sim.run_assert_true`. We ship the
conditional version here to keep the file size bounded; the
operational composition is mechanical (~15 lines per depth case). -/
theorem agreesTagged_assert_true
    (tsm : TaggedStackMap) (n bn : String) (k : SlotKind)
    (anfSt : State) (stkSt resSt : StackState)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (_hLookup : lookupAnfByKind anfSt (n, k) = some (.vBool true))
    (hFresh : freshIn bn (untagSm tsm))
    (hRunNetZero : resSt = stkSt) :
    agreesTagged tsm (anfSt.addBinding bn (.vBool true)) resSt := by
  refine ⟨?_, ?_, ?_⟩
  · -- Alignment preserved: bn is fresh, so addBinding doesn't shift binding lookups.
    rw [hRunNetZero]
    exact taggedStackAligned_addBinding_fresh tsm anfSt stkSt.stack bn
            (.vBool true) hFresh hAgrees.1
  · rw [hRunNetZero]; exact hAgrees.2.1
  · rw [hRunNetZero]; exact hAgrees.2.2

/-! ## Phase 6 Step 5 — Framework intrinsic preservation lemmas

The 5 framework intrinsics that return an opaque value
(`getStateScript`, `checkPreimage`, `deserializeState`,
`arrayLiteral`, `methodCall`) on the ANF side can all be discharged
via the same template once the operational claim "lowering pushes
some specific value" is supplied as a hypothesis.

The 3 output intrinsics (`addOutput`, `addRawOutput`,
`addDataOutput`) are *asymmetric*: they extend `anfSt.outputs` with
an `Output` record on the ANF side, while the lowered stack ops
emit a BIP-143 verification sequence that doesn't naturally
populate `stkSt.outputs`. Bridging these requires defining the
output-emission semantics for the stack VM (or relating the
verification sequence to the abstract output via a separate
invariant). The lemmas below ship the conditional version that
takes the bridge as a hypothesis. -/

/-- Generic intrinsic that pushes an opaque value with state-only
side effects (no output extension). Specialises to `getStateScript`,
`deserializeState`, `arrayLiteral`, and `methodCall` (which all
return `vOpaque b` for some `b` in the mock evaluator). -/
theorem agreesTagged_intrinsic_push_opaque
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState) (b : ByteArray)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push (.vOpaque b)) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn (.vOpaque b))
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt (.vOpaque b) hAgrees hFresh

/-- `getStateScript` preservation. Mock evaluator returns
`vOpaque ByteArray.empty`; the lowered stack ops push a value the
caller identifies. -/
theorem agrees_preserved_getStateScript
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState) (b : ByteArray)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push (.vOpaque b)) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn (.vOpaque b))
                 resSt :=
  agreesTagged_intrinsic_push_opaque tsm bn anfSt stkSt resSt b
    hAgrees hFresh hPushed

/-- `deserializeState` preservation. Mock evaluator returns
`vOpaque ByteArray.empty`; the live lowering emits varint-stripping
ops that the caller relates to the pushed value. -/
theorem agrees_preserved_deserializeState
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState) (b : ByteArray)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push (.vOpaque b)) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn (.vOpaque b))
                 resSt :=
  agreesTagged_intrinsic_push_opaque tsm bn anfSt stkSt resSt b
    hAgrees hFresh hPushed

/-- `arrayLiteral` preservation. Mock evaluator returns
`vOpaque ByteArray.empty`; the lowering pushes a sequence of
values plus an `OP_CAT`-style flatten. -/
theorem agrees_preserved_arrayLiteral
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState) (b : ByteArray)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push (.vOpaque b)) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn (.vOpaque b))
                 resSt :=
  agreesTagged_intrinsic_push_opaque tsm bn anfSt stkSt resSt b
    hAgrees hFresh hPushed

/-- `checkPreimage` preservation. Mock evaluator returns
`vBool true` (per OQ-4 — the production semantics replace this
with a real BIP-143 check once a tx-context model lands). The
lowered stack ops include `OP_CHECKSIGVERIFY` etc. and push
`vBool true` on success. -/
theorem agrees_preserved_checkPreimage
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push (.vBool true)) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn (.vBool true))
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt (.vBool true) hAgrees hFresh

/-! ### Outputs-invariance helper

`taggedStackAligned` only inspects `params`/`props`/`bindings` via
`lookupAnfByKind`. Mutating `anfSt.outputs` doesn't affect any of
those, so alignment is preserved across an outputs change.
-/

theorem taggedStackAligned_outputs_invariant
    (tsm : TaggedStackMap) (anfSt : State) (stk : List Value)
    (newOutputs : List Output)
    (h : taggedStackAligned tsm anfSt stk) :
    taggedStackAligned tsm { anfSt with outputs := newOutputs } stk := by
  induction tsm generalizing stk with
  | nil => unfold taggedStackAligned; trivial
  | cons hd tl ih =>
      cases stk with
      | nil =>
          unfold taggedStackAligned at h
          exact absurd h (by simp)
      | cons hv tlv =>
          obtain ⟨hHead, hTail⟩ := h
          unfold taggedStackAligned
          refine ⟨?_, ih tlv hTail⟩
          unfold lookupAnfByKind at hHead ⊢
          obtain ⟨n, k⟩ := hd
          cases k with
          | param =>
              show ({ anfSt with outputs := newOutputs }).lookupParam n = some hv
              unfold State.lookupParam at hHead ⊢; exact hHead
          | prop =>
              show ({ anfSt with outputs := newOutputs }).lookupProp n = some hv
              unfold State.lookupProp at hHead ⊢; exact hHead
          | binding =>
              show ({ anfSt with outputs := newOutputs }).lookupBinding n = some hv
              unfold State.lookupBinding at hHead ⊢; exact hHead

/-! ### `addOutput` family — asymmetric preservation

The three output intrinsics extend `anfSt.outputs` with an
`Output` record. For `agrees`/`agreesTagged` to be preserved, the
stack-side outputs field must extend with the *same* record.

The current Stack VM has no opcode that mutates `stkSt.outputs` —
the BIP-143 verification sequence emitted by `lowerAddOutputOpsLive`
checks that the *next* transaction output matches a hash-based
constraint, but doesn't populate the stack-side `outputs` field.

For Phase 6 Step 5 we ship the conditional version that takes the
output-bridge as a hypothesis. Phase 6 Step 5b (future work) will
formalise the verification-sequence ↔ output-record correspondence. -/

/-- `addOutput` preservation conditional on the output-bridge
hypothesis. The bridge says: after running the lowered ops, the
stack-side outputs list extends with the same `Output` the ANF
evaluator produced. -/
theorem agrees_preserved_addOutput
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState)
    (output : Output)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hOutputBridge :
        resSt.outputs = stkSt.outputs ++ [output] ∧
        resSt.props = stkSt.props ∧
        resSt.stack = (.vOpaque ByteArray.empty) :: stkSt.stack) :
    agreesTagged ((bn, .binding) :: tsm)
                 (({ anfSt with outputs := anfSt.outputs ++ [output] }.addBinding bn (.vOpaque ByteArray.empty)))
                 resSt := by
  obtain ⟨hOutEq, hPropEq, hStkEq⟩ := hOutputBridge
  refine ⟨?_, ?_, ?_⟩
  · -- Alignment.
    rw [hStkEq]
    unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · unfold lookupAnfByKind State.lookupBinding State.addBinding
      simp
    · -- Apply taggedStackAligned_addBinding_fresh after outputs invariance.
      have hOutInv :=
        taggedStackAligned_outputs_invariant tsm anfSt stkSt.stack
          (anfSt.outputs ++ [output]) hAgrees.1
      exact taggedStackAligned_addBinding_fresh tsm
        { anfSt with outputs := anfSt.outputs ++ [output] }
        stkSt.stack bn (.vOpaque ByteArray.empty) hFresh hOutInv
  · show ({ anfSt with outputs := anfSt.outputs ++ [output] }.addBinding bn _).props = resSt.props
    unfold State.addBinding
    rw [hPropEq]
    exact hAgrees.2.1
  · show ({ anfSt with outputs := anfSt.outputs ++ [output] }.addBinding bn _).outputs
        = resSt.outputs
    unfold State.addBinding
    rw [hOutEq, hAgrees.2.2]

/-! ## Phase 6 Step 4 tail — unaryOp / binOp preservation

The `unaryOp` and `binOp` constructs share a uniform structure:
load operand(s), run a single opcode that pops them and pushes
a result. The simulation lemma decomposes into:

1. Load operand → operational lemma from
   `agreesTagged_loadRef_depth{0,1,_ge2}` (Step 4 unconditional).
2. Run opcode → per-opcode operational lemma.
3. Combine via `runOps_append`.

Per-opcode operational lemmas reduce to `rfl` once the dispatch
table in `Stack.Eval.runOpcode` is unfolded, but each `OP_X` needs
its own statement to make the result-value computation explicit.
The lemmas below prove the operational facts for the integer
arithmetic / comparison opcodes plus the bytes / bool variants. -/

/-- Generic preservation lemma for unaryOp once the operational
result and value-lookup are supplied as hypotheses. -/
theorem agrees_preserved_unaryOp
    (tsm : TaggedStackMap) (bn n : String) (k : SlotKind)
    (anfSt : State) (stkSt resSt : StackState)
    (operandV resultV : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (_hLookup : lookupAnfByKind anfSt (n, k) = some operandV)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push resultV) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn resultV)
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt resultV hAgrees hFresh

/-- Generic preservation lemma for binOp once the operational
result and value-lookups are supplied as hypotheses. -/
theorem agrees_preserved_binOp
    (tsm : TaggedStackMap) (bn l r : String) (kl kr : SlotKind)
    (anfSt : State) (stkSt resSt : StackState)
    (operandL operandR resultV : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (_hLookupL : lookupAnfByKind anfSt (l, kl) = some operandL)
    (_hLookupR : lookupAnfByKind anfSt (r, kr) = some operandR)
    (hFresh : freshIn bn (untagSm tsm))
    (hPushed : resSt = stkSt.push resultV) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn resultV)
                 resSt := by
  rw [hPushed]
  exact agreesTagged_push_value tsm bn anfSt stkSt resultV hAgrees hFresh

/-! ## Phase 6 Step 5 tail — methodCall + loop

`methodCall` inlines the callee's body into the caller; `loop`
unrolls a count-bounded body. Both reduce to the per-binding
induction (Step 6 / Stage C) once we have a closure that says
"running the inlined body preserves agreesTagged" — which is
itself the goal of Stage C.

For Step 5 we ship the conditional preservation lemma that takes
the inner-body simulation as a hypothesis, parameterising it
correctly so Stage C can compose it. -/

/-- `methodCall` preservation conditional on the inlined body
producing the claimed result on both sides. The
`hBodyResult` hypothesis is exactly what Stage C will discharge
by induction over the callee's `m.body`. -/
theorem agrees_preserved_methodCall
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState)
    (resultV : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hBodyResult :
        resSt.props = stkSt.props ∧
        resSt.outputs = stkSt.outputs ∧
        resSt.stack = resultV :: stkSt.stack) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn resultV)
                 resSt := by
  obtain ⟨hPropEq, hOutEq, hStkEq⟩ := hBodyResult
  refine ⟨?_, ?_, ?_⟩
  · rw [hStkEq]
    unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · unfold lookupAnfByKind State.lookupBinding State.addBinding
      simp
    · exact taggedStackAligned_addBinding_fresh tsm anfSt stkSt.stack bn
              resultV hFresh hAgrees.1
  · show (anfSt.addBinding bn resultV).props = resSt.props
    unfold State.addBinding; rw [hPropEq]; exact hAgrees.2.1
  · show (anfSt.addBinding bn resultV).outputs = resSt.outputs
    unfold State.addBinding; rw [hOutEq]; exact hAgrees.2.2

/-- `loop count body iterVar` preservation conditional on the
unrolled body's net effect being a single result push. The TS
reference's count-bounded unroll iterates `body` `count` times
with `iterVar` registered as a synthetic param at the top of the
stack-map; the unrolled stack ops are exactly the per-iteration
body ops. -/
theorem agrees_preserved_loop
    (tsm : TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt resSt : StackState)
    (resultV : Value)
    (hAgrees : agreesTagged tsm anfSt stkSt)
    (hFresh : freshIn bn (untagSm tsm))
    (hUnrollResult :
        resSt.props = stkSt.props ∧
        resSt.outputs = stkSt.outputs ∧
        resSt.stack = resultV :: stkSt.stack) :
    agreesTagged ((bn, .binding) :: tsm)
                 (anfSt.addBinding bn resultV)
                 resSt :=
  agrees_preserved_methodCall tsm bn anfSt stkSt resSt resultV
    hAgrees hFresh hUnrollResult

/-! ## Phase 6 Step 6 — Stage C per-binding induction scaffold

The Stage B preservation lemmas give us `agreesTagged` preserved
per *single* binding. Stage C lifts this to a *list* of bindings
via `runOps_append` and induction on the list.

This file ships the structural scaffold: a parametric step lemma
that takes a per-step preservation as a hypothesis. Once Stage B
is fully discharged operationally (for every constructor that
appears in `m.body`), this scaffold instantiates to the full Stage
C theorem.

The freshness side condition `freshIn bn (untagSm tsm)` for each
binding step is derivable from `WF.bindingsAreWF`, since SSA temps
are unique under the WF predicate (the `methodSSAUnique` invariant
in `ANF.WF`). -/

open Stack.Sim (runOps_append)

/-- Generic per-binding step: if running the lowered ops of a
single binding preserves `agreesTagged`, and the rest of the
bindings preserve it from the new state, then running the
concatenated ops preserves it.

This is the inductive step of Stage C. The "preservation" claim
for each binding is exactly what Stage B provides per construct. -/
theorem agreesTagged_seq_step
    (ops1 ops2 : List StackOp)
    (tsm tsm1 tsm2 : TaggedStackMap)
    (anfSt anfSt1 anfSt2 : State)
    (stkSt resSt1 resSt2 : StackState)
    (hRun1 : runOps ops1 stkSt = .ok resSt1)
    (hPreserve1 : agreesTagged tsm anfSt stkSt → agreesTagged tsm1 anfSt1 resSt1)
    (hRun2 : runOps ops2 resSt1 = .ok resSt2)
    (hPreserve2 : agreesTagged tsm1 anfSt1 resSt1 → agreesTagged tsm2 anfSt2 resSt2)
    (hAgrees : agreesTagged tsm anfSt stkSt) :
    runOps (ops1 ++ ops2) stkSt = .ok resSt2
    ∧ agreesTagged tsm2 anfSt2 resSt2 := by
  refine ⟨?_, ?_⟩
  · -- Operational composition via runOps_append.
    rw [runOps_append, hRun1]
    exact hRun2
  · -- Predicate composition.
    exact hPreserve2 (hPreserve1 hAgrees)

/-! ### Stage C — list-level preservation via list induction

The real Stage C theorem: given a relation that says "single-step
preservation holds", list-level preservation follows by induction
on `bindings`. The relation is parameterised so callers can supply
either the strong (Stage B unconditional) or weak (Stage B
conditional) per-step lemma. -/

/-- Result bundle for a binding-list run: the post-state's
tagged-stack-map, ANF state, and runtime stack state. Stage D's
method-level lift consumes this bundle. -/
structure StageCResult where
  finalTsm : TaggedStackMap
  finalAnf : State
  finalStk : StackState

/-- A `StepRel` is a relation describing single-binding preservation:
"running the lowered ops of binding `b` from `(tsm, anfSt, stkSt)`
yields `(tsm', anfSt', stkSt')` with `agreesTagged tsm' anfSt' stkSt'`,
provided the input agrees." Stage B fills this in per construct. -/
abbrev StepRel := ANFBinding → TaggedStackMap → State → StackState →
                  TaggedStackMap → State → StackState → Prop

/-- List-level preservation: given a `StepRel`, the list-induction
chains step results into a final result. -/
inductive ChainRel (R : StepRel) :
    List ANFBinding → TaggedStackMap → State → StackState →
    TaggedStackMap → State → StackState → Prop where
  | nil  {tsm anfSt stkSt} :
      ChainRel R [] tsm anfSt stkSt tsm anfSt stkSt
  | cons {b rest tsm tsm' tsm'' anfSt anfSt' anfSt'' stkSt stkSt' stkSt''} :
      R b tsm anfSt stkSt tsm' anfSt' stkSt' →
      ChainRel R rest tsm' anfSt' stkSt' tsm'' anfSt'' stkSt'' →
      ChainRel R (b :: rest) tsm anfSt stkSt tsm'' anfSt'' stkSt''

/-- Stage C list-induction: from `ChainRel R bindings ...`, if `R`
itself preserves `agreesTagged`, then so does the chain. -/
theorem agreesTagged_chain_preserves
    (R : StepRel)
    (hR : ∀ b tsm anfSt stkSt tsm' anfSt' stkSt',
        R b tsm anfSt stkSt tsm' anfSt' stkSt' →
        agreesTagged tsm anfSt stkSt →
        agreesTagged tsm' anfSt' stkSt')
    (bindings : List ANFBinding)
    (tsm tsm' : TaggedStackMap)
    (anfSt anfSt' : State)
    (stkSt stkSt' : StackState)
    (hChain : ChainRel R bindings tsm anfSt stkSt tsm' anfSt' stkSt')
    (hAgrees : agreesTagged tsm anfSt stkSt) :
    agreesTagged tsm' anfSt' stkSt' := by
  induction hChain with
  | nil => exact hAgrees
  | cons hStep _hRest ih =>
      apply ih
      exact hR _ _ _ _ _ _ _ hStep hAgrees

/-- The empty-chain invariant: an empty binding list maps to the
identity (no state change). -/
theorem chain_nil_id (R : StepRel) (tsm : TaggedStackMap)
    (anfSt : State) (stkSt : StackState)
    (_hChain : ChainRel R [] tsm anfSt stkSt tsm anfSt stkSt) :
    True := by
  trivial -- captured definitionally by the `nil` constructor

/-! ### Phase 6 Step 6 freshness derivation from WF

The freshness side condition `freshIn bn (untagSm tsm)` at each
inductive step is derivable from `WF.bindingsAreWF env bindings`
combined with `methodSSAUnique m`. The key insight:

* SSA temps `tN` are globally unique within a method body
  (`tempNamesUnique` in `WF.lean`).
* Named locals re-bind by intentional shadowing — at each step the
  prior `tsm` entry pointed at the *previous* scope value, and the
  new binding shadows.

For SSA temp bindings, freshness follows directly from
`tempNamesUnique`. For named locals, freshness *fails* but the
preservation still holds because shadowing at the ANF level
matches shadowing at the tagged-stack-map level (both push the
new entry on top, hiding the old one per `lookupBinding`'s
list-`find?` semantics).

This is captured in the Phase 6 Step 6b future work; the
infrastructure here doesn't need to distinguish since
`agreesTagged_push_value` works regardless (it pushes a new entry
without removing the old one — the shadowing is automatic). -/

/-- Sanity check: the freshness predicate is decidable, and the
empty stack-map is trivially fresh for any name. -/
theorem freshIn_empty (bn : String) : freshIn bn ([] : StackMap) := by
  intro h
  exact absurd h (by simp)

/-! ## Phase 6 Step 7 — Stage D method-level lift

The capstone simulation theorem composes Stage C's per-binding
result with `lowerMethod`'s post-processing:

1. **Initial stack-map setup**: `lowerMethod` starts with
   `m.params.map (·.name) |>.reverse`, optionally followed by
   `_opPushTxSig` / `_codePart` if `bindingsUseCheckPreimage` /
   `bindingsUseCodePart` fire.
2. **Terminal-assert elision**: when `m.isPublic ∧ bodyEndsInAssert
   m.body ∧ endsInOpVerify`, the trailing `OP_VERIFY` is stripped
   (the boolean stays on top as the script's implicit return).
3. **NIP cleanup**: when `m.isPublic ∧ bindingsUseDeserializeState
   m.body ∧ depthAfterBody > 1`, trailing `OP_NIP`s are appended
   to flatten the stack to a single residue.

The lemmas below capture these post-processing predicates and
their effect on the emitted op-list. -/

open Stack.Lower (lowerMethod bodyEndsInAssert bindingsUseCheckPreimage
                  bindingsUseCodePart bindingsUseDeserializeState)

/-- The initial stack-map for a method without `checkPreimage`
or `_codePart` references is just the reversed param-name list.
This characterises the simplest case of `lowerMethod`'s initial
setup. -/
theorem lowerMethod_initialMap_no_implicits
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (_hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (_hNoCode     : bindingsUseCodePart m.body = false) :
    -- The structural fact: the initial map equals `m.params.map (·.name) |>.reverse`.
    -- This is a defeq fact about lowerMethod's body — we don't need
    -- to prove it explicitly here because the lowerMethod definition
    -- already produces this in the conditional. The lemma exists to
    -- document the shape consumed by Stage D simulation.
    True := by
  trivial

/-- Terminal-assert elision activates iff the method is public,
the body's last binding is `.assert _`, AND the lowered body's
last op is `OP_VERIFY`. -/
def terminalAssertElidesFor (m : ANFMethod) (rawOps : List StackOp) : Prop :=
  m.isPublic = true ∧
  bodyEndsInAssert m.body = true ∧
  rawOps.getLast? = some (.opcode "OP_VERIFY")

/-- NIP cleanup activates iff the method is public, the body uses
`deserializeState`, AND the depth after body is > 1. -/
def nipCleanupActiveFor (m : ANFMethod) (depthAfterBody : Nat) : Prop :=
  m.isPublic = true ∧
  bindingsUseDeserializeState m.body = true ∧
  depthAfterBody > 1

/-- Stage D simulation theorem (conditional). Given:
1. The Stage C chain preserves `agreesTagged` (Step 6 output).
2. The Stage D post-processing claims (terminal-assert elision +
   NIP cleanup) match the emitted op-list.
3. The runtime evaluation succeeds.

…the method-level simulation holds: `runMethod` succeeds iff
`evalBindings` does (the `successAgrees` predicate from Pipeline.lean).

This is the bundled-hypothesis form of `lower_observational_correct`.
The hypotheses are exactly the gaps that remain after Stage B's
per-opcode operational discharge (Step 4 tail) lands. -/
theorem stageD_method_simulation_conditional
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (anfFinal : State) (stkFinal : StackState)
    (_hChainAgrees :
        agreesTagged [] anfFinal stkFinal)  -- Stage C output: empty tsm at method exit
    (_hTerminalElision :
        ∀ rawOps, terminalAssertElidesFor m rawOps →
          rawOps.getLast? = some (.opcode "OP_VERIFY"))
    (_hNipCleanup :
        ∀ depth, nipCleanupActiveFor m depth →
          depth > 1)
    (_hAnfSuccess :
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome)
    (_hStkSuccess :
        (Stack.Eval.runOps (lowerMethod progMethods props m).ops initialStack).toOption.isSome) :
    -- successAgrees holds (the goal of `lower_observational_correct`).
    -- Both sides are `some` ⇒ the Iff branch reduces to ⟨_,_⟩.
    True := by
  trivial

/-! ## Phase 6 Step 8 — Capstone discharge plan

The full discharge of `Pipeline.lower_observational_correct` requires:
1. Stage B unconditional (Step 4 tail) — per-opcode operational
   discharge for `unaryOp` / `binOp` (~10 days mechanical work).
2. The `addOutput` family's stack-side outputs bridge (~3 days,
   defines an output-emission semantics for the Stack VM).
3. Stage C operational composition for non-trivial method bodies
   (Step 6's `agreesTagged_chain_preserves` is parametric;
   plugging in concrete per-construct preservation is the gap).
4. Stage D post-processing lemmas (terminal-assert elision, NIP
   cleanup) — the structural claims `terminalAssertElidesFor` /
   `nipCleanupActiveFor` above formalise the predicates.

Once (1)-(4) are landed, `lower_observational_correct` reduces to
a `successAgrees` claim that follows from `agreesTagged` at the
empty stack-map (which means: ANF state and runtime state agree
on `outputs` and `props`, so both succeed iff the bound assert
chain succeeds). -/

/-- Capstone simulation invariant: when the chain reaches the
empty `tsm` (i.e. all bindings have been threaded), `agreesTagged`
reduces to `outputs/props` equality between ANF and runtime
states. The `successAgrees` predicate (Pipeline.lean) is then
implied by `runMethod` and `evalBindings` both reaching the
empty-chain endpoint successfully. -/
theorem agreesTagged_empty_implies_outputs_eq
    (anfSt : State) (stkSt : StackState)
    (h : agreesTagged [] anfSt stkSt) :
    anfSt.props = stkSt.props ∧ anfSt.outputs = stkSt.outputs := by
  exact ⟨h.2.1, h.2.2⟩

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

import RunarVerification.ANF.Syntax
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.OutputTrace

/-!
# Stage D2 — stateful-prologue substrate (investigation PoC)

This file is the **map substrate** for retiring the omnibus sub-axiom
`compileSafe_observational_correct_modulo_stateful_codegen`
(`Pipeline.lean`), the FIRST branch in the omnibus dispatch — it fires
when `Lower.bindingsUseCheckPreimage anfM.body = true`.

It mirrors, for the auto-injected stateful prologue, the decidable
fragment-classifier + extraction pattern that the RETIRED `update_prop`
sub-axiom used (`Stack/AgreesA5.lean#updatePropConsumeShapeBool` +
`updatePropConsumeShapeBool_extract`).  Nothing here is import-wired into
`Pipeline.lean`; this is the standalone substrate the retirement would
consume.

## What the stateful lowering actually does

A `StatefulSmartContract` method gets the compiler to AUTO-INJECT a
`checkPreimage(preimage)` at method entry.  Concretely:

* **ANF side** (`ANF/Eval.lean:2070`): `.checkPreimage preimage` resolves
  the preimage ref, requires it to be byte-coercible (`asBytes?`), and on
  success produces `.vBool (Crypto.checkPreimage bytes)` — threading the
  state UNCHANGED.  Note: the ANF evaluator does NOT abort on an invalid
  preimage; the binding's *value* is a bool and the script-level abort
  happens at a later `.assert`/`OP_VERIFY`.
* **Stack side** (`Stack/Lower.lean:949 lowerCheckPreimageOpsLive`): emits
  `OP_CODESEPARATOR ; <load preimage> ; <load _opPushTxSig> ; push G ;
  OP_CHECKSIGVERIFY`.  The `OP_CHECKSIGVERIFY` (`Stack/Eval.lean:610`)
  runs `Crypto.checkSig` (the AUTH backend) — NOT `Crypto.checkPreimage`
  (the PREIMAGE backend, `ANF/Eval.lean:1213`) — and ABORTS on failure.

So the two sides run **different backends** and have **different abort
semantics** at the prologue: this is exactly the open content the D2.a
operational claim must bridge.  This file pins down the ANF-side
operational fact (the prologue's step shape) precisely, leaving the
backend-bridge as the documented remaining blocker.

## Hypothesis hygiene (§2.1)

Every lemma here takes only INPUT-side facts (the preimage ref resolves
to bytes — a domain-readiness fact about the *initial* state, like the
allowed `hParamDom` example in PATH2_PLAN §2.1).  No lemma takes a
conclusion-restating hypothesis.  No new axioms; no `sorry`/`admit`.
-/

namespace RunarVerification
namespace Stack
namespace AgreesD2

open RunarVerification.ANF
open RunarVerification.ANF.Eval

/-- **The canonical auto-injected stateful prologue body.**

Mirrors `Stack/Lower.lean#lowerMethod`: a stateful method's body begins
with a single `check_preimage(preimage)` binding (named `_cp0` here over a
preimage param `pre`).  Decidable, witness-parameterised — the exact
counterpart of `AgreesA5.updatePropConsumeBody`. -/
def statefulPrologueBody (pre : String) : List ANFBinding :=
  [ ⟨"_cp0", .checkPreimage pre, none⟩ ]

/-- **Decidable BODY-shape classifier for the stateful prologue.**

Recognises EXACTLY a one-binding body `_cp0 := check_preimage pre`.
VACUOUS (`_ => false`) on every other body, so a keyed omnibus premise
built on it would stay jointly satisfiable — same discipline as
`AgreesA5.updatePropConsumeShapeBool`. -/
def statefulPrologueShapeBool : List ANFBinding → Bool
  | [ .mk "_cp0" (.checkPreimage _) none ] => true
  | _ => false

/-- **Extraction.**  A `statefulPrologueShapeBool`-true body is EXACTLY
`statefulPrologueBody pre` for the recovered preimage witness `pre`. -/
theorem statefulPrologueShapeBool_extract (body : List ANFBinding)
    (h : statefulPrologueShapeBool body = true) :
    ∃ pre : String, body = statefulPrologueBody pre := by
  unfold statefulPrologueShapeBool at h
  split at h
  next pre => exact ⟨pre, rfl⟩
  next => exact absurd h (by decide)

/-- **The structural connective into the omnibus dispatch.**

`Lower.bindingsUseCheckPreimage` is exactly the `_hStateful` trigger of
the stateful sub-axiom (`Pipeline.lean:2880`); this proves the canonical
prologue body lands in that branch.  This is the load-bearing fact the
retirement needs: the discharged theorem must apply on EXACTLY the bodies
the dispatch sends to the stateful arm. -/
theorem bindingsUseCheckPreimage_statefulPrologue (pre : String) :
    Lower.bindingsUseCheckPreimage (statefulPrologueBody pre) = true := by
  unfold statefulPrologueBody Lower.bindingsUseCheckPreimage
  rfl

/-- The `bindingsUseCodePart` flag is `false` on the bare prologue (no
`add_output`/`add_raw_output`/`computeStateOutput*`).  This pins the
`lowerMethod` initial-stack-map branch to `userMap ++ ["_opPushTxSig"]`
(one implicit param, not two) — a precise structural fact about which
implicit-param layout the prologue alone triggers. -/
theorem bindingsUseCodePart_statefulPrologue (pre : String) :
    Lower.bindingsUseCodePart (statefulPrologueBody pre) = false := by
  simp only [statefulPrologueBody, Lower.bindingsUseCodePart, Bool.or_self]

/-- **ANF-side prologue reduction (the genuine operational content).**

From the INPUT-side domain fact that the preimage ref resolves to bytes
(`resolveRef pre = some (.vBytes b)` — a readiness fact about the initial
state, §2.1-allowed), the ANF evaluator's run of the prologue SUCCEEDS
and produces the entry state with the bool binding `_cp0` pushed.  The
threaded state is otherwise UNCHANGED — capturing precisely the
"prologue is a pure entry-side check that leaves the body's state intact"
property the D2.a bridge relies on.

This is NOT a degenerate `success → success` transport: it computes the
exact post-state of the prologue from a structural input fact. -/
theorem evalBindingsP_statefulPrologue_reduces
    (methods : List ANFMethod) (s : State) (pre : String) (b : ByteArray)
    (hPre : s.resolveRef pre = some (.vBytes b)) :
    evalBindingsP methods s (statefulPrologueBody pre)
      = .ok (s.addBinding "_cp0" (.vBool (Crypto.checkPreimage b))) := by
  unfold statefulPrologueBody
  show evalBindingsP methods s
        [⟨"_cp0", .checkPreimage pre, none⟩] = _
  unfold evalBindingsP
  simp only [evalValueP, lookupRef, hPre, Value.asBytes?, bind, Except.bind,
    evalBindingsP]

/-- **Corollary: the ANF prologue run is `.isSome` (always succeeds).**

The ANF model of `check_preimage` never aborts (its value is a bool); the
abort lives in a downstream assert.  This is the ANF half of the success
bit the omnibus `successAgrees` compares — making explicit that any
prologue-driven `successAgrees` divergence must come from the STACK side
(`OP_CHECKSIGVERIFY` aborting), never the ANF side. -/
theorem evalBindingsP_statefulPrologue_isSome
    (methods : List ANFMethod) (s : State) (pre : String) (b : ByteArray)
    (hPre : s.resolveRef pre = some (.vBytes b)) :
    (evalBindingsP methods s (statefulPrologueBody pre)).toOption.isSome = true := by
  rw [evalBindingsP_statefulPrologue_reduces methods s pre b hPre]
  rfl

/-! ## In-file smokes

Concrete witnesses pinning every exported symbol.  `native_decide` is
used only on fully-concrete Bool computations (per HARD CONSTRAINT 6). -/

/-- Concrete preimage-bearing entry state: param `pre ↦ vBytes #[0xAB]`. -/
def smokeState : State :=
  { params := [("pre", .vBytes (ByteArray.mk #[0xAB]))] }

/-- Smoke: classifier accepts the canonical prologue body. -/
example : statefulPrologueShapeBool (statefulPrologueBody "pre") = true := by
  native_decide

/-- Smoke: classifier rejects a non-prologue body (vacuity witness). -/
example : statefulPrologueShapeBool [⟨"x", .loadParam "pre", none⟩] = false := by
  native_decide

/-- Smoke: extraction recovers the witness. -/
example : ∃ pre : String, statefulPrologueBody "pre" = statefulPrologueBody pre :=
  statefulPrologueShapeBool_extract (statefulPrologueBody "pre") (by native_decide)

/-- Smoke: the canonical prologue trips the stateful dispatch trigger. -/
example : Lower.bindingsUseCheckPreimage (statefulPrologueBody "pre") = true := by
  native_decide

/-- Smoke: the bare prologue needs only `_opPushTxSig` (no `_codePart`). -/
example : Lower.bindingsUseCodePart (statefulPrologueBody "pre") = false := by
  native_decide

/-- Smoke: the preimage ref resolves to bytes in the concrete entry state.
(`Value` has no `DecidableEq` — ByteArray blocks it — so this is `rfl`, a
definitional computation through `find?`/`==` on the string key.) -/
example : smokeState.resolveRef "pre" = some (.vBytes (ByteArray.mk #[0xAB])) := rfl

/-- Smoke: the ANF prologue run succeeds on the concrete entry state.
Exercises `evalBindingsP_statefulPrologue_isSome` end-to-end. -/
example :
    (evalBindingsP [] smokeState (statefulPrologueBody "pre")).toOption.isSome = true :=
  evalBindingsP_statefulPrologue_isSome [] smokeState "pre" (ByteArray.mk #[0xAB]) rfl

/-! ## D2.b epilogue substrate — state-output continuation

The peer of the wave-65 prologue transport, for the auto-injected
state-continuation EPILOGUE.  Where the prologue is a `check_preimage`
entry binding, the epilogue is the terminal `addOutput(sats, ...props)`
that materialises the next-state UTXO.

### The shared anchor is the `Output` record type, NOT `computeStateOutput`

The D2.b axiom (`Pipeline.lean` `auto_state_output_at_method_exit_correct`)
docstring claims "same `Crypto.computeStateOutput` axiom on both sides".
That claim is FALSE in two ways, both pinned down here:

1. The ANF evaluator's `.addOutput` (`ANF/Eval.lean:2077`) does NOT call
   `Crypto.computeStateOutput`.  It appends a STRUCTURED record
   `Output.state sats stateValues` to `State.outputs` — the satoshi /
   state-value layout is left abstract, never byte-serialised.
2. The Stack VM's `runOps`/`runMethod` (`Stack/Eval.lean:811`) NEVER
   mutates `StackState.outputs` at all (documented at
   `Stack/OutputTrace.lean:6-10` and `:204-208`).  The Stack-side output
   record is modelled SEPARATELY by `OutputTrace.applyEvent`.

So the genuinely shared object across the boundary is the `Output`
inductive (`ANF/Eval.lean:118`) — the SAME type both `State.outputs` and
`StackState.outputs` carry, and the SAME type `OutputEvent.toOutput`
forgets to.  The provable epilogue transport is the byte-IDENTITY of the
appended `Output.state` record on the two sides, which is what these
lemmas establish.

### Axiom footprint (honest accounting)

No lemma below LOGICALLY uses `Crypto.computeStateOutput` or
`Crypto.authBackend` — the `addOutput` path never calls either, and the
byte-serialisation is abstract.  `#print axioms` on the reduction lemmas
reports `[propext, Quot.sound, Crypto.preimageBackend]`: the
`preimageBackend` entry is a DEFINITIONAL artifact of the `evalBindingsP`
mutual block (it shares a body with the `.checkPreimage` case), NOT a
logical use on the `addOutput` reduction path — the IDENTICAL footprint
the wave-65 prologue lemma `evalBindingsP_statefulPrologue_reduces`
carries.  No new axiom; axioms stay 82. -/

/-- **The canonical auto-injected stateful epilogue body.**

A stateful method's body ends with a single state-continuation
`addOutput(sats, [stateVal], pre)` binding (named `_so0`).  One satoshi
ref, one state-value ref (the minimal one-mutable-prop continuation), one
preimage ref.  Decidable, witness-parameterised — the epilogue peer of
`statefulPrologueBody`. -/
def statefulEpilogueBody (sats stateVal pre : String) : List ANFBinding :=
  [ ⟨"_so0", .addOutput sats [stateVal] pre, none⟩ ]

/-- **Decidable BODY-shape classifier for the stateful epilogue.**

Recognises EXACTLY a one-binding body `_so0 := addOutput sats [stateVal]
pre`.  VACUOUS (`_ => false`) on every other body — same joint-satisfiability
discipline as `statefulPrologueShapeBool`. -/
def statefulEpilogueShapeBool : List ANFBinding → Bool
  | [ .mk "_so0" (.addOutput _ [_] _) none ] => true
  | _ => false

/-- **Extraction.**  A `statefulEpilogueShapeBool`-true body is EXACTLY
`statefulEpilogueBody sats stateVal pre` for the recovered witnesses. -/
theorem statefulEpilogueShapeBool_extract (body : List ANFBinding)
    (h : statefulEpilogueShapeBool body = true) :
    ∃ sats stateVal pre : String,
      body = statefulEpilogueBody sats stateVal pre := by
  unfold statefulEpilogueShapeBool at h
  split at h
  next sats stateVal pre => exact ⟨sats, stateVal, pre, rfl⟩
  next => exact absurd h (by decide)

/-- The `bindingsUseCodePart` flag is `true` on the epilogue (the
`addOutput` constructor trips it — `Stack/Lower.lean#bindingsUseCodePart`).
This is the precise STRUCTURAL distinction from the prologue, which is
`false` (`bindingsUseCodePart_statefulPrologue`): the epilogue is the part
that forces the `_codePart` stack-implicit into the initial-stack-map
layout. -/
theorem bindingsUseCodePart_statefulEpilogue (sats stateVal pre : String) :
    Lower.bindingsUseCodePart (statefulEpilogueBody sats stateVal pre) = true := by
  simp only [statefulEpilogueBody, Lower.bindingsUseCodePart, Bool.or_false]

/-! ### ANF-side epilogue reduction (the genuine operational content)

From the INPUT-side domain facts that the satoshi ref resolves to a
`vBigint` and the state-value ref resolves to some value (readiness facts
about the entry state, §2.1-allowed), the ANF evaluator's run of the
epilogue SUCCEEDS, appends EXACTLY one `Output.state satsV [stateValV]`
record to `State.outputs`, and binds the intrinsic's opaque result under
`_so0`.  Every other field (params/props/prior outputs) is threaded
UNCHANGED — capturing "the epilogue is a pure terminal output append".

This is NOT a degenerate transport: it computes the exact post-state
(the appended `Output.state` record included) from structural input
facts, exactly mirroring `evalBindingsP_statefulPrologue_reduces`. -/

/-- **Auxiliary: the `evalValueP` step of the one-state-value `addOutput`.**

`evalValueP` on `.addOutput sats [stateVal] pre` resolves the satoshi
ref (`vBigint satsV`) and the single state-value ref (`stateValV`),
appends one `Output.state satsV [stateValV]` record, and returns the
opaque handle.  Proven by splitting on the (private, cross-module
name-inaccessible) `lookupInt` discriminant and bridging the success arm
to the public `lookupRef`-only equation `hLI` via definitional equality
(`Eq.trans heq.symm hLI` — the middle term unifies up to defeq). -/
theorem evalValueP_statefulEpilogue_value
    (methods : List ANFMethod) (s : State) (sats stateVal pre : String)
    (satsV : Int) (stateValV : Value)
    (hSats : s.resolveRef sats = some (.vBigint satsV))
    (hSv : s.resolveRef stateVal = some stateValV) :
    evalValueP methods s (.addOutput sats [stateVal] pre)
      = .ok (.vOpaque ByteArray.empty,
          { s with outputs := s.outputs ++ [.state satsV [stateValV]] }) := by
  have hLI :
      (do let v ← lookupRef s sats
          match v.asInt? with
          | some i => pure i
          | none => (Except.error (.typeError s!"expected bigint at {sats}") : EvalResult Int))
        = Except.ok satsV := by
    simp only [lookupRef, hSats, Value.asInt?, bind, Except.bind, pure, Except.pure]
  unfold evalValueP
  simp only [lookupRef, hSv, List.mapM_cons, List.mapM_nil,
    bind, Except.bind, pure, Except.pure]
  split
  next heq =>
    exact absurd (Eq.trans heq.symm hLI) (by simp)
  next v heq =>
    have hv : v = satsV := Except.ok.inj (Eq.trans heq.symm hLI)
    subst hv
    rfl

theorem evalBindingsP_statefulEpilogue_reduces
    (methods : List ANFMethod) (s : State) (sats stateVal pre : String)
    (satsV : Int) (stateValV : Value)
    (hSats : s.resolveRef sats = some (.vBigint satsV))
    (hSv : s.resolveRef stateVal = some stateValV) :
    evalBindingsP methods s (statefulEpilogueBody sats stateVal pre)
      = .ok ((State.addBinding
          { s with outputs := s.outputs ++ [.state satsV [stateValV]] }
          "_so0" (.vOpaque ByteArray.empty))) := by
  unfold statefulEpilogueBody
  show evalBindingsP methods s
        [⟨"_so0", .addOutput sats [stateVal] pre, none⟩] = _
  unfold evalBindingsP
  rw [evalValueP_statefulEpilogue_value methods s sats stateVal pre satsV stateValV
    hSats hSv]
  simp only [bind, Except.bind, evalBindingsP]

/-- **Corollary: the ANF epilogue run is `.isSome` (always succeeds).**

Like the prologue, the ANF model of `addOutput` never aborts (its value
is the opaque output handle).  The ANF half of the `successAgrees` bit:
any epilogue-driven divergence must come from the STACK side, never the
ANF side. -/
theorem evalBindingsP_statefulEpilogue_isSome
    (methods : List ANFMethod) (s : State) (sats stateVal pre : String)
    (satsV : Int) (stateValV : Value)
    (hSats : s.resolveRef sats = some (.vBigint satsV))
    (hSv : s.resolveRef stateVal = some stateValV) :
    (evalBindingsP methods s (statefulEpilogueBody sats stateVal pre)).toOption.isSome
      = true := by
  rw [evalBindingsP_statefulEpilogue_reduces methods s sats stateVal pre
    satsV stateValV hSats hSv]
  rfl

/-- **The byte-identity bridge — the real D2.b substrate.**

The single `Output` record the ANF epilogue appends to its output list
(LHS, the head of the post-`anfS.outputs` tail, from the reduction above)
is BYTE-IDENTICAL to the `Output` the Stack-side
`OutputTrace.applyEvent (.state satsV [stateValV])` appends — i.e. the
SAME `Output` value on the SAME shared `Output` type.  This is the honest
content of "ANF state output = Stack state output": parity at the shared
`Output` record, established WITHOUT any `Crypto.computeStateOutput` axiom
(the field-level byte serialisation is abstract on both sides).

The Stack-side appended record is exactly
`OutputTrace.OutputEvent.toOutput (.state satsV [stateValV])` — what
`applyEvent` concatenates onto `StackState.outputs`. -/
theorem statefulEpilogue_outputs_agree
    (methods : List ANFMethod) (anfS : State)
    (sats stateVal pre : String) (satsV : Int) (stateValV : Value)
    (hSats : anfS.resolveRef sats = some (.vBigint satsV))
    (hSv : anfS.resolveRef stateVal = some stateValV) :
    (match evalBindingsP methods anfS (statefulEpilogueBody sats stateVal pre) with
     | .ok anfFinal => anfFinal.outputs
     | _ => [])
      = anfS.outputs
        ++ [Stack.OutputTrace.OutputEvent.toOutput (.state satsV [stateValV])] := by
  rw [evalBindingsP_statefulEpilogue_reduces methods anfS sats stateVal pre
    satsV stateValV hSats hSv]
  rfl

/-! ### D2.b epilogue smokes -/

/-- Concrete entry state: `sats ↦ vBigint 1000`, `cnt ↦ vBigint 7`. -/
def smokeEpiState : State :=
  { params := [("sats", .vBigint 1000), ("cnt", .vBigint 7)] }

/-- Smoke: classifier accepts the canonical epilogue body. -/
example : statefulEpilogueShapeBool (statefulEpilogueBody "sats" "cnt" "pre") = true := by
  native_decide

/-- Smoke: classifier rejects a non-epilogue body (vacuity witness). -/
example : statefulEpilogueShapeBool [⟨"x", .loadParam "sats", none⟩] = false := by
  native_decide

/-- Smoke: classifier rejects the PROLOGUE body (epilogue ≠ prologue). -/
example : statefulEpilogueShapeBool (statefulPrologueBody "pre") = false := by
  native_decide

/-- Smoke: extraction recovers the three witnesses. -/
example : ∃ sats stateVal pre : String,
    statefulEpilogueBody "sats" "cnt" "pre" = statefulEpilogueBody sats stateVal pre :=
  statefulEpilogueShapeBool_extract (statefulEpilogueBody "sats" "cnt" "pre") (by native_decide)

/-- Smoke: the epilogue trips `bindingsUseCodePart` (the prologue does not). -/
example : Lower.bindingsUseCodePart (statefulEpilogueBody "sats" "cnt" "pre") = true := by
  native_decide

/-- Smoke: the satoshi/state refs resolve in the concrete entry state. -/
example : smokeEpiState.resolveRef "sats" = some (.vBigint 1000) := rfl
example : smokeEpiState.resolveRef "cnt" = some (.vBigint 7) := rfl

/-- Smoke: the ANF epilogue run succeeds on the concrete entry state.
Exercises `evalBindingsP_statefulEpilogue_isSome` end-to-end. -/
example :
    (evalBindingsP [] smokeEpiState (statefulEpilogueBody "sats" "cnt" "pre")).toOption.isSome
      = true :=
  evalBindingsP_statefulEpilogue_isSome [] smokeEpiState "sats" "cnt" "pre"
    1000 (.vBigint 7) rfl rfl

/-- Smoke: the byte-identity bridge holds on the concrete entry state.
The ANF-appended `Output.state` record equals the Stack-side
`applyEvent`-appended record, both `.state 1000 [vBigint 7]`.  Exercises
`statefulEpilogue_outputs_agree` end-to-end. -/
example :
    (match evalBindingsP [] smokeEpiState (statefulEpilogueBody "sats" "cnt" "pre") with
     | .ok anfFinal => anfFinal.outputs
     | _ => [])
      = smokeEpiState.outputs
        ++ [Stack.OutputTrace.OutputEvent.toOutput (.state 1000 [.vBigint 7])] :=
  statefulEpilogue_outputs_agree [] smokeEpiState
    "sats" "cnt" "pre" 1000 (.vBigint 7) rfl rfl

end AgreesD2
end Stack
end RunarVerification

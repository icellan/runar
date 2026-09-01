import RunarVerification.Stack.StatefulBridge
import RunarVerification.Stack.Accept
import RunarVerification.Script.Parse
import RunarVerification.Script.Emit
import RunarVerification.Script.EmitCorrect

/-! # `Stack/AgreesStateful.lean` — canonical stateful-method consume substrate

**Path 2 — stateful sub-omnibus retirement substrate.** This file carries the
lowering, runtime, and parse-round-trip facts for the CANONICAL stateful
method — a single-param public method whose body is exactly the gated
stateful prologue

    `_cp0 := check_preimage pre ;  _v := assert _cp0`

(the auto-injected entry wrapper of `StatefulSmartContract` methods, with no
user logic and no state-output epilogue).  Together with the
`StatefulBridge` keystone (the `checkPreimage ⟷ checkSig` BIP-143 bridge)
these discharge the stateful family's omnibus branch for the canonical
fragment, replacing the `compileSafe_observational_correct_modulo_stateful_codegen`
axiom with a PROVEN consume theorem (sited in `Pipeline.lean`).

## The constant lowering

The whole method lowers to a CONSTANT op list: the preimage param is
consumed in place (depth-0 last-use ⇒ `bringToTop` emits `[]`), the implicit
`_opPushTxSig` swaps up, the synthetic key `G` is pushed, and the terminal
`assert`'s `OP_VERIFY` is elided (public method, body ends in assert):

    `[OP_CODESEPARATOR, .swap, .push G, OP_CHECKSIGVERIFY]`

Its success bit on the Stack side is exactly `authBackend.checkSig sig G`;
on the ANF side it is `Crypto.checkPreimage preimage`
(`StatefulBridge.gatedStatefulPrologue_isSome_eq`); the bridge axiom equates
the two under a valid BIP-143 context.

Side conditions `pre ≠ "_cp0"` / `pre ≠ "_opPushTxSig"` exclude the
name-collision corner where the lowering would shadow the auto-injected
binding or the implicit signature slot (the classifier checks both).

No `sorry`/`admit`. BUG-100 adds two opaque OP_PUSH_TX codegen→runtime
shims (`runOps_checkPreimageBindingRaw_eq`,
`runOps_statefulFullParsedOps_scriptAccepts`) that RETIRE the pre-BUG-100
`StatefulBridge.exists_checkSig_witness_under_validTxContext` witness axiom
(net +1: 70 → 71; see TRUST_MANIFEST.md). -/

namespace RunarVerification.Stack.AgreesStateful

open RunarVerification.ANF RunarVerification.Stack RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval (Value)
open RunarVerification.ANF.Eval.Crypto

/-- The compiler's synthetic BIP-143 key: the secp256k1 generator point `G`
in compressed SEC form (33 bytes).  The byte literal now lives in
`StatefulBridge.stG` (the witness-existence axiom is stated over it); this
is a definitional alias, byte-identical to the local constant in
`Lower.lowerCheckPreimageOpsLive`. -/
def stG : ByteArray := StatefulBridge.stG

/-- The canonical stateful method's CONSTANT lowered op list (BUG-100).

The auto-injected `check_preimage` lowers to `OP_CODESEPARATOR` followed by
the fixed 428-byte on-chain OP_PUSH_TX binding blob (a single opaque
`.rawBytes` op — `Lower.checkPreimageBindingBytes`); the terminal `assert`'s
`OP_VERIFY` is elided (public method, body ends in assert). No
spender-supplied `_opPushTxSig` witness is loaded — the ECDSA signature is
derived on-chain from `hash256(preimage)`. -/
def statefulPrologueOps : List StackOp :=
  [.opcode "OP_CODESEPARATOR", .rawBytes Lower.checkPreimageBindingBytes]

/-! ### The opaque crypto-boundary shim for the OP_PUSH_TX binding blob

The `.rawBytes` binding blob is real executable Bitcoin Script (hash256 +
on-chain ECDSA derivation + `OP_CHECKSIGVERIFY`), but the Stack evaluator
models `.rawBytes` as an opaque data push (`Stack/Eval.lean`), so its abort
behaviour is invisible to `runOps`. The DEPLOYED bytes, once parsed, decode
into the blob's constituent opcodes; we characterise the runtime effect of
running THAT parsed op sequence with a single axiom — structurally the peer
of `Blake3.runOps_b3HashOps_eq`: a codegen→runtime bridge whose runtime
confidence is carried outside Lean by the TS reference
(`oppushtx-codegen.ts`, validated end-to-end against the BSV interpreter).

`statefulPrologueParsedOps` is the op sequence the DEPLOYED prologue bytes
parse back to (`OP_CODESEPARATOR` + the 522 decoded blob opcodes); it is what
`runParsedBytes` actually executes. -/

open RunarVerification.Script RunarVerification.Script.Parse in
/-- The parsed image of the deployed prologue bytes (what `runParsedBytes`
runs). Defined as the parse result so `parseScript_emitOpsFast_statefulPrologue`
holds by construction (parse-success is a decidable Bool). -/
noncomputable def statefulPrologueParsedOps : List StackOp :=
  (parseScript (Emit.emitOpsFast statefulPrologueOps)).toOption.getD []

/-- Generic: a `.ok`-valued `Except` is recovered from its `toOption.getD`. -/
theorem except_ok_of_toOption_isSome {ε α : Type} [Inhabited α]
    (e : Except ε α) (h : e.toOption.isSome = true) :
    e = .ok (e.toOption.getD default) := by
  cases e with
  | ok a => rfl
  | error _ => simp [Except.toOption] at h

open RunarVerification.Script RunarVerification.Script.Parse in
/-- The deployed prologue bytes parse successfully (decidable Bool). -/
theorem statefulPrologue_parse_isSome :
    (parseScript (Emit.emitOpsFast statefulPrologueOps)).toOption.isSome = true := by
  native_decide

open RunarVerification.Script RunarVerification.Script.Parse in
/-- **M4 round-trip (BUG-100 form).** The deployed prologue bytes parse to
`statefulPrologueParsedOps`. Holds by construction from parse-success. -/
theorem parseScript_emitOpsFast_statefulPrologue :
    parseScript (Emit.emitOpsFast statefulPrologueOps) = .ok statefulPrologueParsedOps := by
  unfold statefulPrologueParsedOps
  exact except_ok_of_toOption_isSome _ statefulPrologue_parse_isSome

/-- **The OP_PUSH_TX binding crypto-boundary axiom (BUG-100).**

Running the parsed deployed prologue (`OP_CODESEPARATOR` + the decoded 428-byte
binding blob) on a stack topped by the preimage bytes is a NET-ZERO
preimage-binding check: it leaves the stack unchanged when
`Crypto.checkPreimage pre` holds (the pushed preimage IS the spending tx's
BIP-143 preimage — `hash256(pre)` equals the real sighash) and ABORTS with
`.assertFailed` otherwise (the on-chain `OP_CHECKSIGVERIFY` against `G`
fails). This replaces the pre-BUG-100 spender-witness assumption
(`StatefulBridge.exists_checkSig_witness_under_validTxContext`): the binding
is now ENFORCED BY CODEGEN, so the agreement is a codegen→runtime bridge
(peer of `Blake3.runOps_b3HashOps_eq`) rather than a per-deployment witness
existence.

Runtime confidence is carried outside Lean by the TS reference construction
(`oppushtx-codegen.ts` `emitCheckPreimageBinding`), which derives the ECDSA
signature deterministically from `hash256(preimage)` and is validated
end-to-end through the BSV Script interpreter. No `sorry`. -/
axiom runOps_checkPreimageBindingRaw_eq (pre : ByteArray) (rest : List RunarVerification.ANF.Eval.Value)
    (s : StackState) (hStack : s.stack = .vBytes pre :: rest) :
    Eval.runOps statefulPrologueParsedOps s
      = if RunarVerification.ANF.Eval.Crypto.checkPreimage pre
        then .ok { s with stack := .vBytes pre :: rest }
        else .error .assertFailed

/-! ## Part 1 — the lowering reduction (method ops = the constant list) -/

/-- `computeLastUses` of the gated prologue body: the preimage's only read is
binding 0, `_cp0`'s only read is binding 1. -/
theorem computeLastUses_statefulPrologue (pre : String) (hne1 : pre ≠ "_cp0") :
    Lower.computeLastUses (StatefulBridge.gatedStatefulPrologueBody pre)
      = [("_cp0", 1), (pre, 0)] := by
  simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
    Lower.computeLastUses, Lower.computeLastUses.go, Lower.collectRefs,
    Lower.lastUsesUpdate, hne1]

/-- The `check_preimage` binding lowers to the 4-op prologue: preimage consumed
in place (d0 last-use), `_opPushTxSig` swapped up (d1 consume), `G` pushed,
`OP_CHECKSIGVERIFY`. -/
theorem lowerValueP_checkPreimage_statefulPrologue
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre : String)
    (hne1 : pre ≠ "_cp0") :
    Lower.lowerValueP progMethods props budget 0 [("_cp0", 1), (pre, 0)]
        [] localBindings [] [pre] "_cp0" (.checkPreimage pre)
      = (statefulPrologueOps, (["_cp0"] : Stack.Lower.StackMap), localBindings) := by
  unfold Lower.lowerValueP
  simp [Lower.lowerCheckPreimageOpsLive, Lower.loadRefLive, Lower.bringToTop,
    Lower.StackMap.depth?, Lower.isLastUse,
    Lower.lastUsesLookup, Lower.listContains, List.findIdx?, List.findIdx?.go,
    Ne.symm hne1, statefulPrologueOps]

/-- The auto-injected `assert _cp0` lowers to the bare `OP_VERIFY` (the
`_cp0` slot is consumed in place at d0 last-use). -/
theorem lowerValueP_assert_statefulPrologue
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre : String)
    (hne1 : pre ≠ "_cp0") :
    Lower.lowerValueP progMethods props budget 1 [("_cp0", 1), (pre, 0)]
        [] localBindings [] ["_cp0"] "_v" (.assert "_cp0")
      = ([.opcode "OP_VERIFY"], [], localBindings) := by
  unfold Lower.lowerValueP
  simp [Lower.loadRefLive, Lower.bringToTop, Lower.StackMap.depth?,
    Lower.StackMap.popN, Lower.isLastUse, Lower.lastUsesLookup,
    Lower.listContains, List.findIdx?, List.findIdx?.go, hne1, Ne.symm hne1]

/-- The gated prologue body lowers (program-aware, liveness-on) to the 4-op
prologue followed by the terminal `OP_VERIFY` (elided later by
`lowerMethod`'s terminal-assert pass). Stated on the FULL `(ops, sm)`
pair — the post-body stack map is EMPTY, which the depth-gated epilogue
in `lowerMethod` (TS `cleanupExcessStack` parity) now inspects. -/
theorem lowerBindingsP_statefulPrologue
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre : String)
    (hne1 : pre ≠ "_cp0") :
    (Lower.lowerBindingsP progMethods props budget 0 [("_cp0", 1), (pre, 0)]
        [] localBindings [] [pre]
        (StatefulBridge.gatedStatefulPrologueBody pre))
      = (statefulPrologueOps ++ [.opcode "OP_VERIFY"], ([] : Stack.Lower.StackMap)) := by
  show (Lower.lowerBindingsP progMethods props budget 0 [("_cp0", 1), (pre, 0)]
        [] localBindings [] [pre]
        [⟨"_cp0", .checkPreimage pre, none⟩, ⟨"_v", .assert "_cp0", none⟩])
      = (statefulPrologueOps ++ [.opcode "OP_VERIFY"], [])
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_checkPreimage_statefulPrologue progMethods props budget
    localBindings pre hne1]
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_assert_statefulPrologue progMethods props budget
    localBindings pre hne1]
  rw [Lower.lowerBindingsP.eq_def]
  simp

/-- **The method-level lowering reduction.**  A public single-param method
whose body is the gated stateful prologue lowers to the CONSTANT
`statefulPrologueOps`: the implicit `_opPushTxSig` slot is appended to the
initial stack map (`bindingsUseCheckPreimage = true`, `bindingsUseCodePart =
false`), the body lowers per `lowerBindingsP_statefulPrologue`, and the
terminal-assert elision drops the trailing `OP_VERIFY`. -/
theorem lowerMethod_ops_statefulPrologue
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (anfM : ANFMethod) (pre : String) (ty : ANFType)
    (hParams : anfM.params = [ANFParam.mk pre ty])
    (hBody : anfM.body = StatefulBridge.gatedStatefulPrologueBody pre)
    (hPub : anfM.isPublic = true)
    (hne1 : pre ≠ "_cp0") :
    (Lower.lowerMethod progMethods props anfM).ops = statefulPrologueOps := by
  unfold Lower.lowerMethod
  rw [hParams, hBody, hPub]
  simp only [List.map_cons, List.map_nil, List.reverse_cons, List.reverse_nil,
    List.nil_append]
  have hUsesPre : Lower.bindingsUseCheckPreimage
      (StatefulBridge.gatedStatefulPrologueBody pre) = true := by
    simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
      Lower.bindingsUseCheckPreimage]
  have hUsesCode : Lower.bindingsUseCodePart
      (StatefulBridge.gatedStatefulPrologueBody pre) = false := by
    simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
      Lower.bindingsUseCodePart]
  -- Issue #100: the `_codePart` gate is now `bindingsUseCodePart ||
  -- bindingsReadVarLenState`. The prologue body is preimage/codesep
  -- plumbing with no `load_prop` at all, so the new disjunct is `false`
  -- for ANY property set and the initial stack map is unchanged.
  have hReadsVarLen : Lower.bindingsReadVarLenState progMethods
      (Lower.varLenPropNames props) progMethods.length
      (StatefulBridge.gatedStatefulPrologueBody pre) = false := by
    simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
      Lower.bindingsReadVarLenState]
  have hConstInts : Lower.collectConstInts
      (StatefulBridge.gatedStatefulPrologueBody pre) = [] := by
    simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
      Lower.collectConstInts]
  have hEndsAssert : Lower.bodyEndsInAssert
      (StatefulBridge.gatedStatefulPrologueBody pre) = true := by
    simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
      Lower.bodyEndsInAssert]
  have hNoDeser : Lower.bindingsUseDeserializeState
      (StatefulBridge.gatedStatefulPrologueBody pre) = false := by
    simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
      Lower.bindingsUseDeserializeState]
  -- BUG-100: initial stack map is just `[pre]` (`usesPreimage=true` but
  -- `usesCode=false`, so the inner `if` gives `userMap`; no `_opPushTxSig`).
  rw [hUsesPre, hUsesCode, hReadsVarLen,
    computeLastUses_statefulPrologue pre hne1, hConstInts]
  simp only [Bool.or_self, if_true, if_false, List.cons_append, List.nil_append]
  rw [show ((StatefulBridge.gatedStatefulPrologueBody pre).map (·.name))
        = ["_cp0", "_v"] by
      simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
        ANFBinding.name]]
  simp only [Bool.false_eq_true, if_false, if_true]
  -- NEW-004: the stateful prologue is preimage/codesep plumbing with no
  -- byte-array producer, so the method-wide raw-slot set is empty.
  rw [show Lower.collectRawSlots (StatefulBridge.gatedStatefulPrologueBody pre) = [] from by
        simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
          Lower.collectRawSlots, Lower.collectRawSlotsGo, Lower.rawResultValue]]
  -- …and no `array_literal` binding either.
  rw [show Lower.arrayElemsOf (StatefulBridge.gatedStatefulPrologueBody pre) = [] from by
        simp [StatefulBridge.gatedStatefulPrologueBody, AgreesD2.statefulPrologueBody,
          Lower.arrayElemsOf]]
  simp only [lowerBindingsP_statefulPrologue progMethods props
    Lower.defaultInlineBudget ["_cp0", "_v"] pre hne1]
  simp [hEndsAssert, hNoDeser, statefulPrologueOps]

/-! ## Part 2 — the runtime walk (Stack acceptance = the preimage verdict) -/

/-- **The Stack half of the prologue's ACCEPTANCE bit (BUG-100).**

Running the parsed deployed prologue (`statefulPrologueParsedOps`) on the
method-entry stack (preimage on top) is *accepted* iff the preimage binds to
the spending transaction — i.e. iff `Crypto.checkPreimage preV`. On success
the blob leaves the (nonempty) preimage bytes on top (truthy under `asBool?`);
on failure the on-chain `OP_CHECKSIGVERIFY` inside the blob aborts. Rides on
`runOps_checkPreimageBindingRaw_eq` (the opaque crypto-boundary shim). -/
theorem runOps_statefulPrologueOps_scriptAccepts
    (stkSt : StackState) (preV : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes preV :: rest)
    (hPre : 0 < preV.size) :
    scriptAccepts (runOps statefulPrologueParsedOps stkSt)
      = RunarVerification.ANF.Eval.Crypto.checkPreimage preV := by
  rw [runOps_checkPreimageBindingRaw_eq preV rest stkSt hStk]
  rcases Bool.eq_false_or_eq_true
      (RunarVerification.ANF.Eval.Crypto.checkPreimage preV) with h | h <;>
    simp only [h] <;>
    simp [scriptAccepts, topTruthy, asBool?, hPre]

/-! ## Part 4 — the decidable fragment classifier -/

/-- Decides the canonical stateful consume fragment: one param `pre`, body
EXACTLY the gated stateful prologue on `pre`, with the two name-collision
exclusions. -/
def statefulConsumeShapeBool (m : ANFMethod) : Bool :=
  match m.params, m.body with
  | [p], [⟨bn1, .checkPreimage pre, none⟩, ⟨bn2, .assert ref, none⟩] =>
      (bn1 == "_cp0") && (bn2 == "_v") && (ref == "_cp0") &&
      (p.name == pre) && !(pre == "_cp0") && !(pre == "_opPushTxSig")
  | _, _ => false

/-! ## Part 5 — MANDATORY smokes (anti-vacuity) -/

/-- The canonical stateful method: `verify(pre) { _cp0 := check_preimage pre;
assert _cp0 }`. -/
def smokeMethod : ANFMethod :=
  { name := "verify"
    params := [ANFParam.mk "pre" .byteString]
    body := StatefulBridge.gatedStatefulPrologueBody "pre"
    isPublic := true }

/-- SMOKE — the classifier fires on the canonical method. -/
theorem smoke_classifier_fires : statefulConsumeShapeBool smokeMethod = true := by
  decide +kernel

/-- SMOKE — the method-level lowering reduction fires concretely. -/
theorem smoke_lowerMethod_ops :
    (Lower.lowerMethod [] [] smokeMethod).ops = statefulPrologueOps :=
  lowerMethod_ops_statefulPrologue [] [] smokeMethod "pre" .byteString
    rfl rfl rfl (by decide)


/-! # Part 6 — the WIDENED fragment: prologue + state-output epilogue

**2026-06-11 stateful widening.**  The discharged stateful fragment grows
from the bare gated prologue to the REAL stateful-method shape: entry
prologue **plus** the canonical one-mutable-prop state-output epilogue

    `_cp0 := check_preimage pre ;  _v := assert _cp0 ;
     _so0 := add_output sats [stateVal] ""`

— the honest composition of the two proven substrates
(`StatefulBridge.gatedStatefulPrologueBody` and
`AgreesD2.statefulEpilogueBody`).  The empty preimage ref on the
`add_output` matches the REAL compiler's auto-injection
(`04-anf-lower.ts:1311` emits `{ kind: 'add_output', …, preimage: '' }`);
the full auto-injection additionally deserializes state and asserts a
`hashOutputs` commitment, which remains future widening work.

## The `_codePart` finding

The epilogue's `add_output` trips `Lower.bindingsUseCodePart`, so
`lowerMethod` prepends BOTH implicit params: the initial stack map becomes
`[pre, stateVal, sats, "_opPushTxSig", "_codePart"]` (vs the prologue-only
fragment's `… ++ ["_opPushTxSig"]`).  The prologue's `_opPushTxSig`
consume therefore lowers to `.roll 3` instead of `.swap`, and the
mid-body `assert`'s `OP_VERIFY` is NOT elided (the body no longer ends in
assert — the trailing value is the output bytes, accepted under the
consensus truthy-top rule).

## The constant lowering and its parse image

The whole method lowers to the CONSTANT 68-op `statefulFullOps`
(prologue + `OP_VERIFY` + `lowerAddOutputOpsLive`'s serialization
including the flat-`OP_IF` varint encoder).  The DEPLOYED bytes parse
back to the structurally distinct `statefulFullParsedOps`: flat
`OP_IF`/`OP_ELSE`/`OP_ENDIF` reconstruct as nested `.ifOp`, `pickStruct`
comes back as `.pick`, and int pushes above `OP_16` come back as their
minimal-LE BYTE pushes — which is why the runtime walk needed the
consensus CScriptNum coercion (`Eval.asNum?`) on `OP_LESSTHAN`.

No `sorry`/`admit`. BUG-100 adds two opaque OP_PUSH_TX codegen→runtime
shims (`runOps_checkPreimageBindingRaw_eq`,
`runOps_statefulFullParsedOps_scriptAccepts`) that RETIRE the pre-BUG-100
`StatefulBridge.exists_checkSig_witness_under_validTxContext` witness axiom
(net +1: 70 → 71; see TRUST_MANIFEST.md). -/

open RunarVerification.ANF.Eval

/-- **The composed full-consume body**: gated prologue + one-state-value
epilogue (empty preimage ref on the `add_output`, as the real compiler
emits). -/
def statefulFullBody (pre sats stateVal : String) : List ANFBinding :=
  StatefulBridge.gatedStatefulPrologueBody pre
    ++ AgreesD2.statefulEpilogueBody sats stateVal ""

/-- The constant lowered epilogue ops (`lowerAddOutputOpsLive` on the
post-prologue map `[stateVal, sats, "_codePart"]`): copy `_codePart`,
append `OP_RETURN`, serialize the one bigint state value (8-byte LE),
varint-prefix the script, prepend the 8-byte LE amount. -/
def statefulFullEpilogueOps : List StackOp :=
  [.pickStruct 2, .push (.bytes (ByteArray.mk #[0x6a])), .opcode "OP_CAT",
   .swap, .push (.bigint 8), .opcode "OP_NUM2BIN", .opcode "OP_CAT",
   .opcode "OP_SIZE"]
  ++ Lower.varintEncodingOps
  ++ [.swap, .opcode "OP_CAT", .swap, .push (.bigint 8), .opcode "OP_NUM2BIN",
      .swap, .opcode "OP_CAT"]

/-- The composed method's CONSTANT lowered op list (BUG-100): the gated
prologue (`OP_CODESEPARATOR` + the 428-byte binding blob), the SURVIVING
mid-body `OP_VERIFY`, then the state-output epilogue. No `_opPushTxSig`
witness / `G` push / `OP_CHECKSIGVERIFY` — the binding is inside the blob. -/
def statefulFullOps : List StackOp :=
  [.opcode "OP_CODESEPARATOR", .rawBytes Lower.checkPreimageBindingBytes,
   .opcode "OP_VERIFY"]
  ++ statefulFullEpilogueOps

open RunarVerification.Script RunarVerification.Script.Parse in
/-- The composed method's parse image — what the DEPLOYED bytes run. Defined
as the parse result so `parseScript_emitOpsFast_statefulFull` holds by
construction (parse-success is a decidable Bool). -/
noncomputable def statefulFullParsedOps : List StackOp :=
  (parseScript (Emit.emitOpsFast statefulFullOps)).toOption.getD []

/-! ## Part 6.1 — the lowering reduction (staged) -/

theorem computeLastUses_statefulFull (pre sats stateVal : String)
    (hPC : pre ≠ "_cp0") (hPE : pre ≠ "")
    (hSE : sats ≠ "") (hVE : stateVal ≠ "")
    (hSC : sats ≠ "_cp0") (hVC : stateVal ≠ "_cp0")
    (hSP : sats ≠ pre) (hVP : stateVal ≠ pre) (hSV : sats ≠ stateVal) :
    Lower.computeLastUses (statefulFullBody pre sats stateVal)
      = [("", 2), (stateVal, 2), (sats, 2), ("_cp0", 1), (pre, 0)] := by
  simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
    AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
    Lower.computeLastUses, Lower.computeLastUses.go, Lower.collectRefs,
    Lower.lastUsesUpdate, hPC, hPE, hSE, hVE, hSC, hVC, hSP, hVP, hSV,
    Ne.symm hPC, Ne.symm hPE, Ne.symm hSE, Ne.symm hVE, Ne.symm hSC,
    Ne.symm hVC, Ne.symm hSP, Ne.symm hVP, Ne.symm hSV]

/-- The `check_preimage` binding on the FULL initial map (BUG-100): preimage
consumed in place (d0 last-use), then the 428-byte binding blob. No
`_opPushTxSig` slot exists — only `_codePart` sits below the user params. -/
theorem lowerValueP_checkPreimage_statefulFull
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre sats stateVal : String)
    (hPE : pre ≠ "") (hPS : pre ≠ sats) (hPV : pre ≠ stateVal) (hPC : pre ≠ "_cp0") :
    Lower.lowerValueP progMethods props budget 0
        [("", 2), (stateVal, 2), (sats, 2), ("_cp0", 1), (pre, 0)]
        [] localBindings [] [pre, stateVal, sats, "_codePart"]
        "_cp0" (.checkPreimage pre)
      = ([.opcode "OP_CODESEPARATOR", .rawBytes Lower.checkPreimageBindingBytes],
         (["_cp0", stateVal, sats, "_codePart"] : Stack.Lower.StackMap),
         localBindings) := by
  have e1 : ("" == pre) = false := beq_eq_false_iff_ne.mpr (Ne.symm hPE)
  have e2 : (stateVal == pre) = false := beq_eq_false_iff_ne.mpr (Ne.symm hPV)
  have e3 : (sats == pre) = false := beq_eq_false_iff_ne.mpr (Ne.symm hPS)
  have e4 : ("_cp0" == pre) = false := beq_eq_false_iff_ne.mpr (Ne.symm hPC)
  unfold Lower.lowerValueP
  simp [Lower.lowerCheckPreimageOpsLive, Lower.loadRefLive, Lower.bringToTop,
    Lower.StackMap.depth?, Lower.isLastUse,
    Lower.lastUsesLookup, Lower.listContains, List.find?, List.findIdx?,
    List.findIdx?.go, e1, e2, e3, e4]

/-- The mid-body `assert _cp0` lowers to a SURVIVING `OP_VERIFY` (no
terminal elision — the body continues into the epilogue). -/
theorem lowerValueP_assert_statefulFull
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre sats stateVal : String)
    (hPC : pre ≠ "_cp0") (hSC : sats ≠ "_cp0") (hVC : stateVal ≠ "_cp0") :
    Lower.lowerValueP progMethods props budget 1
        [("", 2), (stateVal, 2), (sats, 2), ("_cp0", 1), (pre, 0)]
        [] localBindings [] ["_cp0", stateVal, sats, "_codePart"]
        "_v" (.assert "_cp0")
      = ([.opcode "OP_VERIFY"], ([stateVal, sats, "_codePart"] : Stack.Lower.StackMap), localBindings) := by
  unfold Lower.lowerValueP
  simp [Lower.loadRefLive, Lower.bringToTop, Lower.StackMap.depth?,
    Lower.StackMap.popN, Lower.isLastUse, Lower.lastUsesLookup,
    Lower.listContains, List.findIdx?, List.findIdx?.go,
    hPC, hSC, hVC, Ne.symm hPC, Ne.symm hSC, Ne.symm hVC]

/-- The `add_output` epilogue lowers to the constant
`statefulFullEpilogueOps` (one mutable bigint prop ⇒ one 8-byte
`OP_NUM2BIN` serialization step). -/
theorem lowerValueP_addOutput_statefulFull
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre sats stateVal pn : String)
    (hProps : props.filter (fun pp => !pp.readonly)
        = [{ name := pn, type := .bigint, readonly := false }])
    (hSE : sats ≠ "") (hVE : stateVal ≠ "") (hSV : sats ≠ stateVal)
    (hVCp : stateVal ≠ "_codePart") (hSCp : sats ≠ "_codePart")
    (hVA : stateVal ≠ "_acc") (hSA : sats ≠ "_acc") :
    Lower.lowerValueP progMethods props budget 2
        [("", 2), (stateVal, 2), (sats, 2), ("_cp0", 1), (pre, 0)]
        [] localBindings [] [stateVal, sats, "_codePart"]
        "_so0" (.addOutput sats [stateVal] "")
      = (statefulFullEpilogueOps, (["_so0", "_codePart"] : Stack.Lower.StackMap), localBindings) := by
  unfold Lower.lowerValueP
  simp [Lower.lowerAddOutputOpsLive, Lower.addOutputStateValuesLive,
    Lower.loadRefOperand, Lower.operandConsume, Lower.bringToTop,
    Lower.StackMap.depth?, Lower.StackMap.popN, Lower.StackMap.push,
    Lower.StackMap.removeAtDepth, Lower.isLastUse, Lower.lastUsesLookup,
    Lower.listContains, List.findIdx?, List.findIdx?.go,
    hProps, Lower.propTypeIsNumeric, Lower.propTypeFixedSize,
    statefulFullEpilogueOps, Lower.varintEncodingOps,
    hSE, hVE, hSV, hVCp, hSCp, hVA, hSA,
    Ne.symm hSE, Ne.symm hVE, Ne.symm hSV, Ne.symm hVCp, Ne.symm hSCp,
    Ne.symm hVA, Ne.symm hSA]

theorem lowerBindingsP_statefulFull
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (pre sats stateVal pn : String)
    (hProps : props.filter (fun pp => !pp.readonly)
        = [{ name := pn, type := .bigint, readonly := false }])
    (hPE : pre ≠ "") (hPS : pre ≠ sats) (hPV : pre ≠ stateVal) (hPC : pre ≠ "_cp0")
    (hSE : sats ≠ "") (hVE : stateVal ≠ "") (hSV : sats ≠ stateVal)
    (hSC : sats ≠ "_cp0") (hVC : stateVal ≠ "_cp0")
    (hVCp : stateVal ≠ "_codePart") (hSCp : sats ≠ "_codePart")
    (hVA : stateVal ≠ "_acc") (hSA : sats ≠ "_acc") :
    Lower.lowerBindingsP progMethods props budget 0
        [("", 2), (stateVal, 2), (sats, 2), ("_cp0", 1), (pre, 0)]
        [] localBindings [] [pre, stateVal, sats, "_codePart"]
        (statefulFullBody pre sats stateVal)
      = (statefulFullOps, (["_so0", "_codePart"] : Stack.Lower.StackMap)) := by
  show Lower.lowerBindingsP progMethods props budget 0
        [("", 2), (stateVal, 2), (sats, 2), ("_cp0", 1), (pre, 0)]
        [] localBindings [] [pre, stateVal, sats, "_codePart"]
        [⟨"_cp0", .checkPreimage pre, none⟩, ⟨"_v", .assert "_cp0", none⟩,
         ⟨"_so0", .addOutput sats [stateVal] "", none⟩]
      = (statefulFullOps, (["_so0", "_codePart"] : Stack.Lower.StackMap))
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_checkPreimage_statefulFull progMethods props budget
    localBindings pre sats stateVal hPE hPS hPV hPC]
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_assert_statefulFull progMethods props budget
    localBindings pre sats stateVal hPC hSC hVC]
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_addOutput_statefulFull progMethods props budget
    localBindings pre sats stateVal pn hProps hSE hVE hSV hVCp hSCp hVA hSA]
  rw [Lower.lowerBindingsP.eq_def]
  simp [statefulFullOps, statefulFullEpilogueOps]

/-- **The method-level lowering reduction (widened fragment).**  A public
3-param method whose body is the composed prologue+epilogue lowers to the
CONSTANT `statefulFullOps`: BOTH implicit params are appended to the
initial stack map (`bindingsUseCodePart = true` — the `_codePart`
finding), no terminal elision fires (`bodyEndsInAssert = false`), and no
NIP cleanup runs. -/
theorem lowerMethod_ops_statefulFull
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (anfM : ANFMethod) (pre sats stateVal pn : String) (tyS tyV tyP : ANFType)
    (hParams : anfM.params
        = [ANFParam.mk sats tyS, ANFParam.mk stateVal tyV, ANFParam.mk pre tyP])
    (hBody : anfM.body = statefulFullBody pre sats stateVal)
    (hPub : anfM.isPublic = true)
    (hProps : props.filter (fun pp => !pp.readonly)
        = [{ name := pn, type := .bigint, readonly := false }])
    (hPE : pre ≠ "") (hPS : pre ≠ sats) (hPV : pre ≠ stateVal)
    (hPC : pre ≠ "_cp0")
    (hSE : sats ≠ "") (hVE : stateVal ≠ "") (hSV : sats ≠ stateVal)
    (hSC : sats ≠ "_cp0") (hVC : stateVal ≠ "_cp0")
    (hVCp : stateVal ≠ "_codePart") (hSCp : sats ≠ "_codePart")
    (hVA : stateVal ≠ "_acc") (hSA : sats ≠ "_acc") :
    (Lower.lowerMethod progMethods props anfM).ops = statefulFullOps := by
  unfold Lower.lowerMethod
  rw [hParams, hBody, hPub]
  simp only [List.map_cons, List.map_nil, List.reverse_cons, List.reverse_nil,
    List.nil_append, List.cons_append]
  have hUsesPre : Lower.bindingsUseCheckPreimage
      (statefulFullBody pre sats stateVal) = true := by
    simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
      AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
      Lower.bindingsUseCheckPreimage]
  have hUsesCode : Lower.bindingsUseCodePart
      (statefulFullBody pre sats stateVal) = true := by
    simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
      AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
      Lower.bindingsUseCodePart]
  have hConstInts : Lower.collectConstInts
      (statefulFullBody pre sats stateVal) = [] := by
    simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
      AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
      Lower.collectConstInts]
  have hEndsAssert : Lower.bodyEndsInAssert
      (statefulFullBody pre sats stateVal) = false := by
    simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
      AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
      Lower.bodyEndsInAssert]
  -- BUG-100: initial stack map is `[pre, stateVal, sats, _codePart]`
  -- (`usesPreimage=true` and `usesCode=true` → `userMap ++ ["_codePart"]`;
  -- no `_opPushTxSig`).
  rw [hUsesPre, hUsesCode,
    computeLastUses_statefulFull pre sats stateVal hPC hPE hSE hVE hSC hVC
      (Ne.symm hPS) (Ne.symm hPV) hSV, hConstInts]
  -- Issue #100: `usesCode` is now `bindingsUseCodePart || bindingsReadVarLenState`
  -- and this body's `add_output` already makes the first disjunct `true`.
  simp only [Bool.true_or, if_true, List.cons_append, List.nil_append]
  rw [show ((statefulFullBody pre sats stateVal).map (·.name))
        = ["_cp0", "_v", "_so0"] by
      simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
        AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
        ANFBinding.name]]
  -- NEW-004: see the prologue peer — no byte-array producer in the
  -- stateful full body either.
  rw [show Lower.collectRawSlots (statefulFullBody pre sats stateVal) = [] from by
        simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
          AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
          Lower.collectRawSlots, Lower.collectRawSlotsGo, Lower.rawResultValue]]
  -- …and no `array_literal` binding either.
  rw [show Lower.arrayElemsOf (statefulFullBody pre sats stateVal) = [] from by
        simp [statefulFullBody, StatefulBridge.gatedStatefulPrologueBody,
          AgreesD2.statefulPrologueBody, AgreesD2.statefulEpilogueBody,
          Lower.arrayElemsOf]]
  simp only [lowerBindingsP_statefulFull progMethods props
    Lower.defaultInlineBudget ["_cp0", "_v", "_so0"] pre sats stateVal pn hProps
    hPE hPS hPV hPC hSE hVE hSV hSC hVC hVCp hSCp hVA hSA]
  simp [hEndsAssert, statefulFullOps, statefulFullEpilogueOps,
    Lower.varintEncodingOps]

/-! ## Part 6.2 — the ANF composed reduction -/

theorem resolveRef_addBinding_ne (s : State) (n r : String) (v : Value)
    (h : r ≠ n) :
    (s.addBinding n v).resolveRef r = s.resolveRef r := by
  simp [State.addBinding, State.resolveRef, State.lookupBinding,
    State.lookupParam, State.lookupProp, List.find?, h, Ne.symm h]

/-- **The composed ANF success bit** = the preimage verdict: the prologue
gates (the `assert _cp0` aborts on a bad preimage), and the epilogue's
`add_output` never aborts (its value is the opaque output handle; the
output record is appended per `AgreesD2.evalValueP_statefulEpilogue_value`). -/
theorem evalBindingsP_statefulFull_isSome_eq
    (methods : List ANFMethod) (s : State) (pre sats stateVal : String)
    (b : ByteArray) (satsV : Int) (svV : Value)
    (hPre : s.resolveRef pre = some (.vBytes b))
    (hSats : s.resolveRef sats = some (.vBigint satsV))
    (hSv : s.resolveRef stateVal = some svV)
    (hS1 : sats ≠ "_cp0") (hS2 : sats ≠ "_v")
    (hV1 : stateVal ≠ "_cp0") (hV2 : stateVal ≠ "_v") :
    (evalBindingsP methods s (statefulFullBody pre sats stateVal)).toOption.isSome
      = Crypto.checkPreimage b := by
  unfold statefulFullBody StatefulBridge.gatedStatefulPrologueBody
    AgreesD2.statefulPrologueBody AgreesD2.statefulEpilogueBody
  show (evalBindingsP methods s
      [⟨"_cp0", .checkPreimage pre, none⟩, ⟨"_v", .assert "_cp0", none⟩,
       ⟨"_so0", .addOutput sats [stateVal] "", none⟩]).toOption.isSome
    = Crypto.checkPreimage b
  have hLookup :
      (s.addBinding "_cp0" (.vBool (Crypto.checkPreimage b))).resolveRef "_cp0"
        = some (.vBool (Crypto.checkPreimage b)) := by
    simp [State.resolveRef, State.lookupBinding, State.addBinding]
  rw [evalBindingsP.eq_def]
  simp only [evalValueP, lookupRef, hPre, Value.asBytes?, bind, Except.bind]
  rw [evalBindingsP.eq_def]
  simp only [evalValueP, lookupRef, hLookup, bind, Except.bind]
  rcases Bool.eq_false_or_eq_true (Crypto.checkPreimage b) with h | h
  case _ =>
    -- verdict TRUE: assert passes, epilogue appends the output.
    simp only [h]
    have hSats2 : ((s.addBinding "_cp0" (Value.vBool true)).addBinding "_v"
        (Value.vBool true)).resolveRef sats = some (.vBigint satsV) := by
      rw [resolveRef_addBinding_ne _ _ _ _ hS2,
        resolveRef_addBinding_ne _ _ _ _ hS1]
      exact hSats
    have hSv2 : ((s.addBinding "_cp0" (Value.vBool true)).addBinding "_v"
        (Value.vBool true)).resolveRef stateVal = some svV := by
      rw [resolveRef_addBinding_ne _ _ _ _ hV2,
        resolveRef_addBinding_ne _ _ _ _ hV1]
      exact hSv
    show (evalBindingsP methods
        ((s.addBinding "_cp0" (Value.vBool true)).addBinding "_v" (Value.vBool true))
        [ANFBinding.mk "_so0" (ANFValue.addOutput sats [stateVal] "") none]).toOption.isSome
      = true
    rw [evalBindingsP.eq_def]
    simp only [AgreesD2.evalValueP_statefulEpilogue_value methods
      ((s.addBinding "_cp0" (Value.vBool true)).addBinding "_v" (Value.vBool true))
      sats stateVal "" satsV svV hSats2 hSv2, bind, Except.bind]
    simp [evalBindingsP, Except.toOption, Option.isSome]
  case _ =>
    -- verdict FALSE: the assert aborts.
    simp only [h]
    simp [Except.toOption, Option.isSome]

/-! ## Part 6.3 — the runtime acceptance (opaque crypto-boundary shim) -/

/-- Abbreviation for the accumulated state-script bytes:
`codePart ++ OP_RETURN ++ stateVal(8-byte LE)`. -/
def epiAcc (cpV sv8 : ByteArray) : ByteArray :=
  cpV ++ ByteArray.mk #[0x6a] ++ sv8

/-- **The full-fragment acceptance shim (BUG-100).**

Running the parsed deployed full-method script (`statefulFullParsedOps` = the
gated prologue blob + `OP_VERIFY` + the state-output epilogue) on the
method-entry stack `[pre, stateVal, sats, _codePart, …]` is *accepted* iff the
preimage binds to the spending transaction — i.e. iff
`Crypto.checkPreimage preV`. On success the blob leaves the (nonempty) preimage
on top, `OP_VERIFY` consumes it, and the epilogue completes leaving a truthy
output-bytes top; on failure the on-chain `OP_CHECKSIGVERIFY` inside the blob
aborts. The widened peer of `runOps_checkPreimageBindingRaw_eq`; the runtime
confidence for the opaque blob is carried by the same TS reference construction
(`oppushtx-codegen.ts`). No `sorry`. -/
axiom runOps_statefulFullParsedOps_scriptAccepts (stkSt : StackState)
    (preV cpV : ByteArray) (svV satsV : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes preV :: .vBigint svV :: .vBigint satsV
        :: .vBytes cpV :: rest)
    (hPre : 0 < preV.size) :
    scriptAccepts (runOps statefulFullParsedOps stkSt)
      = RunarVerification.ANF.Eval.Crypto.checkPreimage preV

/-! ## Part 6.4 — the parse round-trip (M4) -/

open RunarVerification.Script RunarVerification.Script.Parse in
/-- The deployed full-method bytes parse successfully (decidable Bool). -/
theorem statefulFull_parse_isSome :
    (parseScript (Emit.emitOpsFast statefulFullOps)).toOption.isSome = true := by
  native_decide

open RunarVerification.Script RunarVerification.Script.Parse in
/-- **M4 round-trip (BUG-100 form).** The deployed full-method bytes parse to
`statefulFullParsedOps`. Holds by construction from parse-success. -/
theorem parseScript_emitOpsFast_statefulFull :
    parseScript (Emit.emitOpsFast statefulFullOps) = .ok statefulFullParsedOps := by
  unfold statefulFullParsedOps
  exact except_ok_of_toOption_isSome _ statefulFull_parse_isSome

/-! ## Part 6.5 — the decidable fragment classifier -/

/-- Reserved names the widened fragment's user-visible identifiers must
avoid: the auto-injected binding names, the implicit stack params, and
the anonymous stack-map placeholders of the addOutput lowering. -/
def statefulFullReservedNames : List String :=
  ["", "_cp0", "_v", "_so0", "_opPushTxSig", "_codePart", "_acc", "_varint", "_conv"]

/-- All name-collision exclusions of the widened fragment, decidably. -/
def statefulFullNamesOk (pre sats stateVal : String) : Bool :=
  !(statefulFullReservedNames.contains pre) &&
  !(statefulFullReservedNames.contains sats) &&
  !(statefulFullReservedNames.contains stateVal) &&
  pre != sats && pre != stateVal && sats != stateVal

/-- One mutable property, `bigint`-typed, no initializer — the property
table shape whose `add_output` serialization the widened fragment pins. -/
def mutablePropsBigintOne (props : List ANFProperty) : Bool :=
  match props.filter (fun pp => !pp.readonly) with
  | [pp] => (match pp.type with | .bigint => true | _ => false)
              && pp.initialValue.isNone
  | _ => false

/-- Decides the WIDENED stateful consume fragment: three params
`(sats, stateVal, pre)`, body EXACTLY the composed prologue+epilogue,
one mutable bigint property, all name-collision exclusions. -/
def statefulFullConsumeShapeBool (props : List ANFProperty) (m : ANFMethod) : Bool :=
  match m.params, m.body with
  | [pS, pV, pP],
    [⟨bn1, .checkPreimage pre, none⟩, ⟨bn2, .assert ref, none⟩,
     ⟨bn3, .addOutput sats [stateVal] epre, none⟩] =>
      (bn1 == "_cp0") && (bn2 == "_v") && (ref == "_cp0") && (bn3 == "_so0") &&
      (epre == "") &&
      (pS.name == sats) && (pV.name == stateVal) && (pP.name == pre) &&
      statefulFullNamesOk pre sats stateVal &&
      mutablePropsBigintOne props
  | _, _ => false

/-- **Extraction**: a classifier-true method has EXACTLY the composed
body, the matching 3-param list, the one-mutable-bigint-prop filter
shape (its `readonly` pinned `false` by the filter predicate), and the
name exclusions. -/
theorem statefulFullConsumeShapeBool_extract (props : List ANFProperty)
    (m : ANFMethod) (h : statefulFullConsumeShapeBool props m = true) :
    ∃ (pre sats stateVal pn : String) (tyS tyV tyP : ANFType),
      m.params = [ANFParam.mk sats tyS, ANFParam.mk stateVal tyV, ANFParam.mk pre tyP] ∧
      m.body = statefulFullBody pre sats stateVal ∧
      props.filter (fun pp => !pp.readonly)
        = [{ name := pn, type := .bigint, readonly := false }] ∧
      statefulFullNamesOk pre sats stateVal = true := by
  unfold statefulFullConsumeShapeBool at h
  split at h
  case _ =>
    rename_i pS pV pP bn1 pre bn2 ref bn3 sats stateVal epre hParamsEq hBodyEq
    -- peel the `&&`-conjuncts right-to-left
    rw [Bool.and_eq_true] at h; obtain ⟨h, hPropsB⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hNames⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hPP⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hPV⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hPS⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hEpre⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hBn3⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨h, hRef⟩ := h
    rw [Bool.and_eq_true] at h; obtain ⟨hBn1, hBn2⟩ := h
    have hBn1' : bn1 = "_cp0" := beq_iff_eq.mp hBn1
    have hBn2' : bn2 = "_v" := beq_iff_eq.mp hBn2
    have hRef' : ref = "_cp0" := beq_iff_eq.mp hRef
    have hBn3' : bn3 = "_so0" := beq_iff_eq.mp hBn3
    have hEpre' : epre = "" := beq_iff_eq.mp hEpre
    have hPS' : pS.name = sats := beq_iff_eq.mp hPS
    have hPV' : pV.name = stateVal := beq_iff_eq.mp hPV
    have hPP' : pP.name = pre := beq_iff_eq.mp hPP
    subst hBn1'; subst hBn2'; subst hRef'; subst hBn3'; subst hEpre'
    refine ⟨pre, sats, stateVal, ?_⟩
    -- analyze the one-mutable-bigint-prop check
    unfold mutablePropsBigintOne at hPropsB
    rcases hF : props.filter (fun pq => !pq.readonly) with _ | ⟨pp, rest⟩
    case _ =>
      rw [hF] at hPropsB
      exact absurd hPropsB (by decide)
    case _ =>
      rcases rest with _ | ⟨pp2, rest2⟩
      case _ =>
        rw [hF] at hPropsB
        simp only [Bool.and_eq_true] at hPropsB
        obtain ⟨hTy, hIv⟩ := hPropsB
        have hMem : pp ∈ props.filter (fun pq => !pq.readonly) := by
          rw [hF]; exact List.mem_singleton.mpr rfl
        have hRo : pp.readonly = false := by
          have := (List.mem_filter.mp hMem).2
          simpa using this
        have hTy' : pp.type = .bigint := by
          revert hTy; cases pp.type <;> simp
        have hIv' : pp.initialValue = none := by
          cases hI : pp.initialValue
          · rfl
          · rw [hI] at hIv; simp [Option.isNone] at hIv
        have hpp : pp = ⟨pp.name, .bigint, false, none⟩ := by
          cases pp; simp_all
        refine ⟨pp.name, pS.type, pV.type, pP.type, ?_, ?_, ?_, hNames⟩
        · rw [hParamsEq, ← hPS', ← hPV', ← hPP']
        · rw [hBodyEq]; rfl
        · rw [hF, hpp]
      case _ =>
        rw [hF] at hPropsB
        simp at hPropsB
  case _ => exact absurd h (by decide)

/-- Unpack the decidable name-exclusion bundle into the 16 disequalities
the lowering/ANF reductions consume. -/
theorem statefulFullNamesOk_unpack (pre sats stateVal : String)
    (h : statefulFullNamesOk pre sats stateVal = true) :
    pre ≠ "" ∧ pre ≠ "_cp0" ∧ pre ≠ "_v" ∧ pre ≠ "_so0" ∧
    pre ≠ "_opPushTxSig" ∧ pre ≠ "_codePart" ∧
    sats ≠ "" ∧ sats ≠ "_cp0" ∧ sats ≠ "_v" ∧ sats ≠ "_so0" ∧
    sats ≠ "_opPushTxSig" ∧ sats ≠ "_codePart" ∧ sats ≠ "_acc" ∧
    stateVal ≠ "" ∧ stateVal ≠ "_cp0" ∧ stateVal ≠ "_v" ∧ stateVal ≠ "_so0" ∧
    stateVal ≠ "_opPushTxSig" ∧ stateVal ≠ "_codePart" ∧ stateVal ≠ "_acc" ∧
    pre ≠ sats ∧ pre ≠ stateVal ∧ sats ≠ stateVal := by
  simp only [statefulFullNamesOk, statefulFullReservedNames, List.contains_cons,
    List.contains_nil, Bool.or_false, Bool.not_or, Bool.and_eq_true,
    Bool.not_eq_true', beq_eq_false_iff_ne, bne_iff_ne] at h
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> simp_all

/-! ## Part 6.6 — MANDATORY smokes (anti-vacuity) -/

/-- The canonical widened stateful method:
`verify(sats, stateVal, pre) { _cp0 := check_preimage pre; assert _cp0;
_so0 := add_output(sats, [stateVal], "") }`. -/
def smokeFullMethod : ANFMethod :=
  { name := "verify"
    params := [ANFParam.mk "sats" .bigint, ANFParam.mk "stateVal" .bigint,
               ANFParam.mk "pre" .byteString]
    body := statefulFullBody "pre" "sats" "stateVal"
    isPublic := true }

/-- The one-mutable-prop property table the widened fragment serializes. -/
def smokeFullProps : List ANFProperty :=
  [{ name := "count", type := .bigint, readonly := false }]

/-- SMOKE — the widened classifier fires on the canonical method. -/
theorem smoke_full_classifier_fires :
    statefulFullConsumeShapeBool smokeFullProps smokeFullMethod = true := by
  native_decide

/-- SMOKE — the widened classifier REJECTS the prologue-only method
(the two fragments are disjoint). -/
theorem smoke_full_classifier_rejects_prologueOnly :
    statefulFullConsumeShapeBool smokeFullProps smokeMethod = false := by
  native_decide

/-- SMOKE — the prologue-only classifier rejects the widened body. -/
theorem smoke_prologue_classifier_rejects_full :
    statefulConsumeShapeBool smokeFullMethod = false := by
  native_decide

/-- SMOKE — the method-level lowering reduction fires concretely. -/
theorem smoke_full_lowerMethod_ops :
    (Lower.lowerMethod [] smokeFullProps smokeFullMethod).ops = statefulFullOps :=
  lowerMethod_ops_statefulFull [] smokeFullProps smokeFullMethod
    "pre" "sats" "stateVal" "count" .bigint .bigint .byteString rfl rfl rfl rfl
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    (by decide)

end RunarVerification.Stack.AgreesStateful

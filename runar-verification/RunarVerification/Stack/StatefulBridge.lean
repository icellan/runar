import RunarVerification.Stack.AgreesD2
import RunarVerification.Stack.TxContext

/-!
# Stage D2.a — the `checkPreimage ⟷ checkSig` BIP-143 bridge (Task 8 keystone)

This file resolves the §11.6 **split-backend wall** for the auto-injected
stateful prologue, the open content the `AgreesD2.lean` substrate left as
"the documented remaining blocker".

## The wall (precise)

The two sides of the stateful prologue route through **different crypto
backends** and have **different abort semantics**:

* **ANF side** (`ANF/Eval.lean:2186`).  The auto-injected
  `_cp0 := check_preimage(pre)` binding resolves the preimage ref, requires
  it byte-coercible, and produces `.vBool (Crypto.checkPreimage bytes)` —
  threading state UNCHANGED.  It runs the PREIMAGE backend
  (`preimageBackend`, `ANF/Eval.lean:1213`) and **never aborts**: the value
  is a bool.  The script-level abort happens DOWNSTREAM, at the
  auto-injected `assert _cp0` (`ANF/Eval.lean:2175`): `evalValueP (.assert
  "_cp0")` returns `.error .assertFailed` exactly when `_cp0` is
  `.vBool false`.
* **Stack side** (`Stack/Lower.lean:949 lowerCheckPreimageOpsLive`).  The
  prologue lowers to `OP_CODESEPARATOR ; <load preimage> ; <load
  _opPushTxSig> ; push G ; OP_CHECKSIGVERIFY`.  The terminal
  `OP_CHECKSIGVERIFY` (`Stack/Eval.lean:632`) runs `Crypto.checkSig` (the
  AUTH backend, `ANF/Eval.lean:1189`) over the synthetic
  `_opPushTxSig`-derived signature against the generator `G`, and **aborts
  with `.assertFailed`** unless `authBackend.checkSig sig pk = true`.

So the prologue's success bit on the ANF side (folding in the downstream
`assert _cp0`) is `Crypto.checkPreimage bytes`, and on the Stack side it is
`authBackend.checkSig sig pk`.  These agree only under a BIP-143 / ECDSA
fact about the two external primitives — carried below as the
per-deployment `hSig` provenance hypothesis plus the witness-existence
axiom.

## What this file ships (BUG-100 update, 2026-07-06)

1. `stG` — the compiler's synthetic BIP-143 key (the secp256k1 generator
   `G` in compressed SEC form). Retained as a definitional constant; the
   BUG-100 blob pushes `G` internally.
2. `gatedStatefulPrologueBody` + `gatedStatefulPrologue_isSome_eq` — the ANF
   side of the gated prologue (`check_preimage pre ; assert _cp0`): its
   success bit is EXACTLY `Crypto.checkPreimage pre`. Unchanged by BUG-100
   (the ANF evaluator is codegen-independent).

**RETIRED (BUG-100).** The pre-BUG-100 witness-existence axiom
`exists_checkSig_witness_under_validTxContext` and the correspondence theorem
`statefulPrologue_successAgrees_under_validTxContext` (which bridged the ANF
`checkPreimage` verdict to a spender-supplied `_opPushTxSig` witness via
`OP_CHECKSIGVERIFY`) are GONE. The emitted `checkPreimage` no longer accepts a
spender witness: the compiler injects a fixed 428-byte OP_PUSH_TX blob that
DERIVES the ECDSA signature on-chain from `hash256(preimage)` and runs
`OP_CHECKSIGVERIFY` against `G`, so the preimage↔transaction binding is
**ENFORCED BY CODEGEN**. The Stack-side runtime characterisation now lives in
`AgreesStateful.runOps_checkPreimageBindingRaw_eq` /
`runOps_statefulFullParsedOps_scriptAccepts` (opaque codegen→runtime shims,
peers of `Blake3.runOps_b3HashOps_eq`), and the consume/full theorems in
`Pipeline.lean` need no witness hypothesis.

No `sorry`/`admit`. This file declares **zero** axioms (the witness axiom was
retired; the two replacement binding shims live in `AgreesStateful.lean`).
-/

namespace RunarVerification
namespace Stack
namespace StatefulBridge

open RunarVerification.ANF
open RunarVerification.ANF.Eval
open RunarVerification.Stack.Eval

/-! ## 1 — The synthetic key + the BIP-143 witness-existence axiom -/

/-- The compiler's synthetic BIP-143 key: the secp256k1 generator point `G`
in compressed SEC form (33 bytes).  Byte-identical to the local constant in
`Lower.lowerCheckPreimageOpsLive`; `AgreesStateful.stG` re-exports it. -/
def stG : ByteArray := ByteArray.mk #[
  0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
  0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
  0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
  0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98]

/-! ## 1b — BUG-100: the witness-existence axiom is RETIRED

The pre-BUG-100 axiom `exists_checkSig_witness_under_validTxContext` supplied a
spender signature whose AUTH-backend verdict against `G` matched the preimage
verdict. BUG-100 removed the spender witness entirely: the emitted script now
DERIVES the ECDSA signature on-chain from `hash256(preimage)` and runs
`OP_CHECKSIGVERIFY` against `G`, so the correspondence is ENFORCED BY CODEGEN.
The opaque codegen→runtime bridge for the deployed blob lives in
`AgreesStateful.runOps_checkPreimageBindingRaw_eq` (peer of
`Blake3.runOps_b3HashOps_eq`); this witness-existence axiom is no longer needed
and has been deleted (net axiom count is unchanged — a swap). -/

/-! ## 2 — ANF-side gated prologue reduction (the downstream `assert _cp0`)

The bare ANF prologue (`AgreesD2.evalBindingsP_statefulPrologue_reduces`)
never aborts.  The script-level abort is the downstream auto-injected
`assert _cp0`.  We pin the GATED prologue — the `check_preimage` binding
followed by `assert _cp0` — whose success bit IS the preimage verdict. -/

/-- **The gated ANF stateful prologue.**  The `AgreesD2` prologue body
(`_cp0 := check_preimage pre`) followed by the auto-injected `assert _cp0`
that gates the rest of the stateful method.  THIS body's success bit is
where the ANF side actually aborts on a bad preimage. -/
def gatedStatefulPrologueBody (pre : String) : List ANFBinding :=
  AgreesD2.statefulPrologueBody pre ++ [⟨"_v", .assert "_cp0", none⟩]

/-- **Gated ANF prologue reduction (genuine operational content).**

From the INPUT-side readiness fact that the preimage ref resolves to bytes
`b` (`resolveRef pre = some (.vBytes b)`), the gated prologue:

* SUCCEEDS (returns `.ok`) when `Crypto.checkPreimage b = true`, producing
  the entry state extended with `_cp0 ↦ vBool true` and `_v ↦ vBool true`;
* FAILS with `.assertFailed` when `Crypto.checkPreimage b = false`.

So its success bit is EXACTLY `Crypto.checkPreimage b` — the downstream
`assert _cp0` is precisely where the ANF model aborts on a bad preimage.
This is the ANF half of the prologue's `successAgrees` bit (the Stack half
being `OP_CHECKSIGVERIFY`). -/
theorem gatedStatefulPrologue_isSome_eq
    (methods : List ANFMethod) (s : State) (pre : String) (b : ByteArray)
    (hPre : s.resolveRef pre = some (.vBytes b)) :
    (evalBindingsP methods s (gatedStatefulPrologueBody pre)).toOption.isSome
      = Crypto.checkPreimage b := by
  -- The gated body is the concrete 2-binding list
  --   [ _cp0 := check_preimage pre ;  _v := assert _cp0 ].
  unfold gatedStatefulPrologueBody AgreesD2.statefulPrologueBody
  show (evalBindingsP methods s
        [⟨"_cp0", .checkPreimage pre, none⟩, ⟨"_v", .assert "_cp0", none⟩]).toOption.isSome
      = Crypto.checkPreimage b
  -- The post-state after the `check_preimage` cons-step: `_cp0` is the head
  -- binding, so `resolveRef "_cp0"` finds the bool verdict.
  have hLookup :
      (s.addBinding "_cp0" (.vBool (Crypto.checkPreimage b))).resolveRef "_cp0"
        = some (.vBool (Crypto.checkPreimage b)) := by
    simp [State.resolveRef, State.lookupBinding, State.addBinding]
  -- Step 1: `check_preimage` cons-step (`pre ↦ vBytes b` ⇒ `_cp0 ↦ vBool
  -- (checkPreimage b)`, state threaded). Step 2: `assert "_cp0"` cons-step,
  -- which inspects `_cp0` via `hLookup` and branches on the verdict.
  unfold evalBindingsP
  simp only [evalValueP, lookupRef, hPre, Value.asBytes?, bind, Except.bind,
    evalBindingsP, hLookup]
  -- Branch on the preimage verdict; both arms compute the isSome literal.
  -- `true`  ⇒ assert passes, the empty tail of `evalBindingsP` yields `.ok`;
  -- `false` ⇒ assert returns `.error .assertFailed`.
  rcases Bool.eq_false_or_eq_true (Crypto.checkPreimage b) with h | h <;>
    simp only [h] <;>
    simp [pure, Except.pure, Except.toOption, Option.isSome]

end StatefulBridge
end Stack
end RunarVerification

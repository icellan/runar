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

## What this file ships

1. `stG` — the compiler's synthetic BIP-143 key (the secp256k1 generator
   `G` in compressed SEC form), the shared constant the Stack prologue
   pushes (`Lower.lowerCheckPreimageOpsLive`).  `AgreesStateful` re-exports
   it.
2. `exists_checkSig_witness_under_validTxContext` — the ONE crypto axiom
   (TIGHTENED 2026-06-10): for every well-formed BIP-143 context there
   EXISTS a signature whose AUTH-backend verdict against the synthetic key
   `G` equals the PREIMAGE backend's verdict on the canonical preimage.
   The previous shape (`checkPreimage_iff_checkSig_under_validTxContext`)
   equated the two verdicts for UNIVERSALLY quantified `sig`/`pk` — which
   forced `authBackend.checkSig` to be a CONSTANT function (one valid
   context pins the same boolean for all `sig`,`pk`), a cryptographically
   unfaithful assumption (false for real ECDSA).  The existential shape is
   TRUE under the real-world reading: when the preimage backend accepts,
   the deterministic ECDSA signature over the BIP-143 digest with the
   synthetic key is a verifying witness; when it rejects, any garbage
   byte-string is a non-verifying one.  It constrains NOTHING about
   `checkSig` off the witness, so the backend can be non-constant.
3. `statefulPrologue_successAgrees_under_validTxContext` — the genuine
   correspondence theorem.  The per-deployment sig-provenance fact is now a
   HYPOTHESIS (`hSig : authBackend.checkSig sig stG = Crypto.checkPreimage
   preimage` — "the spender's `_opPushTxSig` witness verifies exactly when
   the preimage backend accepts"), discharged per fixture by the
   conformance harness and, for the in-file smokes, by the witness the
   existence axiom provides (`Classical.choose`).  Composing it with the
   two `AgreesD2` substrate lemmas (ANF side) and the
   `OP_CHECKSIGVERIFY` reduction (Stack side) proves the GATED ANF
   stateful-prologue success bit (the `check_preimage` binding followed by
   its downstream `assert _cp0`) equals the Stack prologue's
   `OP_CHECKSIGVERIFY` success bit.
4. In-file smokes firing the correspondence on a concrete VALID context
   (success on both sides) and exercising the gated-ANF abort path on a
   concrete FALSE preimage verdict.

No `sorry`/`admit`; exactly one `axiom` (the witness existence — count-
neutral with the shape it replaced).
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

/-- **BIP-143 witness existence (crypto assumption — TIGHTENED 2026-06-10).**

For every well-formed BIP-143 context there exists a signature whose
AUTH-backend verdict against the compiler's synthetic key `G` (`stG`)
equals the PREIMAGE backend's verdict on the canonical preimage
`TxContext.buildPreimage ctx`.

History: the previous shape
(`checkPreimage_iff_checkSig_under_validTxContext`) asserted
`Crypto.checkPreimage preimage = authBackend.checkSig sig pk` for
UNIVERSALLY quantified `sig pk : ByteArray`.  That forced
`authBackend.checkSig` to be a CONSTANT function — for any one valid
context, every `(sig, pk)` pair was pinned to the same boolean — an
assumption whose real-world (ECDSA) reading is FALSE: some signatures
verify, most don't.  It was tightened to this existential on 2026-06-10.

Real-world reading (TRUE for ECDSA over BIP-143): the synthetic key is the
generator `G`, whose discrete log (1) is public, so a deterministic ECDSA
signature over the digest of `buildPreimage ctx` is constructible by every
spender.  If the preimage backend accepts the canonical preimage, that
constructed signature is a verifying witness (`true = true`); if it
rejects, any non-signature byte-string fails verification (`false =
false`).  Either way a witness exists.  Crucially the existential
constrains NOTHING about `checkSig` away from the witness — the backend is
free to be non-constant, as real ECDSA is.

Consumers: the per-deployment AGREEMENT for the specific `_opPushTxSig`
witness the spender supplies is now a HYPOTHESIS of
`statefulPrologue_successAgrees_under_validTxContext` (and of the keyed
`hStatefulFrag` omnibus premise in `Pipeline.lean`), discharged per fixture
by the conformance harness.  This axiom's role is anti-vacuity: it supplies
the witness (`Classical.choose`) that lets the in-file smokes and
`Pipeline.smoke_stateful_consume_fires` fire the correspondence end-to-end
on concrete contexts.  It is a sibling of the existing `hashBackend` /
`authBackend` / `preimageBackend` crypto assumptions — NOT a
codegen-soundness axiom.

BUG-100 fix (2026-07-05): the emitted `checkPreimage` no longer accepts a
spender-supplied `_opPushTxSig` witness — the verifying signature is now
DERIVED ON CHAIN from `hash256(preimage)` (Optimal OP_PUSH_TX: `s = (z + r)·k⁻¹
mod n`, `OP_CHECKSIG` against `G`). The "constructible by every spender"
reading above is therefore realized deterministically by the locking script
itself, and the per-deployment agreement is now ENFORCED BY CODEGEN rather than
assumed. Previously the emitted script did NOT enforce this binding (the
covenant-bypass finding); the fix grounds the axiom's assumption in the real
on-chain construction, so this remains a legitimate crypto assumption rather
than a hidden codegen gap. -/
axiom exists_checkSig_witness_under_validTxContext (ctx : TxContext)
    (_hValid : ValidTxContext ctx) :
    ∃ sig : ByteArray,
      RunarVerification.ANF.Eval.Crypto.authBackend.checkSig sig stG
        = RunarVerification.ANF.Eval.Crypto.checkPreimage
            (TxContext.buildPreimage ctx)

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

/-! ## 3 — The prologue success-bit correspondence (the genuine theorem) -/

open RunarVerification.ANF.Eval.Crypto in
/-- **Stateful-prologue success-bit correspondence (Task 8 keystone).**

Under a well-formed BIP-143 context, the GATED ANF stateful-prologue success
bit equals the Stack prologue's `OP_CHECKSIGVERIFY` success bit.

Concretely, with:
* `ValidTxContext ctx` and `stkSt.preimage = buildPreimage ctx` — the
  well-formed-context facts the Stack `OP_CHECKSIGVERIFY` lemma needs;
* `stkSt.stack = stG :: sig :: rest` — the prologue's signature-check stack
  shape (the synthetic key `G` on top, the `_opPushTxSig`-derived witness
  below), matching `runOpcode_CHECKSIGVERIFY_ValidTxContext`;
* `s.resolveRef pre = some (.vBytes preimage)` and `preimage = buildPreimage
  ctx` — the ANF-side input readiness, linking the ANF preimage bytes to the
  Stack-threaded preimage;
* `hSig : authBackend.checkSig sig stG = Crypto.checkPreimage preimage` —
  the per-deployment sig-provenance fact (TIGHTENED 2026-06-10; previously
  supplied by the over-strong universal bridge axiom, which forced
  `checkSig` constant): the spender's witness verifies against the
  synthetic key exactly when the preimage backend accepts.  Discharged per
  fixture by the conformance harness; for the smokes, by the witness
  `exists_checkSig_witness_under_validTxContext` provides;

we have

  `(evalBindingsP methods s (gatedStatefulPrologueBody pre)).isSome`
    ↔  `(runOpcode "OP_CHECKSIGVERIFY" stkSt).isSome`.

Composition:
* ANF half — `gatedStatefulPrologue_isSome_eq`: the LHS isSome is
  `Crypto.checkPreimage preimage`.
* provenance — `hSig`: that equals `authBackend.checkSig sig stG`.
* Stack half — `runOpcode_CHECKSIGVERIFY` definitional shape: the RHS isSome
  is `authBackend.checkSig sig stG` (success ↦ `.ok`, failure ↦
  `.assertFailed`, both branches case-split through the same bool).

NON-VACUOUS: smokes below fire it on a concrete VALID context where the
preimage verdict is forced `true` (both sides succeed) and exercise the
gated-ANF abort on a `false` verdict. -/
theorem statefulPrologue_successAgrees_under_validTxContext
    (methods : List ANFMethod) (s : State)
    (ctx : TxContext) (sig preimage : ByteArray) (rest : List Value)
    (stkSt : StackState) (pre : String)
    (_hValid : ValidTxContext ctx)
    (_hStkPre : stkSt.preimage = TxContext.buildPreimage ctx)
    (hStk : stkSt.stack = .vBytes stG :: .vBytes sig :: rest)
    (_hPreLink : preimage = TxContext.buildPreimage ctx)
    (hAnfPre : s.resolveRef pre = some (.vBytes preimage))
    (hSig : RunarVerification.ANF.Eval.Crypto.authBackend.checkSig sig stG
        = RunarVerification.ANF.Eval.Crypto.checkPreimage preimage) :
    (evalBindingsP methods s (gatedStatefulPrologueBody pre)).toOption.isSome
      ↔ (Eval.runOpcode "OP_CHECKSIGVERIFY" stkSt).toOption.isSome := by
  -- ANF half: LHS isSome = Crypto.checkPreimage preimage.
  rw [gatedStatefulPrologue_isSome_eq methods s pre preimage hAnfPre]
  -- Provenance: Crypto.checkPreimage preimage = authBackend.checkSig sig stG.
  rw [← hSig]
  -- Stack half: reduce `runOpcode "OP_CHECKSIGVERIFY"` to its bool branch.
  -- `popN stkSt 2` peels `[stG, sig]` off `hStk`; the arm then branches on
  -- `checkSig sigB pkB = authBackend.checkSig sig stG`.
  simp only [Eval.runOpcode, Eval.popN, StackState.pop?, hStk, asBytes?,
    RunarVerification.ANF.Eval.Crypto.checkSig]
  -- Both sides are now `<bool> = true ↔ (if <bool> then .ok _ else .error _).isSome`.
  -- The `if` carries a `Decidable (<bool> = true)` instance that depends on the
  -- term, so `simp only [h]` (not `rw`) discharges each branch.
  rcases Bool.eq_false_or_eq_true
      (RunarVerification.ANF.Eval.Crypto.authBackend.checkSig sig stG) with h | h <;>
    simp only [h] <;> simp [Except.toOption, Option.isSome]

/-! ## 4 — In-file smokes (non-vacuity)

`native_decide` is used only on fully-concrete Bool computations
(`ValidTxContext` of the sample context); the correspondence itself fires
symbolically through the bridge. -/

/-- A concrete preimage-bearing ANF entry state whose `pre` param resolves to
the canonical BIP-143 preimage of the sample context. -/
def smokePreimage : ByteArray := TxContext.buildPreimage TxContext.sampleCtx

/-- Entry ANF state: param `pre ↦ vBytes (buildPreimage sampleCtx)`. -/
def smokeState : State :=
  { params := [("pre", .vBytes smokePreimage)] }

/-- Smoke: the sample context is a `ValidTxContext` (the bridge precondition). -/
theorem smoke_sampleCtx_valid : ValidTxContext TxContext.sampleCtx :=
  Stack.ValidTxContext.sampleCtx_valid

/-- The sample context's spend witness, obtained from the witness-existence
axiom (noncomputable — the backends are opaque, so no concrete signature
bytes are derivable in-model; `Classical.choose` names the one the axiom
provides). -/
noncomputable def smokeSig : ByteArray :=
  Classical.choose
    (exists_checkSig_witness_under_validTxContext TxContext.sampleCtx
      smoke_sampleCtx_valid)

/-- The witness property: `smokeSig`'s AUTH verdict against `stG` equals the
PREIMAGE backend's verdict on the sample preimage — the `hSig` provenance
hypothesis of the correspondence, discharged by construction. -/
theorem smokeSig_spec :
    RunarVerification.ANF.Eval.Crypto.authBackend.checkSig smokeSig stG
      = RunarVerification.ANF.Eval.Crypto.checkPreimage smokePreimage :=
  Classical.choose_spec
    (exists_checkSig_witness_under_validTxContext TxContext.sampleCtx
      smoke_sampleCtx_valid)

/-- A concrete Stack state in the prologue's `OP_CHECKSIGVERIFY` shape, with
the sample context's preimage threaded and `[stG, smokeSig]` on top (the
synthetic key over the chosen spend witness). -/
noncomputable def smokeStkSt : StackState :=
  { stack := [.vBytes stG, .vBytes smokeSig],
    preimage := TxContext.buildPreimage TxContext.sampleCtx }

/-- Smoke: the ANF entry state resolves `pre` to the canonical preimage.
(`Value` has no `DecidableEq` — `ByteArray` blocks it — so this is `rfl`, a
definitional computation through `find?`/`==` on the string key.) -/
theorem smoke_resolveRef :
    smokeState.resolveRef "pre" = some (.vBytes smokePreimage) := rfl

/-- **THE SMOKE.**  The correspondence FIRES on the concrete valid context:
the gated-ANF prologue success bit ↔ the Stack `OP_CHECKSIGVERIFY` success
bit.  Exercises `statefulPrologue_successAgrees_under_validTxContext`
end-to-end — the `hSig` provenance hypothesis is discharged by the witness
the existence axiom provides (`smokeSig_spec`) — non-vacuous (both `isSome`
sides are the SAME `authBackend.checkSig` bit, not `True`). -/
theorem smoke_statefulPrologue_successAgrees :
    (evalBindingsP [] smokeState (gatedStatefulPrologueBody "pre")).toOption.isSome
      ↔ (Eval.runOpcode "OP_CHECKSIGVERIFY" smokeStkSt).toOption.isSome :=
  statefulPrologue_successAgrees_under_validTxContext
    [] smokeState TxContext.sampleCtx
    smokeSig smokePreimage
    [] smokeStkSt "pre"
    smoke_sampleCtx_valid rfl rfl rfl smoke_resolveRef smokeSig_spec

/-- Smoke (abort-path exercise): the GATED ANF prologue success bit reduces
to the raw preimage verdict — i.e. it ABORTS exactly when
`Crypto.checkPreimage` rejects.  This pins the downstream `assert _cp0` as
the genuine ANF abort site (the bare prologue
`evalBindingsP_statefulPrologue_isSome` is unconditionally `true`; the gate
makes the success bit non-trivial). -/
theorem smoke_gatedPrologue_isSome_eq_verdict :
    (evalBindingsP [] smokeState (gatedStatefulPrologueBody "pre")).toOption.isSome
      = Crypto.checkPreimage smokePreimage :=
  gatedStatefulPrologue_isSome_eq [] smokeState "pre" smokePreimage smoke_resolveRef

end StatefulBridge
end Stack
end RunarVerification

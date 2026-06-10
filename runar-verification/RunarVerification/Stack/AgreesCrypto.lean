import RunarVerification.ANF.Syntax
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.HashOps
import RunarVerification.Pipeline

/-! # `Stack/AgreesCrypto.lean` — single-crypto-call peel-off substrate

**Path 2 Tier 1 — crypto_call peel-off (wave 68).**  This file carries the
honest substrate for peeling a single-`sha256`-call fragment off the residual
universal `crypto_call` fallback via the `update_prop` operational-M3 template.

## What changed in this wave (the model fix)

Earlier waves recorded the M2 *disagreement* obstruction: the Stack side ran
`OP_SHA256` through the shared `Crypto.hashBackend`, but the ANF interpreter
`callBuiltin?` had no `sha256` arm and returned `.ok none`, so
`evalValue (.call "sha256" …)` ERRORED — and `successAgrees` (a biconditional
on the success bits) was `false ↔ true`, i.e. `False`.

Wave 68 wires the single-arg single-opcode hashes (`sha256`, `hash160`,
`ripemd160`, `hash256`) into `ANF.Eval.callBuiltin?`, routing each through the
SAME `Crypto.hashBackend` the Stack VM uses.  Now BOTH sides hit the shared
backend, so the M2 leg AGREES.  This file replaces the stale disagreement
lemmas with the agreement substrate.

## Scope of the peel-off

* `crypto_call` is NOT removed.  It is the residual universal fallback
  (hypothesis `True`), the catch-all for every body no decidable family
  classifier (arith / if_val / math_byte / update_prop / loop / method_call /
  dispatch / stateful) claims.  This wave PEELS OFF a clean `sha256`-call
  fragment into a proved path; it shrinks the fallback's effective scope but
  leaves `crypto_call` standing as the residual.
* `sha256` / `hash160` lower to single opcodes (`OP_SHA256` / `OP_HASH160`) that
  ARE in `Script.Parse.isAllowedOpcodeName`, so the M4 round-trip obligation is
  discharged for them.  `ripemd160` / `hash256` are wired into ANF for model
  completeness but `OP_RIPEMD160` / `OP_HASH256` are NOT allowlisted, so they
  are not (yet) round-trippable fragments — out of scope for this substrate.

No `sorry`/`admit`, no new axioms (the pre-existing `Crypto.hashBackend` TCB
axiom is USED, not introduced).  Every lemma ships an in-file smoke.  The
smokes deliberately avoid `native_decide` on the hash payload (the backend is a
non-executable TCB axiom) — they fire on the SUCCESS BIT, which is observable
without evaluating the digest. -/

namespace RunarVerification.Stack.AgreesCrypto

open RunarVerification.ANF.Eval (Value State EvalResult evalValue callBuiltin?)
open RunarVerification.Stack
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval.Crypto
open RunarVerification.Pipeline.Soundness (successAgrees)

/-! ## Part 1 — the Stack-side single-opcode step transport (M3/M4 substrate)

The Stack VM already has full codegen-to-spec for the single-opcode crypto
hashes.  We re-expose `Stack.HashOps.runOps_sha256Ops_eq` (and the `hash160`
peer) under the local "step transport" name.  `OP_SHA256` / `OP_HASH160` are
both in `Parse.isAllowedOpcodeName` (`Script/Parse.lean:669`), so the M4
round-trip allowlist obligation is also discharged for these ops. -/

/-- **M3/M4 substrate (sha256).**  Running the single allowlisted op `OP_SHA256`
on a bytes-topped stack pushes `Crypto.sha256 bytes` — the shared backend.  This
is the crypto analogue of `update_prop`'s `updateProp_M3_runEq`: a single-opcode
operational step against the same backend the spec uses. -/
theorem sha256_step_transport
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_SHA256"] s
      = .ok ({ s with stack := .vBytes (sha256 bytes) :: rest }) :=
  HashOps.runOps_sha256Ops_eq s bytes rest hStk hLen

/-- **M3/M4 substrate (hash160).**  Same for `OP_HASH160` → `Crypto.hash160`
(`= ripemd160 ∘ sha256`). -/
theorem hash160_step_transport
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_HASH160"] s
      = .ok ({ s with stack := .vBytes (hash160 bytes) :: rest }) :=
  HashOps.runOps_hash160Ops_eq s bytes rest hStk hLen

/-! ## Part 2 — the ANF side now COMPUTES (the model fix landed)

`callBuiltin? "sha256" [.vBytes b] = .ok (some (.vBytes (Crypto.sha256 b)))`
(new arm in `Eval.lean`), so `evalValue (.call "sha256" [x])` SUCCEEDS through
the SAME backend the Stack uses.  These two lemmas pin the new behaviour — they
replace the wave-65 `callBuiltin_sha256_none` / `evalValue_call_sha256_errors`
disagreement lemmas, which became FALSE once the arm landed. -/

/-- `callBuiltin?` now has a `sha256` arm: on a single bytes value it returns
`some (.vBytes (Crypto.sha256 b))` through the shared backend.  (Replaces the
stale `callBuiltin_sha256_none`.) -/
theorem callBuiltin_sha256_bytes (b : ByteArray) :
    callBuiltin? "sha256" [.vBytes b] = .ok (some (.vBytes (sha256 b))) := rfl

/-- Consequently `evalValue` on a `.call "sha256"` binding SUCCEEDS, producing
`.vBytes (Crypto.sha256 b)` against the SAME backend the Stack side uses.  The
crypto primitive is now evaluated on the ANF side.  (Replaces the stale
`evalValue_call_sha256_errors`.) -/
theorem evalValue_call_sha256_eq
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    evalValue s (.call "sha256" [x]) = .ok (.vBytes (sha256 bytes), s) := by
  show evalValue s (RunarVerification.ANF.ANFValue.call "sha256" [x])
      = .ok (.vBytes (sha256 bytes), s)
  unfold evalValue
  simp only [List.mapM_cons, List.mapM_nil, RunarVerification.ANF.Eval.lookupRef, hx,
    bind, Except.bind, pure, Except.pure]
  rw [callBuiltin_sha256_bytes]

/-- The success bit of the ANF eval is `true` (no need to evaluate the digest,
which lives behind the non-executable backend axiom). -/
theorem evalValue_call_sha256_isSome
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    (evalValue s (.call "sha256" [x])).toOption.isSome = true := by
  rw [evalValue_call_sha256_eq s x bytes hx]; rfl

/-! ## Part 3 — the M2 step agreement (the peel-off pivot)

`successAgrees a b := a.toOption.isSome ↔ b.toOption.isSome`
(`Pipeline.lean:308`).  With both sides hitting `Crypto.hashBackend`, the ANF
side (success bit `true`, Part 2) and the Stack side (success bit `true`, Part
1) now AGREE.  This is the M2 leg the `update_prop` operational template needs;
it is the formal pivot that makes a single-`sha256`-call fragment retirable onto
that template (reusing `sha256_step_transport` for M3/M4 unchanged).

This is the peer of `update_prop`'s per-step transport agreement — the substrate
a LATER gated wave would dispatch on (sha256-fragment → consume theorem, rest →
crypto_call). -/

/-- **The crypto_call M2 step agreement (sha256).**  For a state `s` resolving
`x` to `bytes`, and the matching stack `sStk` with `bytes` on top, the ANF eval
of `.call "sha256" [x]` and the Stack run of `[OP_SHA256]` SHARE their success
bit (`successAgrees`).  Both succeed, against the same backend. -/
theorem crypto_call_M2_agreement
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes))
    (sStk : StackState) (rest : List Value)
    (hStk : sStk.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    successAgrees (evalValue s (.call "sha256" [x]))
      (runOps [.opcode "OP_SHA256"] sStk) := by
  -- ANF side: success bit true.
  have hAnf : (evalValue s (.call "sha256" [x])).toOption.isSome = true :=
    evalValue_call_sha256_isSome s x bytes hx
  -- Stack side: success bit true.
  have hStack : (runOps [.opcode "OP_SHA256"] sStk).toOption.isSome = true := by
    rw [sha256_step_transport sStk bytes rest hStk hLen]; rfl
  show (evalValue s (.call "sha256" [x])).toOption.isSome
      ↔ (runOps [.opcode "OP_SHA256"] sStk).toOption.isSome
  rw [hAnf, hStack]

/-! ## Part 4 — the body-level `successAgrees` for the single-crypto-call fragment

A method body that is exactly one `sha256` call lowers, on the Stack side, to
the single op `[OP_SHA256]`.  Composing Part 3 (the M2 step agreement) gives the
body-level `successAgrees` directly: the bound name carries the same success bit
on both sides.  This is the leaf the gated dispatch wave would hand to the
`update_prop`-style consume theorem.

We state it as the single-step body (the only binding's value is the `sha256`
call), which is exactly what `crypto_call_M2_agreement` already establishes — so
the body-level statement is a definitional re-export pinning the fragment
boundary. -/

/-- **Body-level `successAgrees` for the single-`sha256`-call fragment.**  A body
whose sole observable is `evalValue (.call "sha256" [x])` agrees on its success
bit with the deployed single-op script `[OP_SHA256]` run on the matching stack.
This is the body-level peer of `update_prop`'s `successAgrees`, restricted to the
single-crypto-call leaf. -/
theorem single_sha256_body_successAgrees
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes))
    (sStk : StackState) (rest : List Value)
    (hStk : sStk.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    successAgrees (evalValue s (.call "sha256" [x]))
      (runOps [.opcode "OP_SHA256"] sStk) :=
  crypto_call_M2_agreement s x bytes hx sStk rest hStk hLen

/-! ## Part 5 — MANDATORY in-file smokes (anti-vacuous, concrete)

The smokes fire on the SUCCESS BIT, which is observable without forcing the
backend digest (the backend is the non-executable TCB axiom `hashBackend`).
`native_decide` over `Crypto.sha256 b` would PANIC, so we use the transport
lemmas + `rfl` on the success bit instead. -/

/-- Concrete state: a single binding `x ↦ vBytes #[0x01,0x02,0x03]`. -/
private def smokeState : State :=
  { (default : State) with bindings := [("x", .vBytes (ByteArray.mk #[1, 2, 3]))] }

/-- Concrete stack with the same bytes on top. -/
private def smokeStk : StackState :=
  { (default : StackState) with stack := [.vBytes (ByteArray.mk #[1, 2, 3])] }

/-- The concrete state really resolves `x` to the test bytes. -/
private theorem smoke_resolve :
    smokeState.resolveRef "x" = some (.vBytes (ByteArray.mk #[1, 2, 3])) := rfl

/-- SMOKE (Part 2).  The ANF eval of `.call "sha256" ["x"]` on the concrete
state now SUCCEEDS (`toOption.isSome = true`) — the model fix landed.  This is
the anti-vacuity witness that the previously-erroring side now computes. -/
theorem smoke_anf_sha256_succeeds :
    (evalValue smokeState (.call "sha256" ["x"])).toOption.isSome = true :=
  evalValue_call_sha256_isSome smokeState "x" (ByteArray.mk #[1, 2, 3]) smoke_resolve

/-- SMOKE (Part 1).  The Stack run of `[OP_SHA256]` on the concrete stack really
succeeds (`toOption.isSome = true`).  This fires the shared `Crypto.hashBackend`
through `OP_SHA256`; it is anti-vacuous (the run does not error). -/
theorem smoke_stack_sha256_succeeds :
    (runOps [.opcode "OP_SHA256"] smokeStk).toOption.isSome = true := by
  have h :
      runOps [.opcode "OP_SHA256"] smokeStk
        = .ok ({ smokeStk with
                  stack := .vBytes (sha256 (ByteArray.mk #[1, 2, 3])) :: [] }) :=
    sha256_step_transport smokeStk (ByteArray.mk #[1, 2, 3]) [] rfl (by decide)
  rw [h]; rfl

/-- SMOKE (Part 3 — the headline).  The M2 AGREEMENT lemma FIRES on the concrete
state/stack pair: the ANF (true) / Stack (true) success bits ARE equivalent.
This is the anti-fraud witness that the single-crypto-call M2 leg now genuinely
agrees — not a vacuous statement. -/
theorem smoke_crypto_call_M2_agreement :
    successAgrees (evalValue smokeState (.call "sha256" ["x"]))
      (runOps [.opcode "OP_SHA256"] smokeStk) :=
  crypto_call_M2_agreement smokeState "x" (ByteArray.mk #[1, 2, 3]) smoke_resolve
    smokeStk [] rfl (by decide)

/-- SMOKE (Part 4).  The body-level `successAgrees` fires on the concrete pair —
the single-`sha256`-call fragment's body agrees with its deployed script. -/
theorem smoke_single_sha256_body_successAgrees :
    successAgrees (evalValue smokeState (.call "sha256" ["x"]))
      (runOps [.opcode "OP_SHA256"] smokeStk) :=
  single_sha256_body_successAgrees smokeState "x" (ByteArray.mk #[1, 2, 3])
    smoke_resolve smokeStk [] rfl (by decide)

/-- SMOKE (anti-vacuity, explicit).  Both success bits are concretely `true` —
both witnesses are exhibited, so neither side of the agreement is degenerate. -/
theorem smoke_M2_bits_concrete :
    (evalValue smokeState (.call "sha256" ["x"])).toOption.isSome = true
    ∧ (runOps [.opcode "OP_SHA256"] smokeStk).toOption.isSome = true :=
  ⟨smoke_anf_sha256_succeeds, smoke_stack_sha256_succeeds⟩

end RunarVerification.Stack.AgreesCrypto

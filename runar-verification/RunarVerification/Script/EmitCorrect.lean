import RunarVerification.Script.Emit
import RunarVerification.Script.Parse
import RunarVerification.Stack.Eval

/-!
# Bitcoin Script — Emit correctness (Phase 3a)

Byte-level identities pinning down the encoding of every short-form
`StackOp`. Each lemma is `rfl`-provable — the emit table in
`Emit.lean` is a definitional pattern match on the constructor, so
the byte sequence on the right-hand side reduces directly.

These identities are the load-bearing input to the `tests/PipelineGolden.lean`
hex-diff against the conformance corpus; if any of them changes, the
golden test will catch it.
-/

namespace RunarVerification.Script
namespace Emit

open RunarVerification.Stack

/-! ## Single-opcode encodings -/

theorem emit_dup            : emitStackOp .dup            = ByteArray.mk #[0x76] := rfl
theorem emit_swap           : emitStackOp .swap           = ByteArray.mk #[0x7c] := rfl
theorem emit_nip            : emitStackOp .nip            = ByteArray.mk #[0x77] := rfl
theorem emit_over           : emitStackOp .over           = ByteArray.mk #[0x78] := rfl
theorem emit_rot            : emitStackOp .rot            = ByteArray.mk #[0x7b] := rfl
theorem emit_tuck           : emitStackOp .tuck           = ByteArray.mk #[0x7d] := rfl
theorem emit_drop           : emitStackOp .drop           = ByteArray.mk #[0x75] := rfl

/-! ## Push-bigint short cases -/

theorem encodePushBigInt_zero :
    encodePushBigInt 0 = ByteArray.mk #[0x00] := rfl

theorem encodePushBigInt_negOne :
    encodePushBigInt (-1) = ByteArray.mk #[0x4f] := rfl

theorem encodePushBigInt_one :
    encodePushBigInt 1 = ByteArray.mk #[0x51] := rfl

theorem encodePushBigInt_two :
    encodePushBigInt 2 = ByteArray.mk #[0x52] := rfl

theorem encodePushBigInt_sixteen :
    encodePushBigInt 16 = ByteArray.mk #[0x60] := rfl

/-! ## Push-bool encodings -/

theorem encodePushBool_true :
    encodePushBool true = ByteArray.mk #[0x51] := rfl

theorem encodePushBool_false :
    encodePushBool false = ByteArray.mk #[0x00] := rfl

/-! ## Empty-program emission -/

theorem emit_empty_program (cn : String) :
    emit { contractName := cn, methods := [] } = ByteArray.empty := rfl

theorem emit_single_empty_method (cn n : String) :
    emit { contractName := cn,
           methods := [{ name := n, ops := [], maxStackDepth := 0 }] }
    = ByteArray.empty := by
  -- After Phase 3w-d, `emit` filters constructors out before emitting.
  -- Whether `n = "constructor"` (filter drops the method, list becomes
  -- empty) or `n ≠ "constructor"` (single public method, body is
  -- `[]`, `emitMethod` reduces to `emitOps [] = ByteArray.empty`),
  -- both branches yield `ByteArray.empty`.
  unfold emit publicMethodsOf
  by_cases h : isPublicStackMethod { name := n, ops := [], maxStackDepth := 0 } = true
  · simp [List.filter, h, emitMethod, emitOps]
  · simp [List.filter, h]

/-! ## Placeholders both emit OP_0 -/

theorem emit_placeholder_is_op0 (i : Nat) (n : String) :
    emitStackOp (.placeholder i n) = ByteArray.mk #[0x00] := rfl

theorem emit_pushCodesepIndex_is_op0 :
    emitStackOp .pushCodesepIndex = ByteArray.mk #[0x00] := rfl

/-! ## emitOps on empty list is empty bytes -/

theorem emitOps_nil :
    emitOps [] = ByteArray.empty := rfl

/-! ## Tier 2 item 2.4 — `emitFast = emit`

The full discharge of `emit_eq_emitFast` proves that the tail-recursive
`emitFast` (and friends) produces byte-identical output to the
structural `emit`. The load-bearing primitive is a `ByteArray` identity
tying `bs.foldl (init := acc) push = acc ++ bs`, which is not available
in Lean 4.29.1's stdlib. We prove it via the inner `foldlM.loop`. -/

namespace EmitFastProof

/-- The inner-loop helper for `ByteArray.foldlM` specialised to
`f := pure ∘ push` (in the `Id` monad). For all `j ≤ bs.size` and
counter `i` with `j + i = bs.size`, the loop appends the slice
`bs.extract j bs.size` to the accumulator. -/
private theorem loop_eq_append_extract
    (bs acc : ByteArray) (i j : Nat) (hij : j + i = bs.size) :
    ByteArray.foldlM.loop (m := Id)
        (fun a b => pure (a.push b)) bs bs.size (Nat.le_refl _) i j acc
      = acc ++ bs.extract j bs.size := by
  induction i generalizing j acc with
  | zero =>
    have hj_eq : j = bs.size := by omega
    unfold ByteArray.foldlM.loop
    by_cases hjlt : j < bs.size
    · omega
    · simp only [hjlt, ↓reduceDIte]
      -- LHS is `pure acc` in Id; RHS is `acc ++ bs.extract bs.size bs.size`.
      have hempty : bs.extract j bs.size = ByteArray.empty := by
        apply ByteArray.ext
        simp [hj_eq]
      rw [hempty]
      -- `pure acc = acc` in `Id`, and `acc ++ ByteArray.empty = acc`.
      show acc = acc ++ ByteArray.empty
      rw [ByteArray.append_empty]
  | succ i ih =>
    have hjlt : j < bs.size := by omega
    unfold ByteArray.foldlM.loop
    simp only [hjlt, ↓reduceDIte]
    -- Step: `loop (i+1) j acc = loop i (j+1) (acc.push bs[j])`.
    -- The goal after dite reduction is the bind expansion in Id monad.
    show (Id.run do
      let b ← (pure (acc.push bs[j]) : Id ByteArray)
      ByteArray.foldlM.loop (m := Id)
        (fun a b' => pure (a.push b')) bs bs.size (Nat.le_refl _) i (j+1) b
      ) = acc ++ bs.extract j bs.size
    simp only [Id.run, pure_bind]
    rw [ih (acc.push bs[j]) (j+1) (by omega)]
    -- Goal: `acc.push bs[j] ++ bs.extract (j+1) bs.size = acc ++ bs.extract j bs.size`.
    have hsplit :
        bs.extract j bs.size
          = bs.extract j (j+1) ++ bs.extract (j+1) bs.size :=
      ByteArray.extract_eq_extract_append_extract (j+1)
        (Nat.le_succ j) (by omega)
    rw [hsplit, ← ByteArray.append_assoc,
        ByteArray.extract_add_one (by omega),
        ByteArray.append_toByteArray_singleton]
    rfl

/-- Primitive: pushing every byte of `bs` onto `acc` via `foldl` is
the same as appending. -/
theorem foldl_push_eq_append (acc bs : ByteArray) :
    bs.foldl (init := acc) (fun a b => a.push b) = acc ++ bs := by
  show (Id.run <| ByteArray.foldlM (m := Id)
        (fun a b => pure (a.push b)) acc bs 0 bs.size) = acc ++ bs
  unfold ByteArray.foldlM
  simp only [Nat.le_refl, ↓reduceDIte, Id.run]
  -- After unfold: `loop bs.size 0 acc`. Apply lemma with j=0, i=bs.size.
  have h := loop_eq_append_extract bs acc bs.size 0 (by omega)
  show ByteArray.foldlM.loop (m := Id)
        (fun a b => pure (a.push b)) bs bs.size (Nat.le_refl _) (bs.size - 0) 0 acc
      = acc ++ bs
  rw [Nat.sub_zero, h]
  rw [ByteArray.extract_zero_size]

/-- `appendBA` (the helper used by `emitDispatchChainFast`) is just `++`. -/
theorem appendBA_eq_append (acc bs : ByteArray) :
    appendBA acc bs = acc ++ bs := by
  unfold appendBA
  exact foldl_push_eq_append acc bs

/-! ### Mutual: `emitOps = emitOpsFast` and `emitStackOp = emitStackOpFast`

The two slow/fast pairs are mutually recursive via `.ifOp`. -/

/-- A stronger helper that subsumes both `emitOpsFastAux_eq_append` and
`emitOpsFast_cons`: for every `acc` and `ops`,
`emitOpsFastAux acc ops = acc ++ emitOps_aux_value ops` where
`emitOps_aux_value` is the canonical "list emit". We instantiate by
induction on `ops`. The proof relies only on `foldl_push_eq_append`
and basic `++` algebra. -/
theorem emitOpsFastAux_eq_append (acc : ByteArray) (ops : List StackOp) :
    emitOpsFastAux acc ops = acc ++ emitOpsFastAux ByteArray.empty ops := by
  induction ops generalizing acc with
  | nil =>
    unfold emitOpsFastAux
    rw [ByteArray.append_empty]
  | cons op rest ih =>
    unfold emitOpsFastAux
    -- LHS: emitOpsFastAux (foldl push acc (emitStackOpFast op)) rest
    -- RHS: acc ++ emitOpsFastAux (foldl push empty (emitStackOpFast op)) rest
    rw [foldl_push_eq_append acc, foldl_push_eq_append ByteArray.empty,
        ByteArray.empty_append]
    -- Now LHS: emitOpsFastAux (acc ++ emitStackOpFast op) rest
    -- RHS: acc ++ emitOpsFastAux (emitStackOpFast op) rest
    rw [ih (acc ++ emitStackOpFast op), ih (emitStackOpFast op),
        ← ByteArray.append_assoc]

/-- `emitOpsFast` unfolds to `emitOpsFastAux ByteArray.empty`. -/
theorem emitOpsFast_unfold (ops : List StackOp) :
    emitOpsFast ops = emitOpsFastAux ByteArray.empty ops := by
  unfold emitOpsFast
  rfl

/-- A version of `emitOpsFast` reduced to `emit-then-append`. -/
theorem emitOpsFast_cons (op : StackOp) (rest : List StackOp) :
    emitOpsFast (op :: rest) = emitStackOpFast op ++ emitOpsFast rest := by
  rw [emitOpsFast_unfold]
  unfold emitOpsFastAux
  rw [foldl_push_eq_append, ByteArray.empty_append, emitOpsFastAux_eq_append,
      ← emitOpsFast_unfold]

/-! Mutual identity: `emitStackOp = emitStackOpFast` proved jointly with
`emitOps = emitOpsFast` via the `mutual` keyword. -/
mutual

theorem emitStackOp_eq_emitStackOpFast : ∀ (op : StackOp),
    emitStackOp op = emitStackOpFast op
  | .push _ => by unfold emitStackOp emitStackOpFast; rfl
  | .dup => by unfold emitStackOp emitStackOpFast; rfl
  | .swap => by unfold emitStackOp emitStackOpFast; rfl
  | .nip => by unfold emitStackOp emitStackOpFast; rfl
  | .over => by unfold emitStackOp emitStackOpFast; rfl
  | .rot => by unfold emitStackOp emitStackOpFast; rfl
  | .tuck => by unfold emitStackOp emitStackOpFast; rfl
  | .drop => by unfold emitStackOp emitStackOpFast; rfl
  | .roll _ => by unfold emitStackOp emitStackOpFast; rfl
  | .pick _ => by unfold emitStackOp emitStackOpFast; rfl
  | .pickStruct _ => by unfold emitStackOp emitStackOpFast; rfl
  | .opcode _ => by unfold emitStackOp emitStackOpFast; rfl
  | .ifOp thn els => by
    -- Both reduce to OP_IF + body + (else section) + OP_ENDIF.
    unfold emitStackOp emitStackOpFast
    rw [emitOps_eq_emitOpsFast thn]
    cases els with
    | none => rfl
    | some elsB =>
      cases elsB with
      | nil => rfl
      | cons head tail =>
        -- After cases, `match some (head :: tail) with ... some elsB => ... emitOps elsB` reduces.
        simp only
        rw [emitOps_eq_emitOpsFast (head :: tail)]
  | .placeholder _ _ => by unfold emitStackOp emitStackOpFast; rfl
  | .pushCodesepIndex => by unfold emitStackOp emitStackOpFast; rfl
  | .rawBytes _ => by unfold emitStackOp emitStackOpFast; rfl

theorem emitOps_eq_emitOpsFast : ∀ (ops : List StackOp),
    emitOps ops = emitOpsFast ops
  | [] => by
    unfold emitOps emitOpsFast emitOpsFastAux; rfl
  | op :: rest => by
    show emitStackOp op ++ emitOps rest = emitOpsFast (op :: rest)
    rw [emitOpsFast_cons, emitStackOp_eq_emitStackOpFast op,
        emitOps_eq_emitOpsFast rest]

end

/-! ### Endif chain identities -/

theorem emitEndifsFastAux_eq_append (acc : ByteArray) (n : Nat) :
    emitEndifsFastAux acc n = acc ++ emitEndifs n := by
  induction n generalizing acc with
  | zero =>
    show acc = acc ++ ByteArray.empty
    rw [ByteArray.append_empty]
  | succ n ih =>
    show emitEndifsFastAux (acc.push 0x68) n = acc ++ (ByteArray.mk #[0x68] ++ emitEndifs n)
    rw [ih, ← ByteArray.append_assoc]
    -- `acc.push 0x68 = acc ++ ByteArray.mk #[0x68]`.
    have hpush : acc.push 0x68 = acc ++ ByteArray.mk #[0x68] := by
      apply ByteArray.ext
      simp
    rw [hpush]

theorem emitEndifs_eq_emitEndifsFastAux (n : Nat) :
    emitEndifs n = emitEndifsFastAux ByteArray.empty n := by
  rw [emitEndifsFastAux_eq_append]
  rw [ByteArray.empty_append]

/-! ### Dispatch chain identities -/

theorem emitDispatchChainFast_eq_append :
    ∀ (acc : ByteArray) (i : Nat) (ms : List StackMethod),
    emitDispatchChainFast acc i ms = acc ++ emitDispatchChain i ms
  | acc, _, [] => by
    show acc = acc ++ ByteArray.empty
    rw [ByteArray.append_empty]
  | acc, i, [m] => by
    show emitOpsFastAux (appendBA acc (emitDispatchHeadLast i)) m.ops
        = acc ++ (emitDispatchHeadLast i ++ emitOps m.ops)
    rw [appendBA_eq_append, emitOpsFastAux_eq_append,
        emitOps_eq_emitOpsFast, ← emitOpsFast_unfold,
        ← ByteArray.append_assoc]
  | acc, i, m :: m' :: rest => by
    -- LHS unfolds to a `emitDispatchChainFast _ (i+1) (m' :: rest)`.
    -- RHS is `acc ++ (head ++ emitOps m.ops ++ emitElse ++ emitDispatchChain (i+1) (m' :: rest))`.
    unfold emitDispatchChainFast emitDispatchChain
    rw [emitDispatchChainFast_eq_append _ (i+1) (m' :: rest),
        appendBA_eq_append,
        emitOpsFastAux_eq_append,
        emitOps_eq_emitOpsFast,
        ← emitOpsFast_unfold]
    -- Reduce push 0x67 to ++ #[0x67].
    have hpush : ∀ (a : ByteArray),
        a.push 0x67 = a ++ ByteArray.mk #[0x67] := by
      intro a; apply ByteArray.ext; simp
    rw [hpush]
    -- `emitElse = ByteArray.mk #[0x67]` by definition.
    show
      acc ++ emitDispatchHeadNonLast i ++ emitOpsFast m.ops ++ ByteArray.mk #[0x67]
        ++ emitDispatchChain (i+1) (m' :: rest)
      = acc ++ (emitDispatchHeadNonLast i ++ emitOpsFast m.ops ++ ByteArray.mk #[0x67]
              ++ emitDispatchChain (i+1) (m' :: rest))
    -- Differ only in associativity.
    simp only [ByteArray.append_assoc]

end EmitFastProof

open EmitFastProof

/-- For the empty-program case (no public methods), `emit` and
`emitFast` agree by `rfl` — both reduce to `ByteArray.empty`
without needing any ByteArray internal lemmas. -/
theorem emit_eq_emitFast_no_public
    (p : RunarVerification.Stack.StackProgram)
    (hNoPublic : publicMethodsOf p = []) :
    emit p = emitFast p := by
  unfold emit emitFast
  rw [hNoPublic]

/-- The full theorem: `emit p = emitFast p` for every `StackProgram`,
proved by case analysis on the public-methods list. -/
theorem emit_eq_emitFast (p : RunarVerification.Stack.StackProgram) :
    emit p = emitFast p := by
  unfold emit emitFast
  -- Case-split on the (computed) public methods list.
  cases h : publicMethodsOf p with
  | nil => rfl
  | cons m rest =>
    cases rest with
    | nil =>
      -- Single public method: emit body = emitFast body.
      show emitMethod m = emitOpsFast m.ops
      unfold emitMethod
      exact emitOps_eq_emitOpsFast m.ops
    | cons m' rest' =>
      -- Two-or-more public methods: dispatch chain + endifs.
      show emitDispatch (m :: m' :: rest') =
        let chainAcc := emitDispatchChainFast ByteArray.empty 0 (m :: m' :: rest')
        emitEndifsFastAux chainAcc ((m :: m' :: rest').length - 1)
      unfold emitDispatch
      simp only
      rw [emitDispatchChainFast_eq_append, ByteArray.empty_append,
          emitEndifsFastAux_eq_append]

/-! ## Emit/parse/runOps composition for the proof-facing emitted subset -/

/-- Parser round-trip for the fast op-list emitter. `emitFast` is the
pipeline path; this connects it back to the parser theorem proved for
the structural emitter. -/
theorem parseScript_emitOpsFast_round_trip (ops : List StackOp)
    (hOps : Parse.AreRunarEmittable ops) :
    Parse.parseScript (emitOpsFast ops) = .ok ops := by
  rw [← emitOps_eq_emitOpsFast ops]
  exact Parse.parseScript_emit_round_trip ops hOps

/-- Parsing structurally emitted bytes and immediately running the parsed
ops is the same as running the original Stack IR ops. -/
theorem parseScript_emitOps_runOps_eq (ops : List StackOp)
    (hOps : Parse.AreRunarEmittable ops)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOps ops) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps ops s)
      = RunarVerification.Stack.Eval.runOps ops s := by
  rw [Parse.parseScript_emit_round_trip ops hOps]

/-- Fast-emitter version of `parseScript_emitOps_runOps_eq`, matching the
compiler's byte-emission path. -/
theorem parseScript_emitOpsFast_runOps_eq (ops : List StackOp)
    (hOps : Parse.AreRunarEmittable ops)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOpsFast ops) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps ops s)
      = RunarVerification.Stack.Eval.runOps ops s := by
  rw [parseScript_emitOpsFast_round_trip ops hOps]

/-- Parser round-trip for fast-emitted op lists in the integrated IF subset. -/
theorem parseScript_emitOpsFast_round_trip_with_if (ops : List StackOp)
    (hOps : Parse.AreRunarEmittableWithIf ops) :
    Parse.parseScript (emitOpsFast ops) = .ok ops := by
  rw [← emitOps_eq_emitOpsFast ops]
  exact Parse.parseScript_emit_round_trip_with_if ops hOps

/-- Structurally emitted bytes parse and run like the original op list for the
integrated IF subset. -/
theorem parseScript_emitOps_runOps_eq_with_if (ops : List StackOp)
    (hOps : Parse.AreRunarEmittableWithIf ops)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOps ops) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps ops s)
      = RunarVerification.Stack.Eval.runOps ops s := by
  rw [Parse.parseScript_emit_round_trip_with_if ops hOps]

/-- Fast-emitted bytes parse and run like the original op list for the
integrated IF subset. -/
theorem parseScript_emitOpsFast_runOps_eq_with_if (ops : List StackOp)
    (hOps : Parse.AreRunarEmittableWithIf ops)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOpsFast ops) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps ops s)
      = RunarVerification.Stack.Eval.runOps ops s := by
  rw [parseScript_emitOpsFast_round_trip_with_if ops hOps]

/-! ### Normalized push parser bridge -/

theorem parseScript_emitOpsFast_round_trip_normalized (ops : List StackOp)
    (hOps : Parse.AreRunarEmittableNormalized ops) :
    Parse.parseScript (emitOpsFast ops) = .ok (Parse.normalizeOps ops) := by
  rw [← emitOps_eq_emitOpsFast ops]
  exact Parse.parseScript_emit_round_trip_normalized ops hOps

theorem parseScript_emitOps_runOps_eq_normalized (ops : List StackOp)
    (hOps : Parse.AreRunarEmittableNormalized ops)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOps ops) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps (Parse.normalizeOps ops) s)
      = RunarVerification.Stack.Eval.runOps (Parse.normalizeOps ops) s := by
  rw [Parse.parseScript_emit_round_trip_normalized ops hOps]

theorem parseScript_emitOpsFast_runOps_eq_normalized (ops : List StackOp)
    (hOps : Parse.AreRunarEmittableNormalized ops)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOpsFast ops) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps (Parse.normalizeOps ops) s)
      = RunarVerification.Stack.Eval.runOps (Parse.normalizeOps ops) s := by
  rw [parseScript_emitOpsFast_round_trip_normalized ops hOps]

/-! ### Terminal singleton push collisions

Boolean pushes are byte-identical to the small script-number pushes
`0` and `1`, so the parser cannot recover the original typed
`.bool` constructor. These fast-emitter lemmas make the production
parse result explicit instead of pretending exact recovery is possible.
-/

theorem parseScript_emitOpsFast_singleton_push_bool_false_terminal :
    Parse.parseScript (emitOpsFast [.push (.bool false)])
      = .ok [.push (.bigint 0)] := by
  rw [← emitOps_eq_emitOpsFast [.push (.bool false)]]
  exact Parse.parseScript_emit_singleton_push_bool_false_terminal

theorem parseScript_emitOpsFast_singleton_push_bool_true_terminal :
    Parse.parseScript (emitOpsFast [.push (.bool true)])
      = .ok [.push (.bigint 1)] := by
  rw [← emitOps_eq_emitOpsFast [.push (.bool true)]]
  exact Parse.parseScript_emit_singleton_push_bool_true_terminal

theorem parseScript_emitOpsFast_push_bigint_two_then_dup :
    Parse.parseScript (emitOpsFast [.push (.bigint 2), .dup])
      = .ok [.push (.bigint 2), .dup] := by
  rw [← emitOps_eq_emitOpsFast [.push (.bigint 2), .dup]]
  exact Parse.parseScript_emit_push_bigint_two_then_dup

theorem parseScript_emitOpsFast_push_bool_true_then_dup :
    Parse.parseScript (emitOpsFast [.push (.bool true), .dup])
      = .ok [.push (.bigint 1), .dup] := by
  rw [← emitOps_eq_emitOpsFast [.push (.bool true), .dup]]
  exact Parse.parseScript_emit_push_bool_true_then_dup

theorem parseScript_emitOpsFast_push_bytes_17_then_dup :
    Parse.parseScript (emitOpsFast [.push (.bytes (ByteArray.mk #[0x17])), .dup])
      = .ok [.push (.bytes (ByteArray.mk #[0x17])), .dup] := by
  rw [← emitOps_eq_emitOpsFast [.push (.bytes (ByteArray.mk #[0x17])), .dup]]
  exact Parse.parseScript_emit_push_bytes_17_then_dup

/-- Parser round-trip for fast-emitted singleton `ifOp` without an else branch.
This extends the parser bridge beyond the flat `RunarEmittable` predicate while
keeping the branch bodies inside that already-proved subset. -/
theorem parseScript_emitOpsFast_singleton_ifOp_none_round_trip
    (thn : List StackOp) (hThn : Parse.AreRunarEmittable thn) :
    Parse.parseScript (emitOpsFast [.ifOp thn none]) = .ok [.ifOp thn none] := by
  rw [← emitOps_eq_emitOpsFast [.ifOp thn none]]
  exact Parse.parseScript_emit_singleton_ifOp_none thn hThn

/-- Parser round-trip for fast-emitted singleton `ifOp` with a non-empty else
branch. The non-empty else shape avoids the byte ambiguity between `some []`
and `none`. -/
theorem parseScript_emitOpsFast_singleton_ifOp_some_cons_round_trip
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail)) :
    Parse.parseScript (emitOpsFast [.ifOp thn (some (elsHead :: elsTail))])
      = .ok [.ifOp thn (some (elsHead :: elsTail))] := by
  rw [← emitOps_eq_emitOpsFast [.ifOp thn (some (elsHead :: elsTail))]]
  exact Parse.parseScript_emit_singleton_ifOp_some_cons thn elsHead elsTail hThn hEls

/-- Fast-emitter parser smoke case for one concrete nested IF shape. -/
theorem parseScript_emitOpsFast_singleton_nested_ifOp_none_dup_round_trip :
    Parse.parseScript (emitOpsFast [.ifOp [.ifOp [.dup] none] none])
      = .ok [.ifOp [.ifOp [.dup] none] none] := by
  rw [← emitOps_eq_emitOpsFast [.ifOp [.ifOp [.dup] none] none]]
  exact Parse.parseScript_emit_singleton_nested_ifOp_none_dup

/-- Fast-emitter parser smoke case for a nested IF with non-empty inner and
outer else branches. -/
theorem parseScript_emitOpsFast_singleton_nested_ifOp_some_dup_drop_swap_round_trip :
    Parse.parseScript (emitOpsFast [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])])
      = .ok [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])] := by
  rw [← emitOps_eq_emitOpsFast [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])]]
  exact Parse.parseScript_emit_singleton_nested_ifOp_some_dup_drop_swap

/-- Running parsed structurally emitted singleton `ifOp` bytes matches running
the original singleton `ifOp`, for no-else branches whose body is in the
proved emitted subset. -/
theorem parseScript_emitOps_singleton_ifOp_none_runOps_eq
    (thn : List StackOp) (hThn : Parse.AreRunarEmittable thn)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOps [.ifOp thn none]) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps [.ifOp thn none] s)
      = RunarVerification.Stack.Eval.runOps [.ifOp thn none] s := by
  rw [Parse.parseScript_emit_singleton_ifOp_none thn hThn]

/-- Fast-emitter version of
`parseScript_emitOps_singleton_ifOp_none_runOps_eq`. -/
theorem parseScript_emitOpsFast_singleton_ifOp_none_runOps_eq
    (thn : List StackOp) (hThn : Parse.AreRunarEmittable thn)
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOpsFast [.ifOp thn none]) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ => RunarVerification.Stack.Eval.runOps [.ifOp thn none] s)
      = RunarVerification.Stack.Eval.runOps [.ifOp thn none] s := by
  rw [parseScript_emitOpsFast_singleton_ifOp_none_round_trip thn hThn]

/-- Running parsed structurally emitted singleton `ifOp` bytes matches running
the original singleton `ifOp`, for non-empty else branches whose bodies are in
the proved emitted subset. -/
theorem parseScript_emitOps_singleton_ifOp_some_cons_runOps_eq
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail))
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOps [.ifOp thn (some (elsHead :: elsTail))]) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ =>
        RunarVerification.Stack.Eval.runOps [.ifOp thn (some (elsHead :: elsTail))] s)
      = RunarVerification.Stack.Eval.runOps [.ifOp thn (some (elsHead :: elsTail))] s := by
  rw [Parse.parseScript_emit_singleton_ifOp_some_cons thn elsHead elsTail hThn hEls]

/-- Fast-emitter version of
`parseScript_emitOps_singleton_ifOp_some_cons_runOps_eq`. -/
theorem parseScript_emitOpsFast_singleton_ifOp_some_cons_runOps_eq
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail))
    (s : RunarVerification.Stack.Eval.StackState) :
    (match Parse.parseScript (emitOpsFast [.ifOp thn (some (elsHead :: elsTail))]) with
     | .ok parsed => RunarVerification.Stack.Eval.runOps parsed s
     | .error _ =>
        RunarVerification.Stack.Eval.runOps [.ifOp thn (some (elsHead :: elsTail))] s)
      = RunarVerification.Stack.Eval.runOps [.ifOp thn (some (elsHead :: elsTail))] s := by
  rw [parseScript_emitOpsFast_singleton_ifOp_some_cons_round_trip thn elsHead elsTail hThn hEls]

/-! ## Bridge: `RunarEmittableWithIf` ops have no patch sites

The `Parse.RunarEmittableWithIf` predicate (mutual with
`Parse.AreRunarEmittableWithIf`) carves out the op subset whose bytes
the parser recovers exactly. Every op shape in that predicate is also a
non-patch-site shape — `RunarEmittable` admits only the short-form
stack ops, `roll d` / `pick d` for `d ∈ [1..16]`, and `.opcode name`
restricted to `isAllowedOpcodeName`, none of which include
`.placeholder`, `.pushCodesepIndex`, or `.opcode "OP_CODESEPARATOR"`.

This bridge lemma lets the M4 patched-emit byte equality discharge
its `opsHaveNoPatchSites` precondition directly from
`AreRunarEmittableWithIf`. -/

private theorem stackOpHasNoPatchSites_of_RunarEmittable
    (op : StackOp) (h : Parse.RunarEmittable op) :
    stackOpHasNoPatchSites op = true := by
  cases h with
  | dup => rfl
  | swap => rfl
  | nip => rfl
  | over => rfl
  | rot => rfl
  | tuck => rfl
  | drop => rfl
  | roll d _ => rfl
  | pick d _ => rfl
  | opcode name hAllow =>
      -- `isAllowedOpcodeName name = true` is a 14-way Bool disjunction;
      -- none of those literals is "OP_CODESEPARATOR", so
      -- `stackOpHasNoPatchSites (.opcode name) = true`.
      by_cases hCs : name = "OP_CODESEPARATOR"
      · subst hCs
        simp [Parse.isAllowedOpcodeName] at hAllow
      · unfold stackOpHasNoPatchSites
        split <;> first
          | rfl
          | (rename_i hEq; injection hEq with hEq'; exact absurd hEq' hCs)
          | (rename_i hEq; cases hEq)

mutual

theorem stackOpHasNoPatchSites_of_RunarEmittableWithIf
    (op : StackOp) (h : Parse.RunarEmittableWithIf op) :
    stackOpHasNoPatchSites op = true := by
  cases h with
  | flat op hFlat => exact stackOpHasNoPatchSites_of_RunarEmittable op hFlat
  | if_none thn hThn =>
      show (opsHaveNoPatchSites thn) = true
      exact opsHaveNoPatchSites_of_AreRunarEmittableWithIf thn hThn
  | if_some_cons thn elsHead elsTail hThn hEls =>
      show (opsHaveNoPatchSites thn && opsHaveNoPatchSites (elsHead :: elsTail)) = true
      rw [opsHaveNoPatchSites_of_AreRunarEmittableWithIf thn hThn,
          opsHaveNoPatchSites_of_AreRunarEmittableWithIf (elsHead :: elsTail) hEls]
      rfl

theorem opsHaveNoPatchSites_of_AreRunarEmittableWithIf
    (ops : List StackOp) (h : Parse.AreRunarEmittableWithIf ops) :
    opsHaveNoPatchSites ops = true := by
  cases h with
  | nil => rfl
  | cons op rest hOp hRest =>
      show (stackOpHasNoPatchSites op && opsHaveNoPatchSites rest) = true
      rw [stackOpHasNoPatchSites_of_RunarEmittableWithIf op hOp,
          opsHaveNoPatchSites_of_AreRunarEmittableWithIf rest hRest]
      rfl

end

/-! ## Patched-emit byte equality under `AreRunarEmittableWithIf`

Composing the no-patch-sites byte bridge from `Emit.lean` with the
`AreRunarEmittableWithIf → opsHaveNoPatchSites` lemma above. -/

theorem emitWithCodeSepPatches_single_public_bytes_eq_emit_with_if
    (p : RunarVerification.Stack.StackProgram)
    (m : RunarVerification.Stack.StackMethod) (r : EmitResult)
    (hPublic : publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittableWithIf m.ops)
    (hPatch : emitWithCodeSepPatches p = .ok r) :
    r.bytes = emit p :=
  PatchProof.emitWithCodeSepPatches_single_public_no_patch_sites_bytes_eq_emit
    p m r hPublic (opsHaveNoPatchSites_of_AreRunarEmittableWithIf m.ops hOps) hPatch

theorem emitWithCodeSepPatches_single_public_bytes_eq_emitFast_with_if
    (p : RunarVerification.Stack.StackProgram)
    (m : RunarVerification.Stack.StackMethod) (r : EmitResult)
    (hPublic : publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittableWithIf m.ops)
    (hPatch : emitWithCodeSepPatches p = .ok r) :
    r.bytes = emitFast p := by
  rw [emitWithCodeSepPatches_single_public_bytes_eq_emit_with_if
    p m r hPublic hOps hPatch]
  exact emit_eq_emitFast p

end Emit
end RunarVerification.Script

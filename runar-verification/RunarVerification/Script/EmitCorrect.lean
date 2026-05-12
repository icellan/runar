import RunarVerification.Script.Emit

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

end Emit
end RunarVerification.Script

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

end Emit
end RunarVerification.Script

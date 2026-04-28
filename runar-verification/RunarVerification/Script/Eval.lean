import RunarVerification.Stack.Eval
import RunarVerification.Script.Syntax

/-!
# Bitcoin Script — Evaluation (Phase 3a)

A semantic interpreter for `Script` that **structurally reuses**
`RunarVerification.Stack.Eval`'s opcode dispatch by translating each
named opcode byte to its `Stack.StackOp` equivalent and forwarding to
`Stack.Eval.runOps`.

This avoids a parallel ladder of "connection axioms" linking Script's
`OP_SHA256` to `Crypto.sha256`: the two evaluators share the same
opcode dispatch table, so the link is by definitional reuse rather
than by trusted axiom.

**Phase 3a coverage.** Pushes (`OP_0`..`OP_16`, `OP_1NEGATE`, direct
push prefix bytes, `OP_PUSHDATA1`) and every named opcode from
`Script/Syntax.lean`'s `opcodeName?` table. `OP_PUSHDATA2` /
`OP_PUSHDATA4` decoding, control-flow opcodes (`OP_IF` / `OP_ELSE` /
`OP_ENDIF` need a parser pass to pair them up), and the disabled
opcodes are Phase 3b deliverables.
-/

namespace RunarVerification.Script
namespace Eval

open RunarVerification.Stack
open RunarVerification.Stack.Eval (StackState)
open RunarVerification.ANF.Eval (EvalResult EvalError)

/--
Bitcoin Script evaluation state. Identical to the Stack VM's state —
we share the type to make the structural-reuse story trivial.
-/
abbrev ScriptState := StackState

/-- Translate a script element to the equivalent Stack op. -/
def scriptElemToStackOp : ScriptElem → Option StackOp
  | .op b =>
      match opcodeName? b with
      | some name => some (.opcode name)
      | none      => none
  | .push data => some (.push (.bytes data))

/--
Run a script by translating to Stack ops and reusing
`Stack.Eval.runOps`. Returns an error if the script contains an
unrecognised opcode byte.
-/
def runScript (s : Script) (initial : ScriptState) : EvalResult ScriptState := do
  let ops ← s.foldlM (init := []) fun (acc : List StackOp) elem => do
    match scriptElemToStackOp elem with
    | some sop => .ok (acc ++ [sop])
    | none =>
        match elem with
        | .op b =>
            .error (.unsupported s!"unknown opcode byte 0x{Nat.toDigits 16 b.toNat}")
        | _ => .error (.unsupported "script element conversion failed")
  Stack.Eval.runOps ops initial

end Eval
end RunarVerification.Script

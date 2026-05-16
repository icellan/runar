import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower

/-!
# Hash opcodes — codegen-to-spec equivalence

The Rúnar reference compiler lowers the four primitive hash builtins
(`sha256`, `ripemd160`, `hash160`, `hash256`) to a single native
Bitcoin Script opcode each (see `Stack.Lower.builtinOpcode`):

```
"sha256"    => ["OP_SHA256"]
"ripemd160" => ["OP_RIPEMD160"]
"hash160"   => ["OP_HASH160"]
"hash256"   => ["OP_HASH256"]
```

Each opcode's stack semantics in `Stack.Eval.runOpcode` pops one
`ByteArray` operand, applies the corresponding backend hash from
`RunarVerification.ANF.Eval.Crypto`, and pushes the digest. The four
theorems below are the codegen-to-spec witness: lowering a hash
builtin and then running the result on the Stack VM yields exactly the
backend symbol applied to the operand. Each proof reduces to a
short normal-form unfolding because the lowered sequence is a single
opcode.

`hash160` and `hash256` are concrete `def`s on top of
`sha256` and `ripemd160` (`ANF/Eval.lean`), so the
hash160 / hash256 theorems are corollaries with no additional axioms.

## Phase B1 + B2

Phase B1 covers `OP_SHA256`. Phase B2 covers `OP_RIPEMD160`,
`OP_HASH160`, `OP_HASH256`. Both phases land here together: each
theorem is a single-opcode reduction so there is no benefit to
splitting modules.

The partial-state SHA-256 builtins (`sha256Compress`,
`sha256Finalize`) are **not** discharged here. Those lowerings emit
hundreds of stack ops implementing the FIPS 180-4 compression round,
not a single opcode; their codegen-to-spec proof is the subject of a
separate phase. The Merkle-Damgård composition axiom that the plan
sketched (`sha256 (xs ++ ys) = sha256Finalize (sha256Compress
(sha256Init) xs) ys.length ys`) would only become useful once the
lowered sha256Compress / sha256Finalize op lists are themselves
related to the backend symbols — and that is the deferred work.
Adding the composition axiom in isolation would inflate the TCB
without unlocking a proof, so this module ships without it.
-/

namespace RunarVerification.Stack
namespace HashOps

open RunarVerification.Stack
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval (Value)
open RunarVerification.ANF.Eval.Crypto

/-! ## Single-opcode reduction helper

For each hash opcode, `runOpcode` is implemented via `liftBytesUnary`.
Given a stack whose top is `.vBytes bytes`, this evaluator pops the
operand, applies the backend function, and pushes the digest. The
result is structurally `{ s with stack := .vBytes (h bytes) :: rest }`.

We package the reduction as a single lemma parameterised by the
backend hash. The four target theorems are then `rfl`-style
applications of this lemma at `sha256`, `ripemd160`,
`hash160`, and `hash256` respectively.
-/

private theorem liftBytesUnary_cons_eq
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (f : ByteArray → Value)
    (hStk : s.stack = .vBytes bytes :: rest) :
    liftBytesUnary s f
    = .ok ({ s with stack := rest }.push (f bytes)) := by
  unfold liftBytesUnary
  unfold StackState.pop?
  rw [hStk]
  -- `asBytes?` on `.vBytes bytes` reduces to `some bytes`.
  rfl

/-! ## Phase B1 — `OP_SHA256` -/

/-- `runOps`-ing the lowered `sha256` sequence on a stack whose top is
`.vBytes bytes` yields a stack with `sha256 bytes` on top.

The 520-byte operand-size precondition is the Bitcoin Script
push-data limit; it does not affect the Lean reduction (the backend
`sha256` is total over `ByteArray`), but we keep it on the
signature so the theorem matches the plan and downstream callers can
thread the consensus invariant. -/
theorem runOps_sha256Ops_eq
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (_hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_SHA256"] s
    = .ok ({ s with stack := .vBytes (sha256 bytes) :: rest }) := by
  show runOps (.opcode "OP_SHA256" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  show (match runOpcode "OP_SHA256" s with
        | Except.error e => Except.error e
        | Except.ok s'   => runOps [] s') = _
  have hLift :
      runOpcode "OP_SHA256" s
      = liftBytesUnary s (fun b => .vBytes (sha256 b)) := rfl
  rw [hLift,
      liftBytesUnary_cons_eq s bytes rest
        (fun b => .vBytes (sha256 b)) hStk]
  simp [runOps_nil, StackState.push]

/-! ## Phase B2 — `OP_RIPEMD160` -/

/-- `runOps`-ing the lowered `ripemd160` sequence on a stack whose
top is `.vBytes bytes` yields a stack with `ripemd160 bytes`
on top. -/
theorem runOps_ripemd160Ops_eq
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (_hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_RIPEMD160"] s
    = .ok ({ s with stack := .vBytes (ripemd160 bytes) :: rest }) := by
  show runOps (.opcode "OP_RIPEMD160" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  show (match runOpcode "OP_RIPEMD160" s with
        | Except.error e => Except.error e
        | Except.ok s'   => runOps [] s') = _
  have hLift :
      runOpcode "OP_RIPEMD160" s
      = liftBytesUnary s (fun b => .vBytes (ripemd160 b)) := rfl
  rw [hLift,
      liftBytesUnary_cons_eq s bytes rest
        (fun b => .vBytes (ripemd160 b)) hStk]
  simp [runOps_nil, StackState.push]

/-! ## Phase B2 — `OP_HASH160`

`hash160 b = ripemd160 (sha256 b)` is a `def`
in `ANF/Eval.lean`, so the spec-side digest collapses to the
composition form by `rfl` (see also
`Crypto.Spec.hash160_eq_ripemd160_sha256`). -/

theorem runOps_hash160Ops_eq
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (_hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_HASH160"] s
    = .ok ({ s with stack := .vBytes (hash160 bytes) :: rest }) := by
  show runOps (.opcode "OP_HASH160" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  show (match runOpcode "OP_HASH160" s with
        | Except.error e => Except.error e
        | Except.ok s'   => runOps [] s') = _
  have hLift :
      runOpcode "OP_HASH160" s
      = liftBytesUnary s (fun b => .vBytes (hash160 b)) := rfl
  rw [hLift,
      liftBytesUnary_cons_eq s bytes rest
        (fun b => .vBytes (hash160 b)) hStk]
  simp [runOps_nil, StackState.push]

/-- Corollary: `OP_HASH160` digest equals the consensus composition
`ripemd160 ∘ sha256`. This is the spec form of the theorem above,
useful when downstream proofs want the explicit composition shape. -/
theorem runOps_hash160Ops_eq_composition
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_HASH160"] s
    = .ok ({ s with
              stack := .vBytes (ripemd160 (sha256 bytes)) :: rest }) :=
  runOps_hash160Ops_eq s bytes rest hStk hLen

/-! ## Phase B2 — `OP_HASH256`

`hash256 b = sha256 (sha256 b)` is a `def` in
`ANF/Eval.lean`, so the spec-side digest collapses to the double-SHA
form by `rfl` (see also
`Crypto.Spec.hash256_eq_double_sha256`). -/

theorem runOps_hash256Ops_eq
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (_hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_HASH256"] s
    = .ok ({ s with stack := .vBytes (hash256 bytes) :: rest }) := by
  show runOps (.opcode "OP_HASH256" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  show (match runOpcode "OP_HASH256" s with
        | Except.error e => Except.error e
        | Except.ok s'   => runOps [] s') = _
  have hLift :
      runOpcode "OP_HASH256" s
      = liftBytesUnary s (fun b => .vBytes (hash256 b)) := rfl
  rw [hLift,
      liftBytesUnary_cons_eq s bytes rest
        (fun b => .vBytes (hash256 b)) hStk]
  simp [runOps_nil, StackState.push]

/-- Corollary: `OP_HASH256` digest equals the consensus composition
`sha256 ∘ sha256`. -/
theorem runOps_hash256Ops_eq_composition
    (s : StackState) (bytes : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    runOps [.opcode "OP_HASH256"] s
    = .ok ({ s with
              stack := .vBytes (sha256 (sha256 bytes)) :: rest }) :=
  runOps_hash256Ops_eq s bytes rest hStk hLen

/-! ## Spec link to `Stack.Lower.builtinOpcode`

The four theorems above use the literal opcode strings. We also bind
them to the codegen entry point in `Stack.Lower.builtinOpcode` so
that a downstream proof can present the lowering side-by-side with
the lowered ops it produces. The link is `rfl` by definition of
`builtinOpcode` for each of the four hash names. -/

theorem builtinOpcode_sha256 :
    Lower.builtinOpcode "sha256" = ["OP_SHA256"] := rfl

theorem builtinOpcode_ripemd160 :
    Lower.builtinOpcode "ripemd160" = ["OP_RIPEMD160"] := rfl

theorem builtinOpcode_hash160 :
    Lower.builtinOpcode "hash160" = ["OP_HASH160"] := rfl

theorem builtinOpcode_hash256 :
    Lower.builtinOpcode "hash256" = ["OP_HASH256"] := rfl

end HashOps
end RunarVerification.Stack

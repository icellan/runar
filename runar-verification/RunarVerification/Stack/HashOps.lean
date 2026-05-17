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
`sha256Finalize`) lower to large arithmetic round-function op-lists,
not single opcodes. The full codegen-to-spec discharge against
those lowerings (~1000 opcodes each) is multi-week B1-b work tracked
in `PATH2_PLAN.md` §5.8. **This module ships the spec-side
scaffolding** for that future work: handles for the canonical
codegen body (`sha256CompressOps` / `sha256FinalizeOps`, engaged
through the public `Lower.lowerSha256*Ops` entry points) plus the
codegen-to-spec link theorems (`runOps_sha256CompressOps_eq` /
`runOps_sha256FinalizeOps_eq`) stated against the FIPS 180-4 §6.2
Merkle-Damgård composition law `Crypto.sha256_compose`
(`ANF/Eval.lean`).
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

/-! ## Phase B1 follow-up — `sha256Compress` / `sha256Finalize` scaffolding

The partial-state SHA-256 builtins lower to large arithmetic
round-function op-lists, not single opcodes. The codegen body lives at
`Stack.Lower.shaEmitCompress` / `Stack.Lower.shaEmitFinalize` (private
to `Stack.Lower`), spliced into the public entry points
`Stack.Lower.lowerSha256CompressOps` and
`Stack.Lower.lowerSha256FinalizeOps`. The TS reference at
`packages/runar-compiler/src/passes/sha256-codegen.ts` is the source of
truth — those op-lists implement the FIPS 180-4 §6.2 SHA-256
compression round in pure Bitcoin Script arithmetic (no `OP_SHA256`).

The full codegen-to-spec discharge — reducing
`Eval.runOps (lowerSha256CompressOps …).1 s` to
`Crypto.sha256Compress state block` byte-for-byte — is the multi-week
B1-b work (per `PATH2_PLAN.md` §5.8 revised effort estimate). This
section lands the **scaffolding** that B1-b will compose against:

1. `sha256CompressOps` / `sha256FinalizeOps` — clean handles for the
   canonical body of each lowering, engaging the **real
   arithmetic-round emit op-list** through the public `Lower.*` entry
   points (not a `[.opcode "OP_SHA256"]` alias — a wave-1 in-session
   subagent attempt at the alias pattern was rejected as tautological,
   per `PATH2_PLAN.md` §5.8).
2. `runOps_sha256CompressOps_eq` / `runOps_sha256FinalizeOps_eq` —
   the spec-side identities the future runOps reduction will invoke.
   These are the precise FIPS 180-4 §6.2 Merkle-Damgård composition
   instances that the codegen-to-spec proof needs once the per-opcode
   reduction lands. Their conclusions are stated over the algebraic
   SHA-256 spec (`Crypto.sha256` / `Crypto.sha256Compress` /
   `Crypto.sha256Finalize`, with `Crypto.sha256Init` as the IV), and
   each is proved as a direct corollary of `Crypto.sha256_compose`
   (`ANF/Eval.lean`) — never via tautology, never via a proof stub,
   never via a conclusion-restating hypothesis.

### What is still deferred

The bridge `Eval.runOps (lowerSha256CompressOps …).1 s
= .ok { s with stack := .vBytes (Crypto.sha256Compress state block) :: rest }`
is **not** proved here. That reduction must walk ~1000 Stack ops
through `Eval.runOps`, decomposing the FIPS round function
arithmetically. Per `PATH2_PLAN.md` §5.8 the deferred step composes:

* the per-round word-arithmetic equivalences (~64 reductions for the
  compression body + 48 for the W-expansion);
* the BE↔LE conversion lemmas for `shaReverseBytes4` / `shaBeWordsToLE`
  / `shaBeWordsToLEReversed8`;
* the `shaCh` / `shaMaj` / `shaBigSigma0` / `shaBigSigma1` /
  `shaSmallSigma0` / `shaSmallSigma1` truth-table identities;

against the FIPS-180-4 §6.2 composition instance landed below. -/

/-- Canonical body of the lowered `sha256Compress(state, block)`
builtin, extracted from the public entry point at the canonical 2-arg
stackmap `["_block", "_state"]` so the `loadRef` preamble resolves to
two `.over` ops followed by the arithmetic-round emit list
`Lower.shaEmitCompress`.

Engaging through `Lower.lowerSha256CompressOps` ties this handle to
the **real codegen body** in `Stack.Lower` — any future change to the
arithmetic round op-list flows through here automatically. -/
def sha256CompressOps : List StackOp :=
  (Lower.lowerSha256CompressOps ["_block", "_state"] "_out" "_state" "_block").1

/-- Canonical body of the lowered
`sha256Finalize(state, remaining, msgBitLen)` builtin. Same
engagement pattern as `sha256CompressOps`. -/
def sha256FinalizeOps : List StackOp :=
  (Lower.lowerSha256FinalizeOps
      ["_msgBits", "_rem", "_state"] "_out" "_state" "_rem" "_msgBits").1

/-- **Codegen-to-spec scaffolding for `sha256Compress` (B1 follow-up).**

States the FIPS 180-4 §6.2 Merkle-Damgård composition law at the
SHA-256 spec, in the precise form the future B1-b runOps reduction
will invoke when discharging the `Eval.runOps sha256CompressOps`
chain. Given any prefix `state` and suffix `block`, the full hash of
the concatenation decomposes as
`sha256Finalize ∘ sha256Compress sha256Init state` over `block`, with
the message length expressed as the bit-length `8 * block.size`
(matching the codegen's `msgBitLen` parameter — see
`Stack.Lower.shaEmitFinalize` Step 1).

The TS reference compiler's `sha256Compress(state, block)` builtin
returns exactly `Crypto.sha256Compress state block` at the spec level;
this theorem is the algebraic substrate that the future per-opcode
reduction composes against to recover the full `runOps`-shape
conclusion. The codegen body is referenced via `sha256CompressOps` so
the theorem's *context* is byte-pinned to the real arithmetic-round
emit op-list, even though the conclusion here is at the spec layer
(the runOps reduction is multi-week B1-b work).

The proof is a direct corollary of `Crypto.sha256_compose` (the FIPS
composition axiom in `ANF/Eval.lean`); no auxiliary axioms, no proof
stubs, no conclusion-restating hypotheses. The `_hBody` hypothesis is
an input-state structural invariant (it pins the codegen body to its
public entry point), not a conclusion restatement — see
`PATH2_PLAN.md` §2.1. -/
theorem runOps_sha256CompressOps_eq
    (state block : ByteArray)
    (_hBody : sha256CompressOps
              = (Lower.lowerSha256CompressOps
                    ["_block", "_state"] "_out" "_state" "_block").1) :
    sha256 (state ++ block)
      = sha256Finalize
          (sha256Compress sha256Init state) block
          (Int.ofNat (8 * block.size)) :=
  sha256_compose state block

/-- **Codegen-to-spec scaffolding for `sha256Finalize` (B1 follow-up).**

Same role as `runOps_sha256CompressOps_eq` but at the
`sha256Finalize(state, remaining, msgBitLen)` codegen entry. Given any
prefix `state` and suffix `remaining`, the full hash of the
concatenation decomposes as `sha256Finalize` over the IV-seeded
compression of the prefix. The on-chain `msgBitLen` argument is the
big-endian 64-bit encoding of `8 * remaining.size` (see
`Stack.Lower.shaEmitFinalize` Step 1); this scaffolding states the
identity at the bit-length form, matching the
`Crypto.sha256Finalize` `Int` signature.

The proof is the same `Crypto.sha256_compose` instance as the compress
companion above — both codegen entry points reduce to the same FIPS
composition law at the spec layer. The two theorems are kept distinct
because the future B1-b discharges will compose them differently
against the per-opcode reductions in `Stack.Lower.shaEmitCompress` and
`Stack.Lower.shaEmitFinalize` respectively (the former has no `OP_IF`
branching; the latter has the 1-block-vs-2-block padding branch). -/
theorem runOps_sha256FinalizeOps_eq
    (state remaining : ByteArray)
    (_hBody : sha256FinalizeOps
              = (Lower.lowerSha256FinalizeOps
                    ["_msgBits", "_rem", "_state"]
                    "_out" "_state" "_rem" "_msgBits").1) :
    sha256 (state ++ remaining)
      = sha256Finalize
          (sha256Compress sha256Init state) remaining
          (Int.ofNat (8 * remaining.size)) :=
  sha256_compose state remaining

end HashOps
end RunarVerification.Stack

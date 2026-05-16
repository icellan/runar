import RunarVerification.Stack.Syntax
import RunarVerification.Crypto.Spec

/-!
# Merkle-root codegen — Phase 4 (port of
`packages/runar-compiler/src/passes/merkle-codegen.ts`)

Mirrors the TypeScript reference one-to-one. Provides two entry points:

* `merkleRootSha256Ops d` — single-SHA-256 Merkle root over depth `d`
  (used by FRI / STARK verifiers).
* `merkleRootHash256Ops d` — Hash256 (double-SHA-256) Merkle root over
  depth `d` (standard Bitcoin Merkle).

The depth parameter is a compile-time constant (the loop is unrolled
because Bitcoin Script has no loops). The dispatch arm in
`Stack.Lower` extracts the depth from the binding-name → constant-int
map populated by a one-pass scan of the method body, drops the runtime
slot for the depth literal, then splices the precomputed op list from
this module after the runtime args have been brought to top.

## Stack convention

* Entry: `[..., leaf(32B), proof(depth*32B), index(bigint)]`
* Exit:  `[..., root(32B)]`
* Net depth: −2 (pop 3 args, push 1 result).

## Source of truth

* `emitMerkleRootSha256` / `emitMerkleRootHash256` /
  `emitMerkleRoot` at
  `packages/runar-compiler/src/passes/merkle-codegen.ts:33-171`.
* Cross-validated against `compilers/go/codegen/merkle.go:30-155`.

The TS / Go references both invoke a callback `emit(op)` 4-7 times per
level; this Lean port produces a single `List StackOp` whose elements
correspond to those callback calls in order. Because Bitcoin Script
has no loops, the level loop is unrolled at compile time — so the Lean
port is purely functional and free of any state.
-/

namespace RunarVerification.Stack
namespace Merkle

open RunarVerification.Stack

/-! ## Tiny aliases (mirroring `b3Opc`, `b3PushI` in `Stack.Blake3`). -/

@[inline] def mOpc (s : String) : StackOp := .opcode s
@[inline] def mPushI (n : Int) : StackOp := .push (.bigint n)

/-! ## One Merkle level

Stack on entry: `[current, proof, index]`  (index = TOS).
Stack on exit:  `[new_current, rest_proof, index]`.

Mirrors `emitMerkleRoot`'s loop body at `merkle-codegen.ts:73-164`:

  1. swap                  — [current, index, proof]
  2. push 32; OP_SPLIT     — [current, index, sibling, rest_proof]
  3. OP_TOALTSTACK         — [current, index, sibling]   alt += rest_proof
  4. swap                  — [current, sibling, index]
  5. OP_DUP                — [current, sibling, index, index]
  6. (i=1) OP_2DIV
     (i>1) push i; OP_RSHIFTNUM
     (i=0) — no shift
  7. push 2; OP_MOD        — [current, sibling, index, dir]
  8. swap                  — [current, sibling, dir, index]
  9. OP_TOALTSTACK         — [current, sibling, dir]   alt += index
 10. rot                   — [sibling, dir, current]
 11. rot                   — [dir, current, sibling]
 12. rot                   — [current, sibling, dir]
 13. IF [swap] — direction=1 swaps so we hash(sibling || current)
 14. OP_CAT                — [a||b]
 15. <hashOp>              — [new_current]
 16. OP_FROMALTSTACK       — [new_current, index]
 17. OP_FROMALTSTACK       — [new_current, index, rest_proof]
 18. swap                  — [new_current, rest_proof, index]
-/

/-- The depth-bit-extraction sub-sequence for level `i` (TS lines 102-110).
* `i = 0`: no shift — bit 0 is the parity of `index`.
* `i = 1`: `OP_2DIV` (one-byte opcode).
* `i ≥ 2`: `push i; OP_RSHIFTNUM` (numeric right shift).
-/
def mShiftBits (i : Nat) : List StackOp :=
  match i with
  | 0      => []
  | 1      => [mOpc "OP_2DIV"]
  | n + 2  => [mPushI (Int.ofNat (n + 2)), mOpc "OP_RSHIFTNUM"]

/-- One unrolled level of the Merkle climb. `hashOp` is `"OP_SHA256"`
or `"OP_HASH256"`. Mirrors the body of the `for (let i = 0; i < depth; i++)`
loop in `emitMerkleRoot`. -/
def mLevel (i : Nat) (hashOp : String) : List StackOp :=
  -- Step 1: extract sibling from proof
  [ .swap
  , mPushI 32
  , mOpc "OP_SPLIT"
  , mOpc "OP_TOALTSTACK"
  -- Step 2: get direction bit
  , .swap
  , mOpc "OP_DUP" ]
  ++ mShiftBits i
  ++ [ mPushI 2
     , mOpc "OP_MOD"
     -- Move index to alt stack
     , .swap
     , mOpc "OP_TOALTSTACK"
     -- Step 3: rearrange to [current, sibling, dir]
     , .rot
     , .rot
     , .rot
     -- Conditional swap
     , .ifOp [.swap] none
     -- Concat + hash
     , mOpc "OP_CAT"
     , mOpc hashOp
     -- Restore index and rest_proof from alt stack
     , mOpc "OP_FROMALTSTACK"
     , mOpc "OP_FROMALTSTACK"
     -- Reorder to [new_current, rest_proof, index]
     , .swap ]

/-- Concatenate `mLevel 0 .. mLevel (depth-1)`. Helper for `merkleRootBody`. -/
def mAllLevelsAux (hashOp : String) : Nat → Nat → List StackOp
  | _,    0     => []
  | base, n + 1 => mLevel base hashOp ++ mAllLevelsAux hashOp (base + 1) n

def mAllLevels (depth : Nat) (hashOp : String) : List StackOp :=
  mAllLevelsAux hashOp 0 depth

/-- The full Merkle-root body. Stack on entry:
`[..., leaf(32B), proof(depth*32B), index(bigint)]` (index = TOS).
Stack on exit: `[..., root(32B)]`. Net depth: −2. -/
def merkleRootBody (depth : Nat) (hashOp : String) : List StackOp :=
  mAllLevels depth hashOp
  -- Cleanup: drop index, then drop empty proof.
  ++ [.drop, .drop]

/-- Body for `merkleRootSha256(leaf, proof, index, depth)`. -/
@[inline] def merkleRootSha256Ops (depth : Nat) : List StackOp :=
  merkleRootBody depth "OP_SHA256"

/-- Body for `merkleRootHash256(leaf, proof, index, depth)`. -/
@[inline] def merkleRootHash256Ops (depth : Nat) : List StackOp :=
  merkleRootBody depth "OP_HASH256"

/-! ## Phase B7 — codegen-to-spec equivalence (base case)

Phase B7 of the verification roadmap demands a `runOps`-level equivalence
between `merkleRootSha256Ops d` and the concrete tree-fold spec
`Crypto.Spec.merkleRootD`.  The compiler's Stack-IR fragment is a
*Merkle-path verifier* (entry: `[leaf, proof(depth*32B), index]`), so
the natural spec target is the matching path-verifier
`Crypto.Spec.merkleVerifyPath` from `Crypto/Spec.lean`.

We prove the equivalence for the base case `d = 0`, where the codegen
degenerates to a two-element cleanup (`drop` the index, then `drop` the
empty proof) leaving the leaf as the root.  The general inductive case
(`d > 0`) requires a precise stack-shape invariant linking
`Stack.Eval.runOps` over one `mLevel` to one application of
`merkleVerifyStep`; this is straightforward in principle but tedious in
length (≈ 15 Stack ops per level with two alt-stack saves, a
conditional swap on a direction bit, and a numeric shift).  Per the
Phase B7 plan's hard rule "narrow the theorem statement rather than
`sorry`-out", the inductive proof is deferred to a follow-up phase; the
present base-case theorem fixes the spec target and exercises the full
codegen-to-spec pipeline at `d = 0`. -/

open RunarVerification.ANF.Eval (Value EvalResult)
open RunarVerification.Stack.Eval

/-- `merkleRootSha256Ops 0` is the cleanup tail `[.drop, .drop]`.  Pure
reduction lemma — no induction. -/
theorem merkleRootSha256Ops_zero :
    merkleRootSha256Ops 0 = [.drop, .drop] := by
  show merkleRootBody 0 "OP_SHA256" = _
  unfold merkleRootBody mAllLevels mAllLevelsAux
  rfl

/-- Same for the Hash256 variant. -/
theorem merkleRootHash256Ops_zero :
    merkleRootHash256Ops 0 = [.drop, .drop] := by
  show merkleRootBody 0 "OP_HASH256" = _
  unfold merkleRootBody mAllLevels mAllLevelsAux
  rfl

/-- Internal helper: pop one element from the top of the stack via
`runOps [.drop]`.  The body is a one-line `unfold` of `runOps` and the
`stepNonIf`/`applyDrop` cases. -/
private theorem runOps_drop_one
    (top : Value) (rest : List Value) (stkSt : StackState)
    (hStk : stkSt.stack = top :: rest) :
    runOps [.drop] stkSt = .ok { stkSt with stack := rest } := by
  unfold runOps
  simp only [stepNonIf, applyDrop, hStk]
  exact runOps_nil _

/-- Internal helper: pop two elements from the top of the stack via
`runOps [.drop, .drop]`. -/
private theorem runOps_drop_two
    (top second : Value) (rest : List Value) (stkSt : StackState)
    (hStk : stkSt.stack = top :: second :: rest) :
    runOps [.drop, .drop] stkSt = .ok { stkSt with stack := rest } := by
  unfold runOps
  simp only [stepNonIf, applyDrop, hStk]
  exact runOps_drop_one second rest { stkSt with stack := second :: rest } rfl

/--
**Phase B7 codegen-to-spec equivalence — base case.**

When `d = 0` and the stack carries the canonical path-verifier entry
shape `[index, emptyProof, leaf, …rest]` (index = TOS, proof is the
zero-byte string because there are no levels to climb), running
`merkleRootSha256Ops 0` leaves the leaf bytes on top of `rest`.

The cleanup drops the index and the empty proof, leaving the leaf as
the root.  The right-hand side matches
`Crypto.Spec.merkleVerifyPath HashBackend.sha256 leaf emptyProof index 0`
by `merkleVerifyPath_zero`. -/
theorem runOps_merkleRootSha256Ops_zero_eq
    (leaf emptyProof : ByteArray) (index : Int)
    (rest : List Value) (stkSt : StackState)
    (hStk : stkSt.stack
            = .vBigint index :: .vBytes emptyProof :: .vBytes leaf :: rest) :
    runOps (merkleRootSha256Ops 0) stkSt
    = .ok { stkSt with stack
              := .vBytes (Crypto.Spec.merkleVerifyPath
                            (fun b => RunarVerification.ANF.Eval.Crypto.sha256 b)
                            leaf emptyProof index 0) :: rest } := by
  rw [merkleRootSha256Ops_zero, Crypto.Spec.merkleVerifyPath_zero]
  exact runOps_drop_two (.vBigint index) (.vBytes emptyProof)
          (.vBytes leaf :: rest) stkSt hStk

/-- The corresponding base-case equivalence for the Hash256 variant. -/
theorem runOps_merkleRootHash256Ops_zero_eq
    (leaf emptyProof : ByteArray) (index : Int)
    (rest : List Value) (stkSt : StackState)
    (hStk : stkSt.stack
            = .vBigint index :: .vBytes emptyProof :: .vBytes leaf :: rest) :
    runOps (merkleRootHash256Ops 0) stkSt
    = .ok { stkSt with stack
              := .vBytes (Crypto.Spec.merkleVerifyPath
                            (fun b => RunarVerification.ANF.Eval.Crypto.hash256 b)
                            leaf emptyProof index 0) :: rest } := by
  rw [merkleRootHash256Ops_zero, Crypto.Spec.merkleVerifyPath_zero]
  exact runOps_drop_two (.vBigint index) (.vBytes emptyProof)
          (.vBytes leaf :: rest) stkSt hStk

end Merkle
end RunarVerification.Stack

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

/-! ## Phase B7 — operational step lemmas for `mLevel`

The inductive step proof needs per-opcode reductions of `stepNonIf` /
`runOpcode` on stacks whose shape matches the trace. Each lemma
below is a small `rfl`-style unfolding pinned to a specific stack
shape — they compose mechanically to give the per-level reduction
in `runOps_mLevel_eq`. Stated in this module rather than in
`Stack.HashOps` because `Stack.HashOps` sits **downstream** of
`Stack.Merkle` in the import graph (`HashOps` imports
`Stack.Lower`, which imports `Stack.Merkle`). -/

private theorem mlevel_stepNonIf_swap
    (s : StackState) (a b : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: rest) :
    stepNonIf .swap s = .ok { s with stack := b :: a :: rest } := by
  show applySwap s = _
  unfold applySwap
  rw [hStk]

private theorem mlevel_stepNonIf_dup
    (s : StackState) (v : Value) (rest : List Value)
    (hStk : s.stack = v :: rest) :
    stepNonIf .dup s = .ok { s with stack := v :: v :: rest } := by
  show applyDup s = _
  unfold applyDup
  rw [hStk]
  show Except.ok (s.push v) = _
  unfold StackState.push
  rw [hStk]

private theorem mlevel_stepNonIf_rot
    (s : StackState) (a b c : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: c :: rest) :
    stepNonIf .rot s = .ok { s with stack := c :: a :: b :: rest } := by
  show applyRot s = _
  unfold applyRot
  rw [hStk]

private theorem mlevel_stepNonIf_drop
    (s : StackState) (v : Value) (rest : List Value)
    (hStk : s.stack = v :: rest) :
    stepNonIf .drop s = .ok { s with stack := rest } := by
  show applyDrop s = _
  unfold applyDrop
  rw [hStk]

private theorem mlevel_stepNonIf_toaltstack
    (s : StackState) (v : Value) (rest : List Value)
    (hStk : s.stack = v :: rest) :
    stepNonIf (.opcode "OP_TOALTSTACK") s
    = Except.ok { s with stack := rest, altstack := v :: s.altstack } := by
  show runOpcode "OP_TOALTSTACK" s = _
  unfold runOpcode
  show (match s.pop? with
        | none => Except.error (ANF.Eval.EvalError.unsupported "OP_TOALTSTACK: empty stack")
        | some (v, s') => Except.ok { s' with altstack := v :: s'.altstack }) = _
  unfold StackState.pop?
  rw [hStk]

private theorem mlevel_stepNonIf_fromaltstack
    (s : StackState) (v : Value) (altRest : List Value)
    (hAlt : s.altstack = v :: altRest) :
    stepNonIf (.opcode "OP_FROMALTSTACK") s
    = Except.ok { s with stack := v :: s.stack, altstack := altRest } := by
  show runOpcode "OP_FROMALTSTACK" s = _
  unfold runOpcode
  show (match s.altstack with
        | []      => Except.error (ANF.Eval.EvalError.unsupported "OP_FROMALTSTACK: empty altstack")
        | v :: rs => Except.ok ({ s with altstack := rs }.push v)) = _
  rw [hAlt]
  rfl

/-- Helper: `popN` on a stack of size ≥ 1 returns the top value and the rest. -/
private theorem popN_one_cons
    (s : StackState) (a : Value) (rest : List Value)
    (hStk : s.stack = a :: rest) :
    popN s 1 = Except.ok ([a], { s with stack := rest }) := by
  unfold popN
  unfold StackState.pop?
  rw [hStk]
  rfl

/-- Helper: `popN` on a stack of size ≥ 2 returns the top two values in
pop order and the rest. -/
private theorem popN_two_cons
    (s : StackState) (a b : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: rest) :
    popN s 2 = Except.ok ([a, b], { s with stack := rest }) := by
  unfold popN
  unfold StackState.pop?
  rw [hStk]
  show (match popN ({ s with stack := b :: rest }) 1 with
        | Except.error e => Except.error e
        | Except.ok (vs, s'') => Except.ok (a :: vs, s'')) = _
  rw [popN_one_cons ({ s with stack := b :: rest }) b rest rfl]

/-- `OP_SPLIT` with non-negative `idx ≤ bs.size`: pops idx (top) and bs,
pushes the prefix `bs.extract 0 idx`, then the suffix `bs.extract idx
bs.size` (which ends up on top). -/
private theorem mlevel_stepNonIf_split
    (s : StackState) (bs : ByteArray) (idx : Nat) (rest : List Value)
    (hStk : s.stack = .vBigint (Int.ofNat idx) :: .vBytes bs :: rest)
    (hIdx : idx ≤ bs.size) :
    stepNonIf (.opcode "OP_SPLIT") s
    = Except.ok { s with stack := .vBytes (bs.extract idx bs.size)
                            :: .vBytes (bs.extract 0 idx) :: rest } := by
  show runOpcode "OP_SPLIT" s = _
  unfold runOpcode
  show (match popN s 2 with
        | Except.error e => Except.error e
        | Except.ok (vs, s') =>
            match vs with
            | [idx', v] =>
                match asBytes? v, asNonNegativeNat? idx' with
                | some bs', some i' =>
                    if i' > bs'.size then
                      Except.error (ANF.Eval.EvalError.unsupported "OP_SPLIT: index past end")
                    else
                      Except.ok ((s'.push (.vBytes (bs'.extract 0 i'))).push
                        (.vBytes (bs'.extract i' bs'.size)))
                | _, _ => Except.error (ANF.Eval.EvalError.typeError "OP_SPLIT expects bytes and non-negative index")
            | _ => Except.error (ANF.Eval.EvalError.unsupported "OP_SPLIT popN bug")) = _
  rw [popN_two_cons s (.vBigint (Int.ofNat idx)) (.vBytes bs) rest hStk]
  show (if idx > bs.size then
              Except.error (ANF.Eval.EvalError.unsupported "OP_SPLIT: index past end")
            else
              Except.ok ((({ s with stack := rest } : StackState).push (.vBytes (bs.extract 0 idx))).push
                (.vBytes (bs.extract idx bs.size)))) = _
  rw [if_neg (Nat.not_lt_of_le hIdx)]
  unfold StackState.push
  rfl

/-- `OP_MOD` on two bigints: pops top (modulus) and below, pushes
`below % top`. Requires top ≠ 0 to avoid div-by-zero. -/
private theorem mlevel_stepNonIf_mod
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest)
    (hNonZero : b ≠ 0) :
    stepNonIf (.opcode "OP_MOD") s
    = Except.ok { s with stack := .vBigint (a % b) :: rest } := by
  show runOpcode "OP_MOD" s = _
  unfold runOpcode
  show (match popN s 2 with
        | Except.error e => Except.error e
        | Except.ok (vs, s') =>
            match vs with
            | [b', a'] =>
                match asInt? a', asInt? b' with
                | some ai, some bi =>
                    if bi == 0 then Except.error .divByZero else Except.ok (s'.push (.vBigint (ai % bi)))
                | _, _ => Except.error (ANF.Eval.EvalError.typeError "OP_MOD expects ints")
            | _ => Except.error (ANF.Eval.EvalError.unsupported "OP_MOD popN bug")) = _
  rw [popN_two_cons s (.vBigint b) (.vBigint a) rest hStk]
  show (if (b == 0) = true then Except.error ANF.Eval.EvalError.divByZero
        else Except.ok ((({ s with stack := rest } : StackState).push (.vBigint (a % b))))) = _
  rw [if_neg (by simp [hNonZero])]
  unfold StackState.push
  rfl

/-- `OP_2DIV`: pops top bigint, pushes `top / 2`. -/
private theorem mlevel_stepNonIf_2div
    (s : StackState) (a : Int) (rest : List Value)
    (hStk : s.stack = .vBigint a :: rest) :
    stepNonIf (.opcode "OP_2DIV") s
    = Except.ok { s with stack := .vBigint (a / 2) :: rest } := by
  show runOpcode "OP_2DIV" s = _
  unfold runOpcode
  show liftIntUnary s (fun i => .vBigint (i / 2)) = _
  unfold liftIntUnary
  unfold StackState.pop?
  rw [hStk]
  show Except.ok (({ s with stack := rest } : StackState).push (.vBigint (a / 2))) = _
  unfold StackState.push
  rfl

/-- `OP_RSHIFTNUM` on two bigints: pops top (shift) and below (value),
pushes `value / 2^shift`. -/
private theorem mlevel_stepNonIf_rshiftnum
    (s : StackState) (a : Int) (b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    stepNonIf (.opcode "OP_RSHIFTNUM") s
    = Except.ok { s with stack := .vBigint (a / (2 ^ b.toNat)) :: rest } := by
  show runOpcode "OP_RSHIFTNUM" s = _
  unfold runOpcode
  show liftIntBin s (fun a b => .vBigint (a / (2 ^ b.toNat))) = _
  unfold liftIntBin
  rw [popN_two_cons s (.vBigint b) (.vBigint a) rest hStk]
  show Except.ok (({ s with stack := rest } : StackState).push
        (.vBigint (a / (2 ^ b.toNat)))) = _
  unfold StackState.push
  rfl

/-- `OP_CAT`: pops top (bytes b) and below (bytes a), pushes `a ++ b`. -/
private theorem mlevel_stepNonIf_cat
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    stepNonIf (.opcode "OP_CAT") s
    = Except.ok { s with stack := .vBytes (a ++ b) :: rest } := by
  show runOpcode "OP_CAT" s = _
  unfold runOpcode
  show liftBytesBin s (fun a b => .vBytes (a ++ b)) = _
  unfold liftBytesBin
  rw [popN_two_cons s (.vBytes b) (.vBytes a) rest hStk]
  show Except.ok (({ s with stack := rest } : StackState).push (.vBytes (a ++ b))) = _
  unfold StackState.push
  rfl

/-- Generic single hash opcode (SHA256 / HASH256): pops top bytes,
applies the appropriate backend, pushes the digest. -/
private theorem mlevel_stepNonIf_sha256
    (s : StackState) (a : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes a :: rest) :
    stepNonIf (.opcode "OP_SHA256") s
    = Except.ok { s with stack := .vBytes (ANF.Eval.Crypto.sha256 a) :: rest } := by
  show runOpcode "OP_SHA256" s = _
  unfold runOpcode
  show liftBytesUnary s (fun b => .vBytes (ANF.Eval.Crypto.sha256 b)) = _
  unfold liftBytesUnary
  unfold StackState.pop?
  rw [hStk]
  show Except.ok (({ s with stack := rest } : StackState).push
        (.vBytes (ANF.Eval.Crypto.sha256 a))) = _
  unfold StackState.push
  rfl

private theorem mlevel_stepNonIf_hash256
    (s : StackState) (a : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes a :: rest) :
    stepNonIf (.opcode "OP_HASH256") s
    = Except.ok { s with stack := .vBytes (ANF.Eval.Crypto.hash256 a) :: rest } := by
  show runOpcode "OP_HASH256" s = _
  unfold runOpcode
  show liftBytesUnary s (fun b => .vBytes (ANF.Eval.Crypto.hash256 b)) = _
  unfold liftBytesUnary
  unfold StackState.pop?
  rw [hStk]
  show Except.ok (({ s with stack := rest } : StackState).push
        (.vBytes (ANF.Eval.Crypto.hash256 a))) = _
  unfold StackState.push
  rfl

/-! ### Chained cons-step helper. -/

/-- Reduce a `runOps (op :: rest)` cons by one non-`.ifOp` step,
threading `stepNonIf op s = .ok t` forward. -/
private theorem mlevel_cons_step
    (op : StackOp) (rest : List StackOp) (s t : StackState)
    (hNotIf : ∀ thn els, op ≠ .ifOp thn els)
    (hStep : stepNonIf op s = .ok t) :
    runOps (op :: rest) s = runOps rest t := by
  rw [runOps_cons_nonIf_eq op rest s hNotIf, hStep]

/-! ### `mShiftBits` reduction.

After the first 6 steps of `mLevel`, the stack is
`[.vBigint index, .vBigint index, .vBytes sibling, .vBytes current, ...rest]`
(top = `index`).  The shift sub-sequence `mShiftBits i` produces
`[.vBigint (index / 2^i), .vBigint index, .vBytes sibling, .vBytes current, ...rest]`
regardless of `i`.  We prove this uniformly via case analysis on `i`. -/

private theorem runOps_mShiftBits_eq
    (s : StackState) (index : Int) (sibling current : ByteArray)
    (rest : List Value) (rest_ops : List StackOp) (i : Nat)
    (hStk : s.stack = .vBigint index :: .vBigint index
                      :: .vBytes sibling :: .vBytes current :: rest) :
    runOps (mShiftBits i ++ rest_ops) s
    = runOps rest_ops { s with stack := .vBigint (index / (2 ^ i))
                              :: .vBigint index
                              :: .vBytes sibling
                              :: .vBytes current :: rest } := by
  cases i with
  | zero =>
      -- mShiftBits 0 = [].  index / 2^0 = index / 1 = index.
      show runOps ([] ++ rest_ops) s = _
      rw [List.nil_append]
      have hDiv : index / (2 ^ 0) = index := by
        show index / 1 = index
        exact Int.ediv_one index
      rw [hDiv]
      have hSelf : s = { s with stack := .vBigint index :: .vBigint index
                              :: .vBytes sibling :: .vBytes current :: rest } := by
        rw [← hStk]
      exact congrArg (runOps rest_ops) hSelf
  | succ n =>
      cases n with
      | zero =>
          -- mShiftBits 1 = [OP_2DIV].
          show runOps (mShiftBits 1 ++ rest_ops) s = _
          unfold mShiftBits mOpc
          rw [List.singleton_append]
          rw [mlevel_cons_step (.opcode "OP_2DIV") rest_ops s
                { s with stack := .vBigint (index / 2) :: .vBigint index
                                  :: .vBytes sibling :: .vBytes current :: rest }
                (fun _ _ h => StackOp.noConfusion h)
                (mlevel_stepNonIf_2div s index
                  (.vBigint index :: .vBytes sibling :: .vBytes current :: rest) hStk)]
          -- 2 ^ 1 = 2 def-equal.
          show runOps rest_ops _ = runOps rest_ops _
          rfl
      | succ m =>
          -- mShiftBits (m+2) = [push (m+2), OP_RSHIFTNUM].
          show runOps (mShiftBits (m + 2) ++ rest_ops) s = _
          unfold mShiftBits mPushI mOpc
          rw [List.cons_append, List.singleton_append]
          show runOps (.push (.bigint (Int.ofNat (m + 2))) :: .opcode "OP_RSHIFTNUM" :: rest_ops) s
                = _
          -- Step 1: push (m+2).
          rw [mlevel_cons_step (.push (.bigint (Int.ofNat (m + 2))))
                (.opcode "OP_RSHIFTNUM" :: rest_ops) s
                (s.push (.vBigint (Int.ofNat (m + 2))))
                (fun _ _ h => StackOp.noConfusion h)
                rfl]
          -- After push, stack is [(m+2), index, index, sibling, current, ...].
          have hStk2 : (s.push (.vBigint (Int.ofNat (m + 2)))).stack
              = .vBigint (Int.ofNat (m + 2)) :: .vBigint index
                :: .vBigint index :: .vBytes sibling :: .vBytes current :: rest := by
            unfold StackState.push
            rw [hStk]
          -- Step 2: OP_RSHIFTNUM.
          rw [mlevel_cons_step (.opcode "OP_RSHIFTNUM") rest_ops
                (s.push (.vBigint (Int.ofNat (m + 2))))
                { (s.push (.vBigint (Int.ofNat (m + 2)))) with
                    stack := .vBigint (index / (2 ^ (Int.ofNat (m + 2)).toNat))
                            :: .vBigint index
                            :: .vBytes sibling :: .vBytes current :: rest }
                (fun _ _ h => StackOp.noConfusion h)
                (mlevel_stepNonIf_rshiftnum (s.push (.vBigint (Int.ofNat (m + 2))))
                  index (Int.ofNat (m + 2))
                  (.vBigint index :: .vBytes sibling :: .vBytes current :: rest)
                  hStk2)]
          -- (Int.ofNat (m+2)).toNat = m + 2.
          have hToNat : (Int.ofNat (m + 2)).toNat = m + 2 := rfl
          rw [hToNat]
          show runOps rest_ops _ = runOps rest_ops _
          rfl

/-! ### Scaffolding for the inductive step (Phase B7).

The per-opcode reduction lemmas above are the operational building
blocks for `runOps (mLevel i hashOp) s`, the codegen-to-spec
equivalence for one Merkle climb level. Once landed, level `i`'s
discharge is:

```
runOps (mLevel i "OP_SHA256" ++ rest_ops) s
  = runOps rest_ops
      (s with stack := vBigint index :: vBytes (proof.extract 32 size)
                       :: vBytes (sha256 combined) :: rest)
where combined =
    if (index / 2^i) % 2 = 0 then current ++ sibling else sibling ++ current,
  sibling = proof.extract 0 32.
```

Composing `runOps_append` over `mAllLevelsAux hashOp 0 d` then yields
`runOps (mAllLevelsAux ...) s = runOps [] (...path-verifier state...)`,
and the cleanup tail `[.drop, .drop]` finishes via `runOps_drop_two`.

**Status (Phase B7 attempt 2, 2026-05-17).** The per-opcode helpers
(swap / dup / rot / drop / OP_TOALTSTACK / OP_FROMALTSTACK / OP_SPLIT
/ OP_MOD / OP_2DIV / OP_RSHIFTNUM / OP_CAT / OP_SHA256 / OP_HASH256)
and the uniform `mShiftBits i` reduction land green. Composing them
into the full per-level lemma is mechanical but long (~150 lines per
level proof × case-split on direction bit through the inner `.ifOp`).
The composition itself is deferred to a follow-up phase. -/

end Merkle
end RunarVerification.Stack

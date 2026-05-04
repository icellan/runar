import RunarVerification.Stack.Syntax

/-!
# BLAKE3 codegen — Phase 4 (port of `packages/runar-compiler/src/passes/blake3-codegen.ts`)

Mirrors the TypeScript reference one-to-one:

* `b3CompressOps` — full compression-function StackOp list
  (TS `generateCompressOps` at `blake3-codegen.ts:260-388`).
  Stack on entry: `[..., chainingValue(32 BE), block(64 BE)]`.
  Stack on exit:  `[..., hash(32 BE)]`.
  Net depth: -1.
* `b3HashOps` — single-block hash entry point
  (TS `emitBlake3Hash` at `blake3-codegen.ts:418-447`).
  Stack on entry: `[..., message(≤ 64 bytes BE)]`.
  Stack on exit:  `[..., hash(32 BE)]`.
  Net depth: 0.

The TypeScript Emitter tracks main- and alt-stack depth at codegen time,
emitting `pushI(BigInt(d))` + a `pick`/`roll` op pair for non-trivial
depths. Lean's `StackOp.pick d` / `StackOp.roll d` already encode the
depth-push in the `Emit` pass, so a single Lean StackOp corresponds to
a TS `pushI` + `pick`/`roll` pair.

The depth tracking inside the Emitter (the `assert` calls in the TS
reference) is a codegen-time consistency check — it has no effect on
the emitted bytes. We do not replicate it.
-/

namespace RunarVerification.Stack
namespace Blake3

open RunarVerification.Stack

/-! ## Tiny aliases (mirroring `shaPushI`, `shaOpc` in `Stack.Lower`) -/

@[inline] def b3Opc (s : String) : StackOp := .opcode s
@[inline] def b3PushI (n : Int) : StackOp := .push (.bigint n)

/-- Push a 32-bit value as 4 little-endian bytes (TS `pushB(u32ToLE n)`). -/
@[inline] def b3PushU32LE (n : UInt32) : StackOp :=
  let b0 : UInt8 := (n &&& 0xff).toUInt8
  let b1 : UInt8 := ((n >>> 8) &&& 0xff).toUInt8
  let b2 : UInt8 := ((n >>> 16) &&& 0xff).toUInt8
  let b3 : UInt8 := ((n >>> 24) &&& 0xff).toUInt8
  .push (.bytes (ByteArray.mk #[b0, b1, b2, b3]))

/-- Push a 32-bit value as 4 big-endian bytes (TS `pushB(u32ToBE n)`). -/
@[inline] def u32ToBEBytes (n : UInt32) : Array UInt8 :=
  let b0 : UInt8 := ((n >>> 24) &&& 0xff).toUInt8
  let b1 : UInt8 := ((n >>> 16) &&& 0xff).toUInt8
  let b2 : UInt8 := ((n >>> 8) &&& 0xff).toUInt8
  let b3 : UInt8 := (n &&& 0xff).toUInt8
  #[b0, b1, b2, b3]

/-- Emit `pick(d)` per TS Emitter: 0 → dup, 1 → over, else `pickStruct d`.
The TS reference emits a single `pick` opcode (no preceding push at the
StackOp layer); the depth becomes a byte-level push inside `Emit`. We
use `pickStruct` (no-pop) for byte parity with TS. -/
@[inline] def b3Pick (d : Nat) : List StackOp :=
  match d with
  | 0     => [.dup]
  | 1     => [.over]
  | n + 2 => [.pickStruct (n + 2)]

/-- Emit `roll(d)` per TS Emitter: 0 → [], 1 → swap, 2 → rot, else `roll d`. -/
@[inline] def b3Roll (d : Nat) : List StackOp :=
  match d with
  | 0     => []
  | 1     => [.swap]
  | 2     => [.rot]
  | n + 3 => [.roll (n + 3)]

/-! ## Word-level utilities (4-byte LE / BE conversions and arithmetic) -/

/-- Reverse 4 bytes on TOS (LE↔BE). 12 ops. TS `reverseBytes4`. -/
def b3ReverseBytes4 : List StackOp :=
  [ b3PushI 1, b3Opc "OP_SPLIT"
  , b3PushI 1, b3Opc "OP_SPLIT"
  , b3PushI 1, b3Opc "OP_SPLIT"
  , .swap, b3Opc "OP_CAT"
  , .swap, b3Opc "OP_CAT"
  , .swap, b3Opc "OP_CAT" ]

/-- LE → numeric. 3 ops. TS `le2num`. -/
def b3Le2Num : List StackOp :=
  [ .push (.bytes (ByteArray.mk #[0x00]))
  , b3Opc "OP_CAT"
  , b3Opc "OP_BIN2NUM" ]

/-- numeric → 4-byte LE. 5 ops. TS `num2le`. -/
def b3Num2Le : List StackOp :=
  [ b3PushI 5, b3Opc "OP_NUM2BIN"
  , b3PushI 4, b3Opc "OP_SPLIT", .drop ]

/-- ROTR(x, n) on a BE 4-byte value. 7 ops. TS `rotrBE`. -/
def b3RotrBE (n : Nat) : List StackOp :=
  [ .dup
  , b3PushI (Int.ofNat n), b3Opc "OP_RSHIFT"
  , .swap
  , b3PushI (Int.ofNat (32 - n)), b3Opc "OP_LSHIFT"
  , b3Opc "OP_OR" ]

/-- ROTR(x, 16) on LE 4-byte value: swap halves. 4 ops. TS `rotr16_LE`. -/
def b3Rotr16LE : List StackOp :=
  [ b3PushI 2, b3Opc "OP_SPLIT"
  , .swap, b3Opc "OP_CAT" ]

/-- ROTR(x, 8) on LE 4-byte value. 4 ops. TS `rotr8_LE`. -/
def b3Rotr8LE : List StackOp :=
  [ b3PushI 1, b3Opc "OP_SPLIT"
  , .swap, b3Opc "OP_CAT" ]

/-- ROTR(x, n) on LE 4-byte value via LE→BE→rotrBE→BE→LE. 31 ops. -/
def b3RotrLEGeneral (n : Nat) : List StackOp :=
  b3ReverseBytes4 ++ b3RotrBE n ++ b3ReverseBytes4

/-- 32-bit add on LE values. 13 ops. -/
def b3Add32 : List StackOp :=
  b3Le2Num ++ [.swap] ++ b3Le2Num ++ [b3Opc "OP_ADD"] ++ b3Num2Le

/-- Add N LE values: top N converted, summed, packed back. -/
def b3AddNAux : Nat → List StackOp
  | 0     => []
  | n + 1 => [.swap] ++ b3Le2Num ++ [b3Opc "OP_ADD"] ++ b3AddNAux n

def b3AddN (n : Nat) : List StackOp :=
  if n < 2 then []
  else b3Le2Num ++ b3AddNAux (n - 1) ++ b3Num2Le

/-! ### Bulk byte-order conversion -/

/-- Helper: emit `n × (reverseBytes4; TOALT)` then `n × FROMALT`.
TS `beWordsToLE(n)`. -/
def b3BeWordsToLEAux1 : Nat → List StackOp
  | 0     => []
  | n + 1 => b3ReverseBytes4 ++ [b3Opc "OP_TOALTSTACK"] ++ b3BeWordsToLEAux1 n

def b3BeWordsToLEAux2 : Nat → List StackOp
  | 0     => []
  | n + 1 => [b3Opc "OP_FROMALTSTACK"] ++ b3BeWordsToLEAux2 n

def b3BeWordsToLE (n : Nat) : List StackOp :=
  b3BeWordsToLEAux1 n ++ b3BeWordsToLEAux2 n

/-- Repeat (push 4; OP_SPLIT) `n` times. TS `for (i = 0; i < n; i++) split4()`. -/
def b3Split4N : Nat → List StackOp
  | 0     => []
  | n + 1 => [b3PushI 4, b3Opc "OP_SPLIT"] ++ b3Split4N n

/-! ## BLAKE3 constants -/

/-- BLAKE3 IV (8 × 32-bit words). Matches first 8 SHA-256 IV constants. -/
def b3IV : Array UInt32 :=
  #[ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
   , 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]

/-- BLAKE3 message permutation. Index `i` of the next round's message
order is the previous round's `MSG_PERMUTATION[i]`-th word. -/
def b3MsgPermutation : Array Nat :=
  #[ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 ]

/-- Domain-separation flag: `CHUNK_START | CHUNK_END | ROOT = 1 | 2 | 8 = 11`. -/
def b3FullFlags : UInt32 := 11

/-- Compute the message schedule (which message-word index appears at
each position in each of the 7 rounds). Returns `schedule[round][pos]`. -/
def b3ComputeMsgSchedule : Array (Array Nat) := Id.run do
  let mut schedule : Array (Array Nat) := #[]
  let mut current : Array Nat :=
    Array.ofFn (n := 16) (fun i => i.val)
  for _ in [0:7] do
    schedule := schedule.push current
    let mut next : Array Nat := Array.replicate 16 0
    for i in [0:16] do
      next := next.set! i (current[b3MsgPermutation[i]!]!)
    current := next
  pure schedule

/-! ## State tracker (pure model of TS `StateTracker`) -/

/-- `StateTracker` wraps an `Array Int` of length 16 — `positions[i]` is
the depth-from-TOS of state word `v[i]`, or `-1` if it has been
shipped to the alt stack. -/
abbrev StateTracker := Array Int

def b3InitTracker : StateTracker :=
  -- v[0] at depth 15 (deepest), v[15] at depth 0 (TOS).
  Array.ofFn (n := 16) (fun i => 15 - (i.val : Int))

@[inline] def stDepth (t : StateTracker) (i : Nat) : Nat :=
  -- Convert the stored Int (always nonneg here) back to Nat.
  t[i]!.toNat

/-- After rolling word `i` from its current depth `d` to TOS, every
other word with depth in `[0, d)` shifts down by one (i.e. its depth
*from TOS* increases). Word `i` lands at depth 0. -/
def b3OnRollToTop (t : StateTracker) (i : Nat) : StateTracker := Id.run do
  let d : Int := t[i]!
  let mut t := t
  for j in [0:16] do
    if j ≠ i then
      let dj := t[j]!
      if dj ≥ 0 ∧ dj < d then
        t := t.set! j (dj + 1)
  t := t.set! i 0
  pure t

/-! ## G function (quarter-round) -/

/-- Half of the G function. Stack entry: `[a, b, c, d, m]` (m=TOS, 5 items).
Stack exit: `[a', b', c', d']` (d'=TOS, 4 items). Net depth: -1.

Operations:
  a' = a + b + m
  d' = (d ^ a') >>> rotD   (rotation on LE)
  c' = c + d'
  b' = (original_b ^ c') >>> rotB

Mirrors TS `emitHalfG` (`blake3-codegen.ts:118-162`). -/
def b3EmitHalfG (rotD rotB : Nat) : List StackOp :=
  -- Save original b for step 4 (b is at depth 3)
  b3Pick 3 ++ [b3Opc "OP_TOALTSTACK"]
  -- Step 1: a' = a + b + m
  -- Stack: [a, b, c, d, m] — a=4, b=3, c=2, d=1, m=0
  ++ b3Roll 3            -- [a, c, d, m, b]
  ++ b3Roll 4            -- [c, d, m, b, a]
  ++ b3AddN 3            -- [c, d, a']
  -- Step 2: d' = (d ^ a') >>> rotD
  -- Stack: [c, d, a'] — c=2, d=1, a'=0
  ++ [.dup]              -- [c, d, a', a']
  ++ [.rot]              -- [c, a', a', d]
  ++ [b3Opc "OP_XOR"]    -- [c, a', (d^a')]
  ++ (if rotD = 16 then b3Rotr16LE
      else if rotD = 8 then b3Rotr8LE
      else b3RotrLEGeneral rotD)
  -- Step 3: c' = c + d'
  -- Stack: [c, a', d']
  ++ [.dup]              -- [c, a', d', d']
  ++ b3Roll 3            -- [a', d', d', c]
  ++ b3Add32             -- [a', d', c']
  -- Step 4: b' = (original_b ^ c') >>> rotB
  -- Stack: [a', d', c']
  ++ [b3Opc "OP_FROMALTSTACK"]   -- [a', d', c', b]
  ++ [.over]                     -- [a', d', c', b, c']
  ++ [b3Opc "OP_XOR"]            -- [a', d', c', (b^c')]
  ++ b3RotrLEGeneral rotB        -- [a', d', c', b']
  -- Rearrange: [a', d', c', b'] → [a', b', c', d']
  ++ [.swap]                     -- [a', d', b', c']
  ++ [.rot]                      -- [a', b', c', d']

/-- Full G function (quarter-round). Stack entry: `[a, b, c, d, mx, my]`
(my=TOS, 6 items). Stack exit: `[a', b', c', d']` (d'=TOS, 4 items).
Net depth: -2. Mirrors TS `emitG` (`blake3-codegen.ts:170-187`). -/
def b3EmitG : List StackOp :=
  -- Save my to alt for phase 2
  [b3Opc "OP_TOALTSTACK"]               -- [a, b, c, d, mx]
  -- Phase 1: first half with mx, ROTR(16) and ROTR(12)
  ++ b3EmitHalfG 16 12
  -- Restore my for phase 2
  ++ [b3Opc "OP_FROMALTSTACK"]          -- [a', b', c', d', my]
  -- Phase 2: second half with my, ROTR(8) and ROTR(7)
  ++ b3EmitHalfG 8 7

/-! ## G call with state-tracker management -/

/-- One `emitGCall` (TS `blake3-codegen.ts:199-228`):
* Roll each of `[ai, bi, ci, di]` to TOS in sequence (updating tracker).
* Pick `mx` and `my` from the message-word region (16 deep below state).
* Run G (consumes 6, produces 4).
* Snap tracker positions for `[ai, bi, ci, di]` to `[3, 2, 1, 0]`.
-/
def b3EmitGCall
    (t : StateTracker) (ai bi ci di mxIdx myIdx : Nat) :
    (List StackOp × StateTracker) := Id.run do
  let mut t := t
  let mut ops : List StackOp := []
  for idx in [ai, bi, ci, di] do
    ops := ops ++ b3Roll (stDepth t idx)
    t := b3OnRollToTop t idx
  -- Pick the two message words. m[i] sits at depth 16 + (15 - i).
  ops := ops ++ b3Pick (16 + (15 - mxIdx))
  -- After pushing mx, the depth of my shifts up by 1 (so we add +1).
  ops := ops ++ b3Pick (16 + (15 - myIdx) + 1)
  ops := ops ++ b3EmitG
  -- After G: result words at depths [3, 2, 1, 0] for [ai, bi, ci, di].
  t := t.set! ai 3
  t := t.set! bi 2
  t := t.set! ci 1
  t := t.set! di 0
  pure (ops, t)

/-! ## Round emission -/

/-- Emit all 8 G calls for one round (4 column + 4 diagonal).
`s` is the round's message schedule. -/
def b3EmitRound (t : StateTracker) (s : Array Nat) :
    (List StackOp × StateTracker) := Id.run do
  let mut t := t
  let mut ops : List StackOp := []
  -- Column mixing
  let (o1, t1) := b3EmitGCall t  0 4  8 12 s[0]!  s[1]!
  ops := ops ++ o1; t := t1
  let (o2, t2) := b3EmitGCall t  1 5  9 13 s[2]!  s[3]!
  ops := ops ++ o2; t := t2
  let (o3, t3) := b3EmitGCall t  2 6 10 14 s[4]!  s[5]!
  ops := ops ++ o3; t := t3
  let (o4, t4) := b3EmitGCall t  3 7 11 15 s[6]!  s[7]!
  ops := ops ++ o4; t := t4
  -- Diagonal mixing
  let (o5, t5) := b3EmitGCall t  0 5 10 15 s[8]!  s[9]!
  ops := ops ++ o5; t := t5
  let (o6, t6) := b3EmitGCall t  1 6 11 12 s[10]! s[11]!
  ops := ops ++ o6; t := t6
  let (o7, t7) := b3EmitGCall t  2 7  8 13 s[12]! s[13]!
  ops := ops ++ o7; t := t7
  let (o8, t8) := b3EmitGCall t  3 4  9 14 s[14]! s[15]!
  ops := ops ++ o8; t := t8
  pure (ops, t)

/-- Emit all 7 rounds. -/
def b3EmitAllRounds : (List StackOp × StateTracker) := Id.run do
  let schedule := b3ComputeMsgSchedule
  let mut t := b3InitTracker
  let mut ops : List StackOp := []
  for round in [0:7] do
    let s := schedule[round]!
    let (o, t') := b3EmitRound t s
    ops := ops ++ o; t := t'
  pure (ops, t)

/-! ## Phase 4 — canonical reorder using alt stack -/

/-- Mirror TS `blake3-codegen.ts:336-348`. For `i = 15..0`:
* Roll word `i` to TOS.
* TOALTSTACK.
* For all `j ≠ i` with `positions[j] ≥ 0`, decrement (the main stack
  shrunk by one because we shipped a word to alt).
* Set `positions[i] = -1`.

Note: between `roll(d)` and `toAlt`, the tracker had been updated by
`onRollToTop` (which only adjusts deeper neighbours). The post-toAlt
loop bumps **everyone** still on main down by one. -/
def b3CanonicalReorder (t : StateTracker) :
    (List StackOp × StateTracker) := Id.run do
  let mut t := t
  let mut ops : List StackOp := []
  -- i = 15, 14, ..., 0
  for k in [0:16] do
    let i : Nat := 15 - k
    let d : Nat := stDepth t i
    ops := ops ++ b3Roll d
    t := b3OnRollToTop t i
    ops := ops ++ [b3Opc "OP_TOALTSTACK"]
    -- Shift remaining main-stack words down by one (their depth-from-TOS
    -- decreases) and ship word i to alt by setting its position to -1.
    let mut t' := t
    for j in [0:16] do
      if j ≠ i then
        let dj := t'[j]!
        if dj ≥ 0 then
          t' := t'.set! j (dj - 1)
    t' := t'.set! i (-1)
    t := t'
  pure (ops, t)

/-! ## XOR-and-pack output stage (TS `blake3-codegen.ts:357-388`) -/

/-- After canonical reorder, the 16 state words sit on alt in order
`v15, v14, ..., v0` (alt is LIFO; the loop pushed v15 first, so it's at
the bottom). Pop them all to main: 16 × FROMALT. -/
def b3FromAltN : Nat → List StackOp
  | 0     => []
  | n + 1 => [b3Opc "OP_FROMALTSTACK"] ++ b3FromAltN n

/-- For `k = 0..7`, bring `v[7-k]` to TOS via `roll(8-k)` and XOR with
`v[15-k]`, ship result to alt. After 8 iterations, alt holds (bottom→top)
`h7..h0`, and main holds `[m0..m15]`. -/
def b3XorPairsAux : Nat → Nat → List StackOp
  | _, 0     => []
  | k, n + 1 => b3Roll (8 - k) ++ [b3Opc "OP_XOR", b3Opc "OP_TOALTSTACK"]
                ++ b3XorPairsAux (k + 1) n

def b3XorPairs : List StackOp := b3XorPairsAux 0 8

/-- Pack `h0..h7` (main stack, h7 = TOS) into a 32-byte BE result.
TS:
```
em.reverseBytes4();           // h7 → h7_BE
for (i = 1..7) {
  em.swap();
  em.reverseBytes4();
  em.swap();
  em.binOp('OP_CAT');
}
```
-/
def b3PackOutputAux : Nat → List StackOp
  | 0     => []
  | n + 1 => [.swap] ++ b3ReverseBytes4 ++ [.swap, b3Opc "OP_CAT"]
             ++ b3PackOutputAux n

def b3PackOutput : List StackOp :=
  b3ReverseBytes4 ++ b3PackOutputAux 7

/-- Drop 16 message words from below the result. 16 × (swap; drop). -/
def b3DropMessageWords : Nat → List StackOp
  | 0     => []
  | n + 1 => [.swap, .drop] ++ b3DropMessageWords n

/-! ## Full compression op list -/

/-- Compute the IV-LE pushes (i = 0..3): pushB(u32ToLE(IV[i])). -/
def b3IVPushes : List StackOp :=
  [ b3PushU32LE b3IV[0]!
  , b3PushU32LE b3IV[1]!
  , b3PushU32LE b3IV[2]!
  , b3PushU32LE b3IV[3]! ]

/-- Generate the full compression op list. Stack on entry:
`[..., chainingValue(32 BE), block(64 BE)]`. Stack on exit:
`[..., hash(32 BE)]`. Net depth: -1. -/
def b3CompressOps : List StackOp :=
  -- ============================================================
  -- Phase 1: Unpack block into 16 LE message words
  -- ============================================================
  -- Split block (64 BE) into 16 × 4-byte BE words, convert each to LE.
  b3Split4N 15
  ++ b3BeWordsToLE 16
  -- Stack: [CV, m0..m15]   m15=TOS

  -- ============================================================
  -- Phase 2: Initialize 16-word state on top of message words
  -- ============================================================
  -- Move CV to alt (currently at depth 16, below the 16 msg words).
  ++ b3Roll 16
  ++ [b3Opc "OP_TOALTSTACK"]
  -- Stack: [m0..m15]   Alt: [CV]

  -- Get CV back, split into 8 LE words.
  ++ [b3Opc "OP_FROMALTSTACK"]
  ++ b3Split4N 7
  ++ b3BeWordsToLE 8
  -- Stack: [m0..m15, cv0..cv7]   cv7=TOS

  -- v[8..11] = IV[0..3]
  ++ b3IVPushes
  -- v[12] = counter_low = 0
  ++ [b3PushU32LE 0]
  -- v[13] = counter_high = 0
  ++ [b3PushU32LE 0]
  -- v[14] = block_len = 64
  ++ [b3PushU32LE 64]
  -- v[15] = flags = 11
  ++ [b3PushU32LE b3FullFlags]
  -- Stack: [m0..m15, v0..v15]   v15=TOS

  -- ============================================================
  -- Phase 3: 7 rounds of G calls
  -- ============================================================
  ++ (let r := b3EmitAllRounds
      let (rOps, tEnd) := r
      let (reorderOps, _) := b3CanonicalReorder tEnd
      rOps ++ reorderOps ++ b3FromAltN 16)
  -- Stack: [m0..m15, v0..v15]   v15=TOS, all in canonical order

  -- ============================================================
  -- Phase 5: XOR pairs h[i] = v[i] ^ v[i+8] (8 pairs).
  -- ============================================================
  ++ b3XorPairs
  -- Alt now holds h7..h0 bottom-up. Main: [m0..m15].
  ++ b3FromAltN 8
  -- Main: [m0..m15, h0..h7]   h7=TOS

  -- ============================================================
  -- Phase 6: Pack into 32-byte BE result and drop message words.
  -- ============================================================
  ++ b3PackOutput
  ++ b3DropMessageWords 16

/-! ## Single-block hash entry point -/

/-- 32-byte BE BLAKE3 IV (concatenation of `u32ToBE(IV[0..7])`). -/
def b3IVBytes32 : ByteArray :=
  let bs : Array UInt8 :=
    (u32ToBEBytes b3IV[0]!) ++ (u32ToBEBytes b3IV[1]!)
    ++ (u32ToBEBytes b3IV[2]!) ++ (u32ToBEBytes b3IV[3]!)
    ++ (u32ToBEBytes b3IV[4]!) ++ (u32ToBEBytes b3IV[5]!)
    ++ (u32ToBEBytes b3IV[6]!) ++ (u32ToBEBytes b3IV[7]!)
  ByteArray.mk bs

/-- Generate the full single-block hash op list. Stack on entry:
`[..., message]` where message has length ≤ 64. Stack on exit:
`[..., hash(32 BE)]`. Net depth: 0. Mirrors TS `emitBlake3Hash`. -/
def b3HashOps : List StackOp :=
  -- Pad message to 64 bytes by appending `64 - len` zero bytes.
  [ b3Opc "OP_SIZE"             -- [message, len]
  , b3PushI 64
  , .swap
  , b3Opc "OP_SUB"              -- [message, 64-len]
  , b3PushI 0
  , .swap
  , b3Opc "OP_NUM2BIN"          -- [message, zeros]
  , b3Opc "OP_CAT"              -- [paddedMessage(64)]
  -- Push IV as 32-byte BE chaining value, swap to put paddedMessage on top.
  , .push (.bytes b3IVBytes32)
  , .swap ]
  -- Splice compression ops.
  ++ b3CompressOps

end Blake3
end RunarVerification.Stack

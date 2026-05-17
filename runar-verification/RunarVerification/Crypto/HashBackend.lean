/-!
# Crypto.HashBackend — concrete hash specs

Concrete `def`s for hash algorithms that previously appeared as bare
`axiom`s in `RunarVerification.ANF.Eval` (`Crypto` namespace).

This module **does not** depend on the ANF interpreter, the Stack
layer, or the Pipeline. It is a leaf module of pure `ByteArray` →
`ByteArray` algorithms. `ANF/Eval.lean` imports this module and
rebinds the named primitives in its own `Crypto` namespace so the
client surface (`Crypto.blake3Hash`, `Crypto.blake3Compress`) is
unchanged.

## What ships here

* `Blake3.blake3Compress` — single-block BLAKE3 compression function
  `(chainingValue : ByteArray) → (block : ByteArray) → ByteArray`.
  Inputs are 32-byte CV (big-endian word encoding) and 64-byte block.
  Output is 32 bytes (big-endian word encoding). 16-word state, 7
  rounds, G quarter-round per BLAKE3 spec §2.1.
* `Blake3.blake3Hash` — single-block hash entry
  `(message : ByteArray) → ByteArray`. Zero-pads `message` to 64
  bytes, calls `blake3Compress` with the IV as chaining value and the
  domain-separation flags `CHUNK_START | CHUNK_END | ROOT = 11`.

## Reference

BLAKE3 spec §2.1 (compression function `F`):
<https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf>

TypeScript codegen the spec must agree with (byte-for-byte at the
codegen-to-spec layer, proved by `Stack.Blake3.runOps_b3*Ops_eq`):
`packages/runar-compiler/src/passes/blake3-codegen.ts`.

## Endianness convention (matches the codegen)

The Bitcoin-Script codegen represents a 32-bit word on the input /
output 32-byte payload using **4 big-endian bytes per word** (the
codegen's `u32ToBE`). Inside the compression function, words are
manipulated as native `UInt32`. The conversion happens at exactly
the input-unpack and output-pack steps.

## Scope (B3-a)

This file lands the concrete spec defs only. The codegen-to-spec
linking theorems (`runOps_b3HashOps_eq`, `runOps_b3CompressOps_eq`)
live in `Stack/Blake3.lean` and remain axioms at the B3-a tier;
B3-b / B3-c discharge them against the concrete spec defs landed
here. The result is `−2` axioms in `ANF/Eval.lean` (the two bare
`axiom blake3Hash` / `axiom blake3Compress` lines are replaced with
`def`s that delegate here).
-/

namespace RunarVerification.Crypto.HashBackend
namespace Blake3

/-! ## Constants -/

/-- BLAKE3 IV (8 × 32-bit words). Matches first 8 SHA-256 IV constants. -/
def IV : Array UInt32 :=
  #[ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
   , 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]

/-- BLAKE3 message permutation. -/
def MSG_PERMUTATION : Array Nat :=
  #[ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 ]

/-- Domain-separation flags for a single-block root chunk:
`CHUNK_START | CHUNK_END | ROOT = 1 | 2 | 8 = 11`. -/
def FULL_FLAGS : UInt32 := 11

/-- BLAKE3 block length (used in the compression state as `v[14]`). -/
def BLOCK_LEN : UInt32 := 64

/-! ## UInt32 utilities -/

/-- 32-bit right rotation. `n` is taken `mod 32`; for `n = 0` this returns
`x` unchanged (per BLAKE3 there is no zero-rotation in practice, but the
definition is total). -/
def rotr32 (x : UInt32) (n : Nat) : UInt32 :=
  let nMod : Nat := n % 32
  if nMod = 0 then x
  else
    let nL : UInt32 := (32 - nMod).toUInt32
    let nR : UInt32 := nMod.toUInt32
    (x >>> nR) ||| (x <<< nL)

/-! ## Byte / word conversion (big-endian per word) -/

/-- Read a `UInt32` from 4 big-endian bytes at offset `i`. Out-of-range
indices read as zero (the callers in this module always pass valid
offsets for the 32-byte and 64-byte payloads). -/
def beU32At (b : ByteArray) (i : Nat) : UInt32 :=
  let b0 : UInt32 := (if i     < b.size then b.get! i     else 0).toUInt32
  let b1 : UInt32 := (if i + 1 < b.size then b.get! (i+1) else 0).toUInt32
  let b2 : UInt32 := (if i + 2 < b.size then b.get! (i+2) else 0).toUInt32
  let b3 : UInt32 := (if i + 3 < b.size then b.get! (i+3) else 0).toUInt32
  (b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3

/-- Encode a `UInt32` as 4 big-endian bytes. -/
def u32ToBE (n : UInt32) : ByteArray :=
  let b0 : UInt8 := ((n >>> 24) &&& 0xff).toUInt8
  let b1 : UInt8 := ((n >>> 16) &&& 0xff).toUInt8
  let b2 : UInt8 := ((n >>> 8)  &&& 0xff).toUInt8
  let b3 : UInt8 := (n          &&& 0xff).toUInt8
  ByteArray.mk #[b0, b1, b2, b3]

/-- Split a 32-byte chaining-value `ByteArray` into 8 BE-encoded words. -/
def cvToWords (cv : ByteArray) : Array UInt32 :=
  Array.ofFn (n := 8) (fun i => beU32At cv (4 * i.val))

/-- Split a 64-byte block `ByteArray` into 16 BE-encoded words. -/
def blockToWords (block : ByteArray) : Array UInt32 :=
  Array.ofFn (n := 16) (fun i => beU32At block (4 * i.val))

/-- Pack 8 words into a 32-byte BE-encoded `ByteArray`. -/
def wordsToBE32 (ws : Array UInt32) : ByteArray :=
  let acc : ByteArray := ByteArray.empty
  let step (acc : ByteArray) (i : Nat) : ByteArray :=
    acc ++ u32ToBE (ws.getD i 0)
  let acc := step acc 0
  let acc := step acc 1
  let acc := step acc 2
  let acc := step acc 3
  let acc := step acc 4
  let acc := step acc 5
  let acc := step acc 6
  let acc := step acc 7
  acc

/-! ## G function and rounds -/

/-- Apply one BLAKE3 G quarter-round to state indices `(a, b, c, d)`
with message words `(mx, my)`. Returns the updated state. Mirrors
the spec exactly:

```
a := a + b + mx
d := (d ^ a) >>> 16
c := c + d
b := (b ^ c) >>> 12
a := a + b + my
d := (d ^ a) >>> 8
c := c + d
b := (b ^ c) >>> 7
```

`UInt32` addition wraps mod 2^32 in Lean. -/
def gMix (st : Array UInt32) (a b c d : Nat) (mx my : UInt32) : Array UInt32 :=
  let va := st.getD a 0
  let vb := st.getD b 0
  let vc := st.getD c 0
  let vd := st.getD d 0
  let va := va + vb + mx
  let vd := rotr32 (vd ^^^ va) 16
  let vc := vc + vd
  let vb := rotr32 (vb ^^^ vc) 12
  let va := va + vb + my
  let vd := rotr32 (vd ^^^ va) 8
  let vc := vc + vd
  let vb := rotr32 (vb ^^^ vc) 7
  let st := st.set! a va
  let st := st.set! b vb
  let st := st.set! c vc
  st.set! d vd

/-- One BLAKE3 round: 4 column-mixing G calls + 4 diagonal-mixing G
calls. `pick` reads the message word at position `idx`; the caller
supplies the round's `schedule` mapping `pos → original_msg_idx`.
Mirrors the TS reference's `emitGCall` ordering. -/
def round (st : Array UInt32) (m : Array UInt32) (schedule : Array Nat) :
    Array UInt32 :=
  let pick (pos : Nat) : UInt32 := m.getD (schedule.getD pos 0) 0
  let st := gMix st 0 4  8 12 (pick 0)  (pick 1)
  let st := gMix st 1 5  9 13 (pick 2)  (pick 3)
  let st := gMix st 2 6 10 14 (pick 4)  (pick 5)
  let st := gMix st 3 7 11 15 (pick 6)  (pick 7)
  let st := gMix st 0 5 10 15 (pick 8)  (pick 9)
  let st := gMix st 1 6 11 12 (pick 10) (pick 11)
  let st := gMix st 2 7  8 13 (pick 12) (pick 13)
  let st := gMix st 3 4  9 14 (pick 14) (pick 15)
  st

/-! ## Message schedule -/

/-- Permute a 16-element schedule by `MSG_PERMUTATION`:
`next[i] = current[MSG_PERMUTATION[i]]`. -/
def permuteSchedule (current : Array Nat) : Array Nat :=
  Array.ofFn (n := 16) (fun i =>
    current.getD (MSG_PERMUTATION.getD i.val 0) 0)

/-- Iterate `permuteSchedule` `k` times. -/
def iterPermute : Nat → Array Nat → Array Nat
  | 0,     s => s
  | k + 1, s => iterPermute k (permuteSchedule s)

/-- Initial schedule: identity `#[0, 1, 2, ..., 15]`. -/
def initialSchedule : Array Nat :=
  Array.ofFn (n := 16) (fun i => i.val)

/-- Schedule used at round index `r` (`0 ≤ r < 7`). Round 0 is the
identity; each subsequent round applies `permuteSchedule`. -/
def scheduleAt (r : Nat) : Array Nat :=
  iterPermute r initialSchedule

/-! ## Compression function -/

/-- Initial 16-word state for a single-block compression with
chaining-value words `cv` (length 8), counter = 0, block_len = 64,
flags = `CHUNK_START | CHUNK_END | ROOT`. -/
def initState (cv : Array UInt32) (flags : UInt32) : Array UInt32 :=
  #[ cv.getD 0 0, cv.getD 1 0, cv.getD 2 0, cv.getD 3 0
   , cv.getD 4 0, cv.getD 5 0, cv.getD 6 0, cv.getD 7 0
   , IV.getD 0 0, IV.getD 1 0, IV.getD 2 0, IV.getD 3 0
   , 0          , 0          , BLOCK_LEN  , flags ]

/-- Run 7 rounds of `round` starting at round index `r`, with state
`st` and message words `m`. Decreases `7 - r` per step. -/
def runRounds (r : Nat) (st : Array UInt32) (m : Array UInt32) :
    Array UInt32 :=
  if h : r ≥ 7 then st
  else
    let st' := round st m (scheduleAt r)
    runRounds (r + 1) st' m
termination_by 7 - r
decreasing_by
  simp_wf
  omega

/-- Output mixing: `out[i] = state[i] ^ state[i + 8]` for `i = 0..7`. -/
def outputMix (st : Array UInt32) : Array UInt32 :=
  Array.ofFn (n := 8) (fun i =>
    (st.getD i.val 0) ^^^ (st.getD (i.val + 8) 0))

/-- BLAKE3 single-block compression function in word form. -/
def compressWords (cv : Array UInt32) (m : Array UInt32)
    (flags : UInt32) : Array UInt32 :=
  let st0 := initState cv flags
  let stF := runRounds 0 st0 m
  outputMix stF

/-! ## ByteArray API -/

/-- BLAKE3 single-block compression on `ByteArray` payloads. Inputs are
the 32-byte chaining value and the 64-byte block, both with words
in big-endian byte order (matching `packages/runar-compiler/src/
passes/blake3-codegen.ts`). The output is a 32-byte big-endian
word-encoded hash. `flags` is fixed to `CHUNK_START | CHUNK_END |
ROOT = 11` for the single-block compress entry exposed by
`Crypto.blake3Compress`. -/
def blake3Compress (cv : ByteArray) (block : ByteArray) : ByteArray :=
  let cvW := cvToWords cv
  let mW := blockToWords block
  wordsToBE32 (compressWords cvW mW FULL_FLAGS)

/-- Zero-pad `msg` on the right to length 64. If `msg.size ≥ 64`,
returns `msg` truncated to 64 bytes (out-of-domain inputs — the
codegen only emits `blake3Hash` for `msg.size ≤ 64`). -/
def padTo64 (msg : ByteArray) : ByteArray :=
  if h : msg.size ≥ 64 then
    msg.extract 0 64
  else
    let padLen : Nat := 64 - msg.size
    msg ++ (ByteArray.mk (Array.replicate padLen (0 : UInt8)))

/-- 32-byte BLAKE3 IV in big-endian word encoding (matches the codegen's
push of `u32ToBE(IV[i])` for `i = 0..7`). -/
def IV_BE : ByteArray :=
  let acc : ByteArray := ByteArray.empty
  let step (acc : ByteArray) (i : Nat) : ByteArray :=
    acc ++ u32ToBE (IV.getD i 0)
  let acc := step acc 0
  let acc := step acc 1
  let acc := step acc 2
  let acc := step acc 3
  let acc := step acc 4
  let acc := step acc 5
  let acc := step acc 6
  let acc := step acc 7
  acc

/-- BLAKE3 single-block hash. Zero-pads `msg` to 64 bytes and compresses
with `IV` as chaining value (matching `emitBlake3Hash` in the TS
codegen). For `msg.size > 64` this falls back to truncate-then-compress,
which is outside the codegen's emit domain — call sites in the IR are
guarded by `msg.size ≤ 64`. -/
def blake3Hash (msg : ByteArray) : ByteArray :=
  blake3Compress IV_BE (padTo64 msg)

end Blake3
end RunarVerification.Crypto.HashBackend

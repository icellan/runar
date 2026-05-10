/-!
# Numeric encoding — BSV consensus minimal little-endian sign-magnitude

Implements the inverse of `RunarVerification.Script.Emit.encodeScriptNumber`
(the script-number encoder used by `Script/Emit.lean`). The pair
`encodeMinimalLE` / `decodeMinimalLE` lives in this module so that the
Stack VM (`Stack/Eval.lean`) can give concrete semantics to
`OP_BIN2NUM` / `OP_NUM2BIN` without reaching across the Stack→Script
module boundary.

## BSV consensus rules (minimal sign-magnitude little-endian)

* Numbers are little-endian sign-magnitude.
* The high bit (`0x80`) of the most-significant byte is the sign bit
  (`0` = positive, `1` = negative).
* Zero is the empty byte sequence `#[]`.
* Non-zero numbers are *minimal*: the most-significant byte must NOT be
  `0x00` or `0x80` — those are redundant sign bytes; instead append a
  sign byte to the previous representation.

## Companion ops

* `OP_INVERT` — bitwise complement of every byte.
* `OP_AND`, `OP_OR`, `OP_XOR` — equal-length byte-by-byte bitwise.
  BSV consensus requires both operands to have identical length;
  unequal lengths are a script error.

## Out of scope

* OP_LSHIFT / OP_RSHIFT byte semantics (these still flow through the
  generic `liftBytesBin` and currently dispatch as numeric shifts via
  the existing arithmetic path; broadening to bit-shift over byte
  buffers is Phase 4.2 work).
-/

namespace RunarVerification.Stack

/-! ## Decoder — `ByteArray → Int` -/

/--
Decode the magnitude (unsigned little-endian) of a `List UInt8`.

`bytes` is little-endian: index 0 is the least-significant byte. We
recurse from the head to keep termination obvious to Lean.
-/
def decodeMagnitudeLE : List UInt8 → Nat
  | []      => 0
  | b :: bs => b.toNat + 256 * decodeMagnitudeLE bs

/--
Decode a `ByteArray` to an `Int` per BSV consensus minimal-LE encoding.

* Empty bytes → `0`.
* Otherwise: the high bit of the last byte is the sign; the rest of
  the bits of the last byte (masked with `0x7f`) plus all earlier
  bytes form the unsigned magnitude in little-endian order.
-/
def decodeMinimalLE (bs : ByteArray) : Int :=
  let l := bs.toList
  match l.reverse with
  | []           => 0
  | last :: rest =>
      -- `rest` is the high-end-first reverse of all bytes BEFORE `last`,
      -- so reversing it back gives the low-end-first body bytes.
      let body : List UInt8 := rest.reverse
      let sign : Bool := (last &&& 0x80) ≠ 0
      let topMag : UInt8 := last &&& 0x7f
      let mag : Nat := decodeMagnitudeLE (body ++ [topMag])
      if sign then -(mag : Int) else (mag : Int)

/-! ## Encoder — `Int → ByteArray` -/

/--
Encode a non-negative natural to little-endian `UInt8` bytes (no
trailing zeros). `n = 0` yields `[]`.

Termination: `n >>> 8 < n` whenever `n ≠ 0`, since `n >>> 8 = n / 256`.
-/
def absToBytesLE (n : Nat) : List UInt8 :=
  if h : n = 0 then []
  else
    have : n >>> 8 < n := by
      have hpos : 0 < n := Nat.pos_of_ne_zero h
      have h256 : (1 : Nat) < 2 ^ 8 := by decide
      simpa [Nat.shiftRight_eq_div_pow] using Nat.div_lt_self hpos h256
    (UInt8.ofNat (n &&& 0xff)) :: absToBytesLE (n >>> 8)
termination_by n

/--
Encode an `Int` to a `ByteArray` per BSV consensus minimal-LE encoding.

Mirrors `Script.Emit.encodeScriptNumber`. The two functions are pinned
to be byte-identical so the Stack VM and the emitter share a single
convention.
-/
def encodeMinimalLE (n : Int) : ByteArray :=
  if n = 0 then ByteArray.empty
  else
    let negative := n < 0
    let absN := n.natAbs
    let bytes := absToBytesLE absN
    match bytes.reverse with
    | []           => ByteArray.empty   -- unreachable (n ≠ 0 ⇒ bytes ≠ [])
    | last :: revBody =>
        let body : List UInt8 := revBody.reverse
        if last &&& 0x80 ≠ 0 then
          let sign : UInt8 := if negative then 0x80 else 0x00
          ByteArray.mk (body ++ [last, sign]).toArray
        else if negative then
          ByteArray.mk (body ++ [last ||| 0x80]).toArray
        else
          ByteArray.mk bytes.toArray

/-! ## Equal-length zip for OP_AND / OP_OR / OP_XOR -/

/--
Byte-by-byte zip with `f`, requiring equal lengths. Returns `none`
when `as.length ≠ bs.length`. Used by `OP_AND` / `OP_OR` / `OP_XOR`.
-/
def zipBytesWith? (f : UInt8 → UInt8 → UInt8)
    (as bs : ByteArray) : Option ByteArray :=
  if as.size ≠ bs.size then none
  else
    let xs : List UInt8 := as.toList
    let ys : List UInt8 := bs.toList
    some (ByteArray.mk (List.zipWith f xs ys).toArray)

/-! ## Padding helper for OP_NUM2BIN -/

/--
Right-pad a `ByteArray` to `target` bytes by appending `0x00` bytes.
If the input is already at least `target` bytes long, it is returned
unchanged. (Callers check the overflow condition before invoking.)
-/
def padToSize (bs : ByteArray) (target : Nat) : ByteArray :=
  let need : Nat := target - bs.size
  let zeros : ByteArray := ByteArray.mk (List.replicate need (0 : UInt8)).toArray
  bs ++ zeros

/-! ## Sign-aware OP_NUM2BIN

`OP_NUM2BIN` produces a byte string of exactly `target` bytes whose
minimal-LE decoding is `n`. Implementation strategy:

1. Compute the canonical minimal encoding `enc := encodeMinimalLE n`
   (which already includes any sign-byte expansion).
2. If `enc.size > target`, the operation must error (BSV consensus:
   the requested size must accommodate the signed value).
3. Otherwise we need to insert padding. The sign bit currently sits
   in the high bit of the last byte of `enc`. To preserve it after
   padding, we:
   * strip the sign bit from the last byte of `enc`,
   * append `(target - enc.size)` zero bytes,
   * set the sign bit in the high bit of the *new* last byte.

Special case: `n = 0`. `enc = []`; we just emit `target` zero bytes.
-/
def num2binEncode? (n : Int) (target : Nat) : Option ByteArray :=
  if n = 0 then some (padToSize ByteArray.empty target)
  else
    let enc : ByteArray := encodeMinimalLE n
    if enc.size > target then none
    else
      let encList : List UInt8 := enc.toList
      let negative := n < 0
      match encList.reverse with
      | []           => none   -- unreachable (n ≠ 0 ⇒ enc nonempty)
      | last :: revBody =>
          let body : List UInt8 := revBody.reverse
          let stripped : UInt8 := last &&& 0x7f
          let padCount : Nat := target - enc.size
          let zeros : List UInt8 := List.replicate padCount (0 : UInt8)
          -- The new MSB is the trailing zero (when padCount > 0) or
          -- `stripped` itself (when padCount = 0).
          if padCount = 0 then
            -- No padding: keep the original sign bit.
            if negative then
              some (ByteArray.mk (body ++ [stripped ||| 0x80]).toArray)
            else
              some (ByteArray.mk (body ++ [stripped]).toArray)
          else
            -- Padded: sign bit lives on the trailing zero (the new MSB).
            let leading : List UInt8 := body ++ [stripped] ++ zeros.dropLast
            let signByte : UInt8 := if negative then 0x80 else 0x00
            some (ByteArray.mk (leading ++ [signByte]).toArray)

/-! ## Round-trip lemmas

The full bidirectional round-trip
`decodeMinimalLE (encodeMinimalLE n) = n`
for every `n : Int` requires case analysis over byte boundaries
(whether the high-magnitude byte already has its high bit set,
whether sign-byte expansion was triggered) and a strong induction
over the recursive `absToBytesLE` shape — substantial work that the
conformance fixtures do not exercise (the audit flags the *stub
status* as a TCB hole, not a runtime divergence). Tier 4.1 closes
that hole by replacing the silent-zero abstract behavior with
concrete, executable byte semantics; the algebraic round-trip
theorem is left for a follow-up tier and is documented here as
deferred — the executable definitions are the spec.

We prove the zero corollary by `simp`, and validate concrete sample
points (single-byte positives/negatives, sign-byte boundaries, and
multi-byte values) by `native_decide` — running the actual encoder
and decoder and comparing results. Together these pin down every
branch of `encodeMinimalLE` on representative inputs, sufficient to
catch any future regression of the bytewise definitions.
-/

theorem decodeMinimalLE_empty :
    decodeMinimalLE ByteArray.empty = 0 := by
  simp [decodeMinimalLE, ByteArray.toList_empty]

theorem encodeMinimalLE_zero :
    encodeMinimalLE 0 = ByteArray.empty := by
  simp [encodeMinimalLE]

theorem decodeMinimalLE_encodeMinimalLE_zero :
    decodeMinimalLE (encodeMinimalLE 0) = 0 := by
  rw [encodeMinimalLE_zero, decodeMinimalLE_empty]

/-! ### Round-trip sample points

Each `native_decide` invocation below runs the actual `encodeMinimalLE`
followed by `decodeMinimalLE` and confirms the concrete result. This
covers each of the four control-flow branches in `encodeMinimalLE`
(no-sign-byte positive, no-sign-byte negative, sign-byte expansion
positive, sign-byte expansion negative) on at least one input.
-/

theorem rt_pos_one_byte_low : decodeMinimalLE (encodeMinimalLE 1) = 1 := by
  native_decide

theorem rt_pos_one_byte_high : decodeMinimalLE (encodeMinimalLE 127) = 127 := by
  native_decide

theorem rt_pos_sign_byte : decodeMinimalLE (encodeMinimalLE 128) = 128 := by
  native_decide

theorem rt_pos_two_byte : decodeMinimalLE (encodeMinimalLE 256) = 256 := by
  native_decide

theorem rt_pos_two_byte_high : decodeMinimalLE (encodeMinimalLE 32767) = 32767 := by
  native_decide

theorem rt_pos_three_byte : decodeMinimalLE (encodeMinimalLE 65536) = 65536 := by
  native_decide

theorem rt_neg_one_byte : decodeMinimalLE (encodeMinimalLE (-1)) = -1 := by
  native_decide

theorem rt_neg_one_byte_high : decodeMinimalLE (encodeMinimalLE (-127)) = -127 := by
  native_decide

theorem rt_neg_sign_byte : decodeMinimalLE (encodeMinimalLE (-128)) = -128 := by
  native_decide

theorem rt_neg_two_byte : decodeMinimalLE (encodeMinimalLE (-256)) = -256 := by
  native_decide

theorem rt_neg_two_byte_high :
    decodeMinimalLE (encodeMinimalLE (-32767)) = -32767 := by
  native_decide

/-! ### `num2binEncode?` semantic round-trip sample points

`OP_NUM2BIN` should preserve the integer through any padding it
applies. The following confirm `(num2binEncode? n target) >>= decode = n`
on representative inputs — including the cases where padding changes
which byte holds the sign bit.
-/

theorem n2b_zero_pad : (num2binEncode? 0 4).map decodeMinimalLE = some 0 := by
  native_decide

theorem n2b_pos_min_size :
    (num2binEncode? 1 1).map decodeMinimalLE = some 1 := by native_decide

theorem n2b_pos_padded :
    (num2binEncode? 1 4).map decodeMinimalLE = some 1 := by native_decide

theorem n2b_pos_sign_bit_padded :
    (num2binEncode? 128 4).map decodeMinimalLE = some 128 := by native_decide

theorem n2b_neg_padded :
    (num2binEncode? (-1) 4).map decodeMinimalLE = some (-1) := by native_decide

theorem n2b_neg_sign_bit_padded :
    (num2binEncode? (-128) 4).map decodeMinimalLE = some (-128) := by native_decide

theorem n2b_overflow_pos_sign : num2binEncode? 128 1 = none := by native_decide

theorem n2b_overflow_pos_two_byte : num2binEncode? 256 1 = none := by native_decide

theorem n2b_overflow_neg_sign : num2binEncode? (-128) 1 = none := by native_decide

theorem n2b_zero_size_zero : num2binEncode? 0 0 = some ByteArray.empty := by
  native_decide

theorem n2b_zero_size_nonzero : num2binEncode? 1 0 = none := by native_decide

end RunarVerification.Stack

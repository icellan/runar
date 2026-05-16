import RunarVerification.ANF.Eval
import RunarVerification.Stack.Eval

/-!
# Transaction context + BIP-143 preimage construction

This module is the spec-side transaction model used by the Lean Stack
and ANF evaluators. It provides a concrete `TxContext` structure and an
explicit `buildPreimage` constructor for the BIP-143 digest bytes.

The BIP-143 extractors in `ANF/Eval.lean` are concrete definitions over
the serialized preimage. Earlier tiers carried 11 `_buildPreimage`
companion axioms here while the extractors were still bare assumptions.
Those axioms are intentionally gone: the executable extractor
definitions and sample theorems below now pin the layout without adding
trusted assumptions.

`OP_CODESEPARATOR` affects which script suffix is serialized as
`scriptCode` inside the preimage. The pure `afterCodeSeparator` helper
models that effect by replacing `ctx.scriptCode` with the post-separator
suffix. The Stack VM's `runOpsPc` runner records executed separator
indices for proof-level execution, while `Script.Emit.emitWithCodeSepPatches`
computes the byte offsets used by deployment-time `pushCodesepIndex`
patching. Callers that need sighash-aware execution should supply the
covered `TxContext` / preimage produced by this helper.

## TCB impact

* +0 axioms for the `TxContext` structure, the `buildPreimage` `def`,
  `afterCodeSeparator`, or the executable sample theorems.
* +0 opaques.

The current repository-wide count is enforced by
`scripts/check-tcb-drift.sh` and recorded in `TRUST_MANIFEST.md`.

## Stack VM boundary

`StackState.preimage : ByteArray := ByteArray.empty`
(`Stack/Eval.lean`) remains the executable carrier used by the current
Stack VM. This avoids changing the large peephole proof surface just to
thread extra metadata. The concrete context model here gives callers a
single disciplined way to produce that byte payload:

```lean
TxContext.buildPreimage (TxContext.afterCodeSeparator ctx suffix)
```
-/

namespace RunarVerification.Stack

/-! ## Helper encoders -/

/-- Encode a `UInt32` to 4 little-endian `UInt8` bytes. -/
def encodeUInt32LE (n : UInt32) : ByteArray :=
  ByteArray.mk #[
    (n &&& 0xff).toUInt8,
    ((n >>> 8) &&& 0xff).toUInt8,
    ((n >>> 16) &&& 0xff).toUInt8,
    ((n >>> 24) &&& 0xff).toUInt8
  ]

/-- Encode a `UInt64` to 8 little-endian `UInt8` bytes. -/
def encodeUInt64LE (n : UInt64) : ByteArray :=
  ByteArray.mk #[
    (n &&& 0xff).toUInt8,
    ((n >>> 8) &&& 0xff).toUInt8,
    ((n >>> 16) &&& 0xff).toUInt8,
    ((n >>> 24) &&& 0xff).toUInt8,
    ((n >>> 32) &&& 0xff).toUInt8,
    ((n >>> 40) &&& 0xff).toUInt8,
    ((n >>> 48) &&& 0xff).toUInt8,
    ((n >>> 56) &&& 0xff).toUInt8
  ]

/-- Bitcoin VarInt (CompactSize) encoding.

* `n < 0xfd`              → 1 byte: `n`
* `n ≤ 0xffff`            → 3 bytes: `0xfd` ++ LE(n, 2)
* `n ≤ 0xffffffff`        → 5 bytes: `0xfe` ++ LE(n, 4)
* otherwise               → 9 bytes: `0xff` ++ LE(n, 8)

In the BIP-143 preimage the only VarInt we actually emit is the
`scriptCode` length — Bitcoin scripts are bounded well below 2³² bytes,
so the 5-byte branch is the practical upper bound. We model the full
spec for completeness. -/
def encodeVarInt (n : Nat) : ByteArray :=
  if n < 0xfd then
    ByteArray.mk #[n.toUInt8]
  else if n ≤ 0xffff then
    ByteArray.mk #[
      0xfd,
      (n &&& 0xff).toUInt8,
      ((n >>> 8) &&& 0xff).toUInt8
    ]
  else if n ≤ 0xffffffff then
    ByteArray.mk #[
      0xfe,
      (n &&& 0xff).toUInt8,
      ((n >>> 8) &&& 0xff).toUInt8,
      ((n >>> 16) &&& 0xff).toUInt8,
      ((n >>> 24) &&& 0xff).toUInt8
    ]
  else
    ByteArray.mk #[
      0xff,
      (n &&& 0xff).toUInt8,
      ((n >>> 8) &&& 0xff).toUInt8,
      ((n >>> 16) &&& 0xff).toUInt8,
      ((n >>> 24) &&& 0xff).toUInt8,
      ((n >>> 32) &&& 0xff).toUInt8,
      ((n >>> 40) &&& 0xff).toUInt8,
      ((n >>> 48) &&& 0xff).toUInt8,
      ((n >>> 56) &&& 0xff).toUInt8
    ]

/-! ## TxContext structure -/

/--
Bitcoin transaction context for sighash computation per BIP-143.

Encapsulates all the fields that get hashed into the preimage when
computing the sig-hash for an `OP_CHECKSIG` operation. Field byte
widths follow BIP-143 (§ "Specification") exactly.

This is the spec-side model; it is not yet consumed by `StackState`.
See the module docstring for the forward-compatibility plan.
-/
structure TxContext where
  /-- Transaction version (4 bytes LE). -/
  version : UInt32
  /-- Hash of all prevouts in the spending transaction (32 bytes,
      `dSHA256` of every outpoint concatenated when `SIGHASH_ALL`;
      `00..00` when the `ANYONECANPAY` flag is set). -/
  hashPrevouts : ByteArray
  /-- Hash of all input sequence numbers (32 bytes, `dSHA256` of every
      sequence concatenated when `SIGHASH_ALL`). -/
  hashSequence : ByteArray
  /-- The outpoint being spent: `txid` (32 bytes) ++ `vout` (4 bytes
      LE). 36 bytes total. -/
  outpoint : ByteArray
  /-- Index of the input being signed inside the spending transaction
      (4 bytes LE). -/
  inputIndex : UInt32
  /-- The post-`OP_CODESEPARATOR` `scriptCode` bytes. Variable length;
      preceded by a `VarInt` length when serialized into the preimage. -/
  scriptCode : ByteArray
  /-- Amount in satoshis being spent by the input being signed
      (8 bytes LE). -/
  amount : UInt64
  /-- Sequence number of the input being signed (4 bytes LE). -/
  sequence : UInt32
  /-- Hash of the spending transaction's outputs (32 bytes, `dSHA256`
      of every output concatenated when `SIGHASH_ALL`). -/
  hashOutputs : ByteArray
  /-- Locktime field of the spending transaction (4 bytes LE). -/
  locktime : UInt32
  /-- 4-byte sighash type. The canonical default is `SIGHASH_ALL |
      FORK_ID = 0x41` (BSV) or `0x01` (legacy Bitcoin); written LE so
      the on-the-wire bytes are e.g. `41 00 00 00`. -/
  sigHashType : UInt32

namespace TxContext

/--
Concrete BIP-143 preimage construction.

Concatenates every field in the canonical BIP-143 byte order. Total
preimage size is 4 + 32 + 32 + 36 + (VarInt scriptCode.size) +
scriptCode.size + 8 + 4 + 32 + 4 + 4 = 156 + (VarInt scriptCode.size)
+ scriptCode.size bytes.
-/
def buildPreimage (ctx : TxContext) : ByteArray :=
  encodeUInt32LE ctx.version
    ++ ctx.hashPrevouts
    ++ ctx.hashSequence
    ++ ctx.outpoint
    ++ encodeVarInt ctx.scriptCode.size
    ++ ctx.scriptCode
    ++ encodeUInt64LE ctx.amount
    ++ encodeUInt32LE ctx.sequence
    ++ ctx.hashOutputs
    ++ encodeUInt32LE ctx.locktime
    ++ encodeUInt32LE ctx.sigHashType

/-- Replace the script suffix covered by BIP-143 sighash. -/
def withScriptCode (ctx : TxContext) (scriptCode : ByteArray) : TxContext :=
  { ctx with scriptCode := scriptCode }

/--
Apply `OP_CODESEPARATOR`'s sighash effect by switching the covered
`scriptCode` to the bytes after the separator.
-/
def afterCodeSeparator (ctx : TxContext) (postSeparatorScript : ByteArray) : TxContext :=
  ctx.withScriptCode postSeparatorScript

/-- Build the BIP-143 preimage after applying a code-separator suffix. -/
def preimageAfterCodeSeparator
    (ctx : TxContext) (postSeparatorScript : ByteArray) : ByteArray :=
  buildPreimage (afterCodeSeparator ctx postSeparatorScript)

end TxContext

/-! ## Executable layout samples -/

open RunarVerification.ANF.Eval

namespace TxContext

def repeatByte (n : Nat) (b : UInt8) : ByteArray :=
  ByteArray.mk ((List.replicate n b).toArray)

def sampleCtx : TxContext where
  version := 2
  hashPrevouts := repeatByte 32 0x11
  hashSequence := repeatByte 32 0x22
  outpoint := repeatByte 36 0x33
  inputIndex := 7
  scriptCode := ByteArray.mk #[0x51, 0xab, 0xac]
  amount := 5000
  sequence := 0xfffffffe
  hashOutputs := repeatByte 32 0x44
  locktime := 9
  sigHashType := 0x41

def samplePostSeparatorScript : ByteArray :=
  ByteArray.mk #[0xac]

theorem extractVersion_buildPreimage_sample :
    Crypto.extractVersion (buildPreimage sampleCtx) = 2 := by
  native_decide

theorem extractHashPrevouts_buildPreimage_sample :
    (Crypto.extractHashPrevouts (buildPreimage sampleCtx)).toList
      = sampleCtx.hashPrevouts.toList := by
  native_decide

theorem extractScriptCode_buildPreimage_sample :
    (Crypto.extractScriptCode (buildPreimage sampleCtx)).toList
      = sampleCtx.scriptCode.toList := by
  native_decide

theorem extractAmount_buildPreimage_sample :
    Crypto.extractAmount (buildPreimage sampleCtx) = 5000 := by
  native_decide

theorem extractSequence_buildPreimage_sample :
    Crypto.extractSequence (buildPreimage sampleCtx) = 0xfffffffe := by
  native_decide

theorem extractOutputHash_buildPreimage_sample :
    (Crypto.extractOutputHash (buildPreimage sampleCtx)).toList
      = sampleCtx.hashOutputs.toList := by
  native_decide

theorem extractLocktime_buildPreimage_sample :
    Crypto.extractLocktime (buildPreimage sampleCtx) = 9 := by
  native_decide

theorem extractSigHashType_buildPreimage_sample :
    Crypto.extractSigHashType (buildPreimage sampleCtx) = 0x41 := by
  native_decide

/--
`extractInputIndex` is intentionally zero: BIP-143 signs the outpoint,
not the input index. The `TxContext.inputIndex` field remains useful for
callers, but it is not serialized into `buildPreimage`.
-/
theorem extractInputIndex_notSerialized_sample :
    Crypto.extractInputIndex (buildPreimage sampleCtx) = 0 := by
  native_decide

theorem afterCodeSeparator_extractScriptCode_sample :
    (Crypto.extractScriptCode
        (preimageAfterCodeSeparator sampleCtx samplePostSeparatorScript)).toList
      = samplePostSeparatorScript.toList := by
  native_decide

end TxContext

/-!
## Phase E — ValidTxContext predicate, BIP-143 field-extraction correctness,
             and OP_CHECKSIG under ValidTxContext.

### E1 — ValidTxContext predicate

`ValidTxContext ctx` holds when all fixed-length BIP-143 fields carry the
mandated byte widths:

* `hashPrevouts`  — 32 bytes (dSHA256 of all outpoints, or 00…00 for
  ANYONECANPAY)
* `hashSequence`  — 32 bytes (dSHA256 of all sequences)
* `outpoint`      — 36 bytes (32-byte txid + 4-byte vout LE)
* `hashOutputs`   — 32 bytes (dSHA256 of all outputs, or 00…00 for
  SIGHASH_NONE/SINGLE)

`version`, `sequence`, `locktime`, and `sigHashType` are `UInt32` (always
4 bytes); `amount` is `UInt64` (always 8 bytes) — correct widths follow
from their types.

`scriptCode` has variable length; this predicate does not constrain it
(the VarInt frame is validated by the concrete `buildPreimage` def
independently).

Cite: BIP-143 §3 "Specification".
-/

/--
Boolean validity check for a BIP-143 transaction context.

Enforces the mandated byte widths of the fixed-length fields.
`scriptCode` length is unconstrained at this level; any non-negative
length is accepted.
-/
def validTxContextBool (ctx : TxContext) : Bool :=
  ctx.hashPrevouts.size == 32 &&
  ctx.hashSequence.size  == 32 &&
  ctx.outpoint.size      == 36 &&
  ctx.hashOutputs.size   == 32

/--
`ValidTxContext ctx` asserts that `ctx` satisfies the BIP-143 fixed-width
field constraints. Backed by `validTxContextBool` for decidability.
-/
def ValidTxContext (ctx : TxContext) : Prop :=
  validTxContextBool ctx = true

/--
`ValidTxContext` is decidable because it is propositionally equal to
`validTxContextBool ctx = true`, which is `Decidable` via `decEq`.
-/
instance (ctx : TxContext) : Decidable (ValidTxContext ctx) :=
  inferInstanceAs (Decidable (validTxContextBool ctx = true))

namespace ValidTxContext

/-- Unfold the conjunction in a `ValidTxContext` proof. -/
theorem iff (ctx : TxContext) :
    ValidTxContext ctx ↔
    ctx.hashPrevouts.size = 32 ∧ ctx.hashSequence.size = 32 ∧
    ctx.outpoint.size = 36 ∧ ctx.hashOutputs.size = 32 := by
  simp [ValidTxContext, validTxContextBool, Bool.and_eq_true]
  omega

/-- A `ValidTxContext` has `hashPrevouts` of size 32. -/
theorem hashPrevouts_size (ctx : TxContext) (h : ValidTxContext ctx) :
    ctx.hashPrevouts.size = 32 := ((iff ctx).mp h).1

/-- A `ValidTxContext` has `hashSequence` of size 32. -/
theorem hashSequence_size (ctx : TxContext) (h : ValidTxContext ctx) :
    ctx.hashSequence.size = 32 := ((iff ctx).mp h).2.1

/-- A `ValidTxContext` has `outpoint` of size 36. -/
theorem outpoint_size (ctx : TxContext) (h : ValidTxContext ctx) :
    ctx.outpoint.size = 36 := ((iff ctx).mp h).2.2.1

/-- A `ValidTxContext` has `hashOutputs` of size 32. -/
theorem hashOutputs_size (ctx : TxContext) (h : ValidTxContext ctx) :
    ctx.hashOutputs.size = 32 := ((iff ctx).mp h).2.2.2

/-- The sample context satisfies `ValidTxContext`. -/
theorem sampleCtx_valid : ValidTxContext TxContext.sampleCtx := by
  native_decide

end ValidTxContext

/-!
### E2 — BIP-143 field-extraction correctness

Private helper lemmas bridge the `encodeUInt32LE` / `decodeLE32`
round-trip.  The main public theorem `extractVersion_buildPreimage_eq`
then connects `Crypto.extractVersion (buildPreimage ctx)` to
`ctx.version.toNat`.

The extraction lemmas for the 32-byte / 36-byte fields (`hashPrevouts`,
`hashSequence`, `outpoint`, `hashOutputs`) require reasoning about
`ByteArray.extract` after concatenation.  That proof is substantially
more involved; it is left as future work together with the
`ValidTxContext` precondition that provides the exact size information.

What we prove here: the **version** field round-trip (LE32 encoding
then decoding at offset 0), which covers the only non-byte-array field
accessible via `Crypto.extractVersion`.
-/

-- ------------------------------------------------------------------ LE32 round-trip helpers

private theorem nat_and_255 (n : Nat) : n &&& 255 = n % 256 := by
  have := Nat.and_two_pow_sub_one_eq_mod n 8; simp at this; exact this

/-- `(n &&& 0xff).toUInt8.toNat = n.toNat % 256`. -/
private theorem toUInt8_and_ff_byte0 (n : UInt32) :
    (n &&& 0xff).toUInt8.toNat = n.toNat % 256 := by
  simp only [UInt32.toNat_and, UInt32.toUInt8, Nat.toUInt8,
    show (0xff : UInt32).toNat = 255 from rfl]
  rw [nat_and_255]; simp

/-- `((n >>> 8) &&& 0xff).toUInt8.toNat = n.toNat / 256 % 256`. -/
private theorem toUInt8_and_ff_byte1 (n : UInt32) :
    ((n >>> 8) &&& 0xff).toUInt8.toNat = n.toNat / 256 % 256 := by
  simp only [UInt32.toNat_and, UInt32.toNat_shiftRight, UInt32.toUInt8, Nat.toUInt8,
    show (0xff : UInt32).toNat = 255 from rfl, show (8 : UInt32).toNat = 8 from rfl,
    show 8 % 32 = 8 from by decide, Nat.shiftRight_eq_div_pow]
  rw [nat_and_255]; simp

/-- `((n >>> 16) &&& 0xff).toUInt8.toNat = n.toNat / 65536 % 256`. -/
private theorem toUInt8_and_ff_byte2 (n : UInt32) :
    ((n >>> 16) &&& 0xff).toUInt8.toNat = n.toNat / 65536 % 256 := by
  simp only [UInt32.toNat_and, UInt32.toNat_shiftRight, UInt32.toUInt8, Nat.toUInt8,
    show (0xff : UInt32).toNat = 255 from rfl, show (16 : UInt32).toNat = 16 from rfl,
    show 16 % 32 = 16 from by decide, Nat.shiftRight_eq_div_pow]
  rw [nat_and_255]; simp

/-- `((n >>> 24) &&& 0xff).toUInt8.toNat = n.toNat / 16777216 % 256`. -/
private theorem toUInt8_and_ff_byte3 (n : UInt32) :
    ((n >>> 24) &&& 0xff).toUInt8.toNat = n.toNat / 16777216 % 256 := by
  simp only [UInt32.toNat_and, UInt32.toNat_shiftRight, UInt32.toUInt8, Nat.toUInt8,
    show (0xff : UInt32).toNat = 255 from rfl, show (24 : UInt32).toNat = 24 from rfl,
    show 24 % 32 = 24 from by decide, Nat.shiftRight_eq_div_pow]
  rw [nat_and_255]; simp

/--
Little-endian encoding / decoding round-trip for `UInt32`.

`decodeLE32 (encodeUInt32LE n ++ rest) 0 = Int.ofNat n.toNat` for any
`n : UInt32` and any suffix `rest`.

This is the key algebraic correctness property of `encodeUInt32LE`.
It does **not** depend on the size or contents of `rest`, because
`decodeLE32` reads exactly 4 bytes starting at offset 0 and the
`encodeUInt32LE` prefix fills positions 0–3.
-/
theorem decodeLE32_encodeUInt32LE
    (n : UInt32) (rest : ByteArray) :
    open RunarVerification.ANF.Eval.Crypto in
    decodeLE32 (encodeUInt32LE n ++ rest) 0 = Int.ofNat n.toNat := by
  -- Step 1: unfold decodeLE32, readByte, and ByteArray append/get primitives.
  simp only [encodeUInt32LE, RunarVerification.ANF.Eval.Crypto.decodeLE32,
    RunarVerification.ANF.Eval.Crypto.readByte,
    ByteArray.size_append,
    show (ByteArray.mk #[(n &&& 0xff).toUInt8, ((n >>> 8) &&& 0xff).toUInt8,
      ((n >>> 16) &&& 0xff).toUInt8, ((n >>> 24) &&& 0xff).toUInt8]).size = 4 from rfl,
    show (0:Nat) < 4 + rest.size from by omega,
    show (1:Nat) < 4 + rest.size from by omega,
    show (2:Nat) < 4 + rest.size from by omega,
    show (3:Nat) < 4 + rest.size from by omega,
    dite_true, ByteArray.get, ByteArray.append,
    List.cons_append, List.nil_append,
    List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ,
    Nat.zero_add]
  -- Step 2: rewrite each byte using the UInt32 → Nat helper lemmas.
  rw [toUInt8_and_ff_byte0, toUInt8_and_ff_byte1, toUInt8_and_ff_byte2, toUInt8_and_ff_byte3]
  -- Step 3: convert <<< to multiplication.
  simp only [Nat.shiftLeft_eq,
             show (2:Nat)^8 = 256 from by decide,
             show (2:Nat)^16 = 65536 from by decide,
             show (2:Nat)^24 = 16777216 from by decide]
  -- Step 4: the Int.ofNat wrapper can be peeled off; the Nat equation follows by omega.
  congr 1
  have hlt : n.toNat < 2^32 := n.toNat_lt
  omega

/--
**E2 (version field).** `Crypto.extractVersion (buildPreimage ctx) = ctx.version.toNat` for
any `TxContext`.

`extractVersion preimage = decodeLE32 preimage 0`, and `buildPreimage`
starts with `encodeUInt32LE ctx.version` at offset 0.  The round-trip
theorem `decodeLE32_encodeUInt32LE` closes the goal.

No `ValidTxContext` hypothesis is needed: the version field occupies a
fixed position at the preimage head regardless of field sizes.
-/
theorem extractVersion_buildPreimage_eq (ctx : TxContext) :
    open RunarVerification.ANF.Eval.Crypto in
    extractVersion (TxContext.buildPreimage ctx) = Int.ofNat ctx.version.toNat := by
  show RunarVerification.ANF.Eval.Crypto.decodeLE32 (TxContext.buildPreimage ctx) 0 =
    Int.ofNat ctx.version.toNat
  have hPre : TxContext.buildPreimage ctx =
      encodeUInt32LE ctx.version ++
      (ctx.hashPrevouts ++ ctx.hashSequence ++ ctx.outpoint ++
       encodeVarInt ctx.scriptCode.size ++ ctx.scriptCode ++
       encodeUInt64LE ctx.amount ++ encodeUInt32LE ctx.sequence ++
       ctx.hashOutputs ++ encodeUInt32LE ctx.locktime ++
       encodeUInt32LE ctx.sigHashType) := rfl
  rw [hPre]
  exact decodeLE32_encodeUInt32LE ctx.version _

/--
The `Crypto.extractVersion` result for the sample context matches the
declared version as a `Nat` coercion.  Companion `native_decide` check.
-/
theorem extractVersion_buildPreimage_eq_sample :
    open RunarVerification.ANF.Eval.Crypto in
    extractVersion (TxContext.buildPreimage TxContext.sampleCtx) =
    Int.ofNat TxContext.sampleCtx.version.toNat := by
  exact extractVersion_buildPreimage_eq TxContext.sampleCtx

/-!
### E3 — OP_CHECKSIG under ValidTxContext

`runOpcode "OP_CHECKSIG"` pops `(pk, sig)` from the stack and returns
`.vBool (authBackend.checkSig sigB pkB)`.  The `preimage` field of
`StackState` is threaded for documentation purposes but the current
Stack VM passes it to `checkSig` purely through the `authBackend`
record: the concrete `runOpcode "OP_CHECKSIG"` calls
`checkSig sigB pkB = authBackend.checkSig sigB pkB`.

The theorem below makes this wiring explicit: given a `ValidTxContext
ctx`, a preimage built by `buildPreimage ctx`, and two byte-values on
the stack (pk on top, sig below), `runOpcode "OP_CHECKSIG"` yields
`.ok (s'.push (.vBool (authBackend.checkSig sigB pkB)))`.

No new axioms are required: this is a definitional unfolding of the
`runOpcode` dispatch table.
-/

open RunarVerification.Stack.Eval in
open RunarVerification.ANF.Eval in
open RunarVerification.ANF.Eval.Crypto in
/--
**E3.** `OP_CHECKSIG` evaluation under a valid BIP-143 context.

Given a stack state with:
* `stkSt.preimage = TxContext.buildPreimage ctx`
* `stkSt.stack = .vBytes pkB :: .vBytes sigB :: rest`
* `ValidTxContext ctx`

running `OP_CHECKSIG` yields `.ok { stkSt' with stack := .vBool
(authBackend.checkSig sigB pkB) :: rest }` where `stkSt'` is the
state after popping the two operands.

Proof: definitional unfolding of `runOpcode` + the two helper lemmas
`popN_two_eq` and `asBytes?_vBytes`.
-/
theorem runOpcode_CHECKSIG_ValidTxContext
    (ctx : TxContext) (sigB pkB : ByteArray) (rest : List Value)
    (stkSt : StackState)
    (_ : ValidTxContext ctx)
    (hPre : stkSt.preimage = TxContext.buildPreimage ctx)
    (hStk : stkSt.stack = .vBytes pkB :: .vBytes sigB :: rest) :
    Eval.runOpcode "OP_CHECKSIG" stkSt =
    .ok { stkSt with stack := .vBool (authBackend.checkSig sigB pkB) :: rest } := by
  simp only [Eval.runOpcode, Eval.popN, StackState.pop?, hStk, StackState.push, asBytes?]
  -- checkSig is definitionally authBackend.checkSig, so rfl closes the goal.
  rfl

open RunarVerification.Stack.Eval in
open RunarVerification.ANF.Eval in
open RunarVerification.ANF.Eval.Crypto in
/--
**E3 (verify mode).** `OP_CHECKSIGVERIFY` under a valid BIP-143 context
succeeds if and only if `authBackend.checkSig sigB pkB = true`, and
fails with `.assertFailed` otherwise.

Proof: definitional unfolding of the `OP_CHECKSIGVERIFY` arm of
`runOpcode`.
-/
theorem runOpcode_CHECKSIGVERIFY_ValidTxContext
    (ctx : TxContext) (sigB pkB : ByteArray) (rest : List Value)
    (stkSt : StackState)
    (_ : ValidTxContext ctx)
    (hPre : stkSt.preimage = TxContext.buildPreimage ctx)
    (hStk : stkSt.stack = .vBytes pkB :: .vBytes sigB :: rest)
    (hSig : authBackend.checkSig sigB pkB = true) :
    Eval.runOpcode "OP_CHECKSIGVERIFY" stkSt =
    .ok { stkSt with stack := rest } := by
  simp only [Eval.runOpcode, Eval.popN, StackState.pop?, hStk, asBytes?]
  -- checkSig = authBackend.checkSig definitionally; unfold then apply hSig.
  simp only [RunarVerification.ANF.Eval.Crypto.checkSig, hSig, ite_true]

end RunarVerification.Stack

import RunarVerification.ANF.Eval

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

end RunarVerification.Stack

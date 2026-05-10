import RunarVerification.ANF.Eval

/-!
# Transaction context + BIP-143 preimage construction

Tier 4.3 of the remediation plan grounds the 11 BIP-143 preimage
extractor axioms (`extractVersion`, `extractHashPrevouts`, …,
`extractSigHashType` in `ANF/Eval.lean:287–297`) in a concrete
`TxContext` structure plus an explicit `buildPreimage` constructor.

Each extractor is paired with a `_buildPreimage` companion axiom
asserting that, when the extractor is applied to the preimage produced
by `buildPreimage ctx`, it returns the corresponding field of `ctx`.

## Why companion axioms instead of concrete extractor `def`s

The natural alternative would be to replace each
`axiom extractVersion : ByteArray → Int`
with a concrete byte-offset `def extractVersion`, then prove the
correctness lemma by `rfl` / `simp`. We deliberately do not take that
path in this tier:

* The 11 extractors land in `ANF/Eval.lean` as bare axioms, and the
  `builtinSig` table (Tier 2 item 2.9) plus `Stack/Lower.lean`
  reference them via the same names. Replacing the axioms with `def`s
  is a multi-file refactor that would touch the lowering code and
  every downstream reference site; it is scheduled as Tier 4
  follow-up work, not Tier 4.3.
* The companion-axiom pattern matches `RunarVerification/Crypto/Spec.lean`
  (Tier 5.1, 2026-05-10), which paired the bare crypto axioms with
  `_correct` companions instead of replacing them with concrete
  implementations.
* Keeping the extractors as axioms preserves the option to ground them
  later against a different preimage representation (e.g. a pre-hashed
  digest, or a structured `BIP143Preimage` inductive) without
  re-proving every downstream theorem.

The trust commitment grows by 11 axioms (one per extractor) plus the
`buildPreimage` definition itself — but becomes **specific**: any
future implementation of the 11 extractors must additionally satisfy
the 11 companion axioms, ruling out attacker-controlled
specializations of the form "extract the wrong field" or "always
return 0".

## TCB impact

* +0 axioms for the `TxContext` structure or the `buildPreimage` `def`
  (both are concrete Lean definitions, not axioms).
* +11 companion axioms (one per BIP-143 extractor).
* +0 opaques.

After this module lands, `TRUST_MANIFEST.md`'s axiom count rises from
83 → 94 (83 baseline + 11 BIP-143 companions). The drift script's
`TARGET_AXIOMS` updates correspondingly.

## Forward compatibility with the Stack VM `txCtx` field

`StackState.preimage : ByteArray := ByteArray.empty`
(`Stack/Eval.lean:49`) is the existing carrier for the BIP-143
preimage. The `TxContext` structure introduced here is **the
spec-side model** — it is not yet woven into `StackState`. The
follow-up Tier 4 task is to add an optional `txCtx : Option
TxContext` parallel field (or a discriminated `BIP143Source`) and
have `OP_CHECKSIG` / `OP_CHECKMULTISIG` opt to consume it via
`txCtx.map TxContext.buildPreimage` when present, falling back to
the existing `preimage` field when not. That refactor is scoped
out of Tier 4.3 to keep the spec landing minimal.
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

end TxContext

/-! ## BIP-143 extractor companion axioms

For each of the 11 extractor axioms in
`RunarVerification.ANF.Eval.Crypto`, we pair a `_buildPreimage`
companion asserting that the extractor inverts the corresponding
field of `buildPreimage ctx`.

Together, the bare extractor axiom + the companion form a trust
commitment: any future implementation of the extractor (e.g. via
concrete byte-offset arithmetic over `ByteArray.get`) must satisfy
the companion. The companion rules out the
"specialize-to-zero" / "specialize-to-empty" attacks where an
attacker chooses extractor specializations that ignore the input.
-/

namespace TxContext

open RunarVerification.ANF.Eval

/-- `extractVersion` recovers the 32-bit version field from a BIP-143
preimage built by `buildPreimage`. -/
axiom extractVersion_buildPreimage (ctx : TxContext) :
    Crypto.extractVersion (buildPreimage ctx) = (ctx.version.toNat : Int)

/-- `extractHashPrevouts` recovers the 32-byte `hashPrevouts` field. -/
axiom extractHashPrevouts_buildPreimage (ctx : TxContext) :
    Crypto.extractHashPrevouts (buildPreimage ctx) = ctx.hashPrevouts

/-- `extractHashSequence` recovers the 32-byte `hashSequence` field. -/
axiom extractHashSequence_buildPreimage (ctx : TxContext) :
    Crypto.extractHashSequence (buildPreimage ctx) = ctx.hashSequence

/-- `extractOutpoint` recovers the 36-byte outpoint field. -/
axiom extractOutpoint_buildPreimage (ctx : TxContext) :
    Crypto.extractOutpoint (buildPreimage ctx) = ctx.outpoint

/-- `extractInputIndex` recovers the 32-bit input index. -/
axiom extractInputIndex_buildPreimage (ctx : TxContext) :
    Crypto.extractInputIndex (buildPreimage ctx) = (ctx.inputIndex.toNat : Int)

/-- `extractScriptCode` recovers the variable-length `scriptCode`
field, stripping the leading `VarInt` length prefix. -/
axiom extractScriptCode_buildPreimage (ctx : TxContext) :
    Crypto.extractScriptCode (buildPreimage ctx) = ctx.scriptCode

/-- `extractAmount` recovers the 64-bit amount field. -/
axiom extractAmount_buildPreimage (ctx : TxContext) :
    Crypto.extractAmount (buildPreimage ctx) = (ctx.amount.toNat : Int)

/-- `extractSequence` recovers the 32-bit sequence field. -/
axiom extractSequence_buildPreimage (ctx : TxContext) :
    Crypto.extractSequence (buildPreimage ctx) = (ctx.sequence.toNat : Int)

/-- `extractOutputHash` recovers the 32-byte `hashOutputs` field. -/
axiom extractOutputHash_buildPreimage (ctx : TxContext) :
    Crypto.extractOutputHash (buildPreimage ctx) = ctx.hashOutputs

/-- `extractLocktime` recovers the 32-bit locktime field. -/
axiom extractLocktime_buildPreimage (ctx : TxContext) :
    Crypto.extractLocktime (buildPreimage ctx) = (ctx.locktime.toNat : Int)

/-- `extractSigHashType` recovers the 32-bit sighash type field. -/
axiom extractSigHashType_buildPreimage (ctx : TxContext) :
    Crypto.extractSigHashType (buildPreimage ctx) = (ctx.sigHashType.toNat : Int)

end TxContext

/-! ## Robustness against extractor-specialization attacks

Without the 11 companion axioms above, an attacker controlling the
meaning of the bare extractor axioms could specialize, for example,

```text
  axiom extractVersion_always_zero : ∀ b, Crypto.extractVersion b = 0
```

which would let any future "the lock script verifies the right
version" theorem trivially fail-open on a `ctx.version ≠ 0` context.

The companion forces the extractor to honour the field of `ctx` it is
named for. Combined with `buildPreimage` injectivity (a future Tier 4
lemma — provable from the bijective concatenation structure once the
`encode*LE` helpers are proven invertible), the 11 companions pin
each extractor to its named projection.

Note: `buildPreimage` injectivity is **not** in scope for this tier.
The companion axioms alone suffice to discharge the 11 extractor
axioms relative to a *fixed* `ctx` — which is the use case for every
sighash-aware lemma in the verification surface.
-/

end RunarVerification.Stack

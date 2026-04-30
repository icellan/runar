import RunarVerification.Stack.Syntax

/-!
# WOTS+ codegen — Phase 4 (port of `lowerVerifyWOTS` /
`emitWOTSOneChain` from `packages/runar-compiler/src/passes/05-stack-lower.ts`)

WOTS+ (Winternitz One-Time Signature) verifier with parameters
`w = 16`, `n = 32` (SHA-256), `len = 67` chains
(64 message chains + 3 checksum chains).

Mirrors the TypeScript reference one-to-one.

## Entry / exit shape (the dispatch arm in `Stack.Lower` handles the
arg load via `loadRefLive`; this module owns the body that fires after
the three args sit on top.)

* `wotsBodyOps` — body emitted *after* `[..., msg, sig, pubkey]`.
  After the body: `[..., bool]`. Net depth: -2 (pop 3 args, push bool).

The TS reference uses a stateful `Emitter` (so `bringToTop` mutates a
stack map). The Lean port is purely functional — every `pick`/`roll` is
a single Lean StackOp constructor (which the Emit pass encodes as
`pushI(d)` + opcode), matching the TS Emitter's two-op output.

## Source of truth

* `lowerVerifyWOTS` at `packages/runar-compiler/src/passes/05-stack-lower.ts:4022-4175`
* `emitWOTSOneChain` at `packages/runar-compiler/src/passes/05-stack-lower.ts:3951-4020`
* Cross-validated against `compilers/go/codegen/stack.go:4159-4350`.
-/

namespace RunarVerification.Stack
namespace Wots

open RunarVerification.Stack

/-! ## Tiny aliases (mirroring `b3Opc`, `b3PushI` in `Stack.Blake3`). -/

@[inline] def wOpc (s : String) : StackOp := .opcode s
@[inline] def wPushI (n : Int) : StackOp := .push (.bigint n)

/-- Push a 2-byte ADRS literal `[chainIndex, j]`. -/
@[inline] def wPushAdrs (chainIndex : Nat) (j : Nat) : StackOp :=
  .push (.bytes (ByteArray.mk #[(chainIndex.toUInt8), (j.toUInt8)]))

/-! ## One WOTS+ chain (15 hash steps, RFC 8391 tweakable hashing).

Stack on entry: `[..., pubSeed, sig, csum, endpt, digit]`  (digit = TOS)
Stack on exit:  `[..., pubSeed, sigRest, newCsum, newEndpt]`

Mirrors `emitWOTSOneChain` (TS `05-stack-lower.ts:3951-4020`). The alt
stack is balanced (4 push, 4 pop). -/
def wOneChainSkipBranch : List StackOp :=
  -- digit > 0 branch: just decrement.
  [ wOpc "OP_1SUB" ]

/-- The "hash one step" branch (digit == 0). The address `[chainIndex, j]`
is pushed as a 2-byte literal. -/
def wOneChainHashBranch (chainIndex j : Nat) : List StackOp :=
  [ .swap                                    -- pubSeed digit X
  , wPushI 2, wOpc "OP_PICK"                  -- copy pubSeed from depth 2
  , wPushAdrs chainIndex j                    -- push ADRS [chainIndex, j]
  , wOpc "OP_CAT"                             -- pubSeed || adrs
  , .swap                                     -- bring X to top
  , wOpc "OP_CAT"                             -- pubSeed || adrs || X
  , wOpc "OP_SHA256"                          -- F result
  , .swap                                     -- pubSeed new_X digit(=0)
  ]

/-- One step `j` of the chain loop. -/
def wOneChainStep (chainIndex j : Nat) : List StackOp :=
  [ wOpc "OP_DUP"
  , wOpc "OP_0NOTEQUAL"
  , .ifOp wOneChainSkipBranch (some (wOneChainHashBranch chainIndex j))
  ]

/-- All 15 hash-loop iterations for one chain. -/
def wOneChainSteps (chainIndex : Nat) : List StackOp :=
  let rec go (j : Nat) (acc : List StackOp) : List StackOp :=
    if j ≥ 15 then acc
    else go (j + 1) (acc ++ wOneChainStep chainIndex j)
  termination_by 15 - j
  go 0 []

/-- Full one-chain emission. -/
def wOneChain (chainIndex : Nat) : List StackOp :=
  -- Entry stack: pubSeed sig csum endpt digit
  -- Save steps_copy = 15 - digit to alt
  [ wOpc "OP_DUP"
  , wPushI 15, .swap, wOpc "OP_SUB"
  , wOpc "OP_TOALTSTACK"        -- push#1: steps_copy
  -- Save endpt, csum to alt
  , .swap, wOpc "OP_TOALTSTACK"  -- push#2: endpt
  , .swap, wOpc "OP_TOALTSTACK"  -- push#3: csum
  -- main: pubSeed sig digit
  -- Split 32B sig element
  , .swap                        -- pubSeed digit sig
  , wPushI 32, wOpc "OP_SPLIT"   -- pubSeed digit sigElem sigRest
  , wOpc "OP_TOALTSTACK"         -- push#4: sigRest
  , .swap                        -- pubSeed sigElem digit
  ]
  -- 15-iteration hash loop
  ++ wOneChainSteps chainIndex
  -- Drop digit (now 0)
  ++ [ .drop ]
  -- Restore from alt: sigRest, csum, endpt_acc, steps_copy
  ++ [ wOpc "OP_FROMALTSTACK"  -- pop#4: sigRest
     , wOpc "OP_FROMALTSTACK"  -- pop#3: csum
     , wOpc "OP_FROMALTSTACK"  -- pop#2: endpt_acc
     , wOpc "OP_FROMALTSTACK"  -- pop#1: steps_copy
     -- main b→t: pubSeed endpoint sigRest csum endpt_acc steps_copy
     -- csum += steps_copy
     , .rot
     , wOpc "OP_ADD"
     -- Concat endpoint to endpt_acc
     , .swap
     , wPushI 3, wOpc "OP_ROLL"
     , wOpc "OP_CAT"
     -- main: pubSeed sigRest newCsum newEndptAcc
     ]

/-! ## Per-byte-of-message-hash processing.

For each of the 32 bytes of `msgHash`, emit:
  * Optional split (only when `byteIdx < 31`) to peel off one byte.
  * Convert byte→unsigned-int and split into high/low nibbles.
  * Run two chains (high then low).
-/

/-- Byte preamble: split off byte 0..30 (last byte = 31 has no split). -/
def wByteSplit (byteIdx : Nat) : List StackOp :=
  if byteIdx < 31 then
    [ wPushI 1, wOpc "OP_SPLIT", .swap ]
  else []

/-- Byte→nibble decomposition. After: `[..., high, low]` (low = TOS). -/
def wByteToNibbles : List StackOp :=
  [ wPushI 0
  , wPushI 1, wOpc "OP_NUM2BIN"
  , wOpc "OP_CAT"
  , wOpc "OP_BIN2NUM"
  , wOpc "OP_DUP"
  , wPushI 16, wOpc "OP_DIV"   -- high
  , .swap
  , wPushI 16, wOpc "OP_MOD"   -- low
  ]

/-- Save `low` (and `hashRest`, when non-last byte) to alt. -/
def wSaveLowAndRest (byteIdx : Nat) : List StackOp :=
  if byteIdx < 31 then
    [ wOpc "OP_TOALTSTACK"     -- low → alt
    , .swap
    , wOpc "OP_TOALTSTACK"     -- hashRest → alt
    ]
  else
    [ wOpc "OP_TOALTSTACK"     -- low → alt
    ]

/-- Retrieve `low` (and re-save `hashRest`) before the second chain. -/
def wRetrieveLow (byteIdx : Nat) : List StackOp :=
  if byteIdx < 31 then
    [ wOpc "OP_FROMALTSTACK"   -- hashRest
    , wOpc "OP_FROMALTSTACK"   -- low
    , .swap
    , wOpc "OP_TOALTSTACK"     -- hashRest → alt
    ]
  else
    [ wOpc "OP_FROMALTSTACK"   -- low
    ]

/-- Optional pop of `hashRest` after the low-nibble chain (only when
non-last byte). -/
def wPopHashRest (byteIdx : Nat) : List StackOp :=
  if byteIdx < 31 then [ wOpc "OP_FROMALTSTACK" ] else []

/-- Process one message byte → two chains. -/
def wOneByte (byteIdx : Nat) : List StackOp :=
  wByteSplit byteIdx
  ++ wByteToNibbles
  ++ wSaveLowAndRest byteIdx
  ++ wOneChain (byteIdx * 2)            -- high nibble chain
  ++ wRetrieveLow byteIdx
  ++ wOneChain (byteIdx * 2 + 1)        -- low nibble chain
  ++ wPopHashRest byteIdx

/-- All 32 message bytes (32 × 2 = 64 chains). -/
def wAllMessageBytes : List StackOp :=
  let rec go (byteIdx : Nat) (acc : List StackOp) : List StackOp :=
    if byteIdx ≥ 32 then acc
    else go (byteIdx + 1) (acc ++ wOneByte byteIdx)
  termination_by 32 - byteIdx
  go 0 []

/-! ## Checksum digit processing (chains 64, 65, 66). -/

/-- One checksum chain (`ci ∈ {0, 1, 2}`).
Stack on entry: `[..., pubSeed, sigRest, endptAcc]`
Stack on exit:  `[..., pubSeed, sigRest, newEndptAcc]` -/
def wChecksumChain (ci : Nat) : List StackOp :=
  [ wOpc "OP_TOALTSTACK"          -- endptAcc → alt (temp)
  , wPushI 0                       -- pubSeed sigRest 0
  , wOpc "OP_FROMALTSTACK"        -- pubSeed sigRest 0 endptAcc
  , wOpc "OP_FROMALTSTACK"        -- pubSeed sigRest 0 endptAcc digit
  ]
  ++ wOneChain (64 + ci)
  -- main: pubSeed sigRest dummyCsum newEndptAcc
  ++ [ .swap                         -- pubSeed sigRest newEndptAcc dummyCsum
     , .drop                          -- pubSeed sigRest newEndptAcc
     ]

/-- All 3 checksum chains. -/
def wAllChecksumChains : List StackOp :=
  wChecksumChain 0 ++ wChecksumChain 1 ++ wChecksumChain 2

/-! ## Full body. -/

/-- Body emitted *after* the dispatch arm has loaded `msg`, `sig`,
`pubkey` to the top of the stack (`[..., msg, sig, pubkey]`). The
result is `[..., bool]`. Mirrors `lowerVerifyWOTS` body
(`05-stack-lower.ts:4039-4172`). -/
def wotsBodyOps : List StackOp :=
  -- Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
  [ wPushI 32, wOpc "OP_SPLIT"          -- msg sig pubSeed pkRoot
  , wOpc "OP_TOALTSTACK"                 -- pkRoot → alt
  -- Rearrange: pubSeed at bottom, hash msg
  , wOpc "OP_ROT"                        -- sig pubSeed msg
  , wOpc "OP_ROT"                        -- pubSeed msg sig
  , .swap                                -- pubSeed sig msg
  , wOpc "OP_SHA256"                     -- pubSeed sig msgHash
  -- Canonical layout: pubSeed sig csum=0 endptAcc=empty hashRem
  , .swap                                -- pubSeed msgHash sig
  , wPushI 0                             -- pubSeed msgHash sig 0
  , wOpc "OP_0"                          -- pubSeed msgHash sig 0 empty
  , wPushI 3, wOpc "OP_ROLL"             -- pubSeed sig 0 empty msgHash
  ]
  -- 32 message bytes → 64 chains
  ++ wAllMessageBytes
  -- main: pubSeed sigRest(96B) totalCsum endptAcc  |  alt: pkRoot
  ++ [ .swap ]                            -- pubSeed sigRest endptAcc totalCsum
  -- Compute 3 checksum digits onto alt: d66, d65, d64.
  -- d66 = csum % 16
  ++ [ wOpc "OP_DUP"
     , wPushI 16, wOpc "OP_MOD"
     , wOpc "OP_TOALTSTACK"
     -- d65 = (csum/16) % 16
     , wOpc "OP_DUP"
     , wPushI 16, wOpc "OP_DIV"
     , wPushI 16, wOpc "OP_MOD"
     , wOpc "OP_TOALTSTACK"
     -- d64 = (csum/256) % 16
     , wPushI 256, wOpc "OP_DIV"
     , wPushI 16, wOpc "OP_MOD"
     , wOpc "OP_TOALTSTACK"
     -- main: pubSeed sigRest endptAcc  |  alt: pkRoot, d66, d65, d64
     ]
  -- 3 checksum chains
  ++ wAllChecksumChains
  -- main: pubSeed sigRest(empty) endptAcc  |  alt: pkRoot
  ++ [ .swap, .drop                       -- drop empty sigRest
     -- main: pubSeed endptAcc
     -- Hash concatenated endpoints → computed pkRoot
     , wOpc "OP_SHA256"
     -- Compare to pkRoot from alt
     , wOpc "OP_FROMALTSTACK"
     , wOpc "OP_EQUAL"
     -- main: pubSeed bool — clean up pubSeed
     , .swap, .drop
     -- main: bool
     ]

end Wots
end RunarVerification.Stack

import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Eval
import RunarVerification.Crypto.Spec

/-!
# Rabin signature verifier codegen — Phase B10 (port of
`packages/runar-compiler/src/passes/rabin-codegen.ts` ⇒ `emitVerifyRabinSig`)

Rabin signature verification checks the modular identity
`(sig² + padding) mod pubKey == SHA256(msg)` using a fixed 10-opcode
script body.

Mirrors the TypeScript reference one-to-one. The dispatch arm in
`Stack.Lower` (`lowerVerifyRabinSigOpsLive`) brings the four args to the
top of the stack via `loadRefLive` — yielding the layout
`bottom→top: msg sig padding pubKey` — and then splices the body
defined here.

## Entry / exit shape

* On entry (after the four args have been loaded):
  `bottom→top: ..., msg, sig, padding, pubKey`  (`pubKey` = TOS)
* On exit: `bottom→top: ..., bool`  (`true` on a valid Rabin signature)

The body is the fixed 10-opcode sequence

  `OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL`

## Source of truth

* `emitVerifyRabinSig` at
  `packages/runar-compiler/src/passes/rabin-codegen.ts:37-48`
* `lowerVerifyRabinSig` at
  `packages/runar-compiler/src/passes/05-stack-lower.ts:3992` (dispatcher)
* Cross-validated against `compilers/go`, `compilers/rust`,
  `compilers/python`, `compilers/zig`, `compilers/ruby`, `compilers/java`
  via the conformance suite (`conformance/runner/runner.ts`).
* Lean lowering helper:
  `RunarVerification.Stack.lowerVerifyRabinSigOpsLive` at
  `RunarVerification/Stack/Lower.lean:1171-1198`.
-/

namespace RunarVerification.Stack
namespace Rabin

open RunarVerification.Stack
open RunarVerification.Stack.Lower

/-! ## Tiny aliases (mirroring `wOpc`/`wPushI` in `Stack.Wots`). -/

@[inline] def rOpc (s : String) : StackOp := .opcode s

/-! ## Body opcode sequence

Mirrors the TS `emitVerifyRabinSig` callback sequence exactly
(`rabin-codegen.ts:37-48`). The stack effect of each step (with the
top of the stack on the right) is:

```
entry: msg sig padding pubKey
  OP_SWAP   ⇒ msg sig pubKey padding
  OP_ROT    ⇒ msg pubKey padding sig
  OP_DUP    ⇒ msg pubKey padding sig sig
  OP_MUL    ⇒ msg pubKey padding sig²
  OP_ADD    ⇒ msg pubKey (sig²+padding)
  OP_SWAP   ⇒ msg (sig²+padding) pubKey
  OP_MOD    ⇒ msg ((sig²+padding) mod pubKey)
  OP_SWAP   ⇒ ((sig²+padding) mod pubKey) msg
  OP_SHA256 ⇒ ((sig²+padding) mod pubKey) SHA256(msg)
  OP_EQUAL  ⇒ bool
```
-/

/-- The 10-opcode Rabin verification body emitted *after* the four args
have been loaded by `loadRefLive`. Mirrors the body section of
`Stack.lowerVerifyRabinSigOpsLive` (lines 1184–1195 of
`Stack/Lower.lean`) one-to-one. -/
def rabinBodyOps : List StackOp :=
  [ .swap
  , .rot
  , .dup
  , rOpc "OP_MUL"
  , rOpc "OP_ADD"
  , .swap
  , rOpc "OP_MOD"
  , .swap
  , rOpc "OP_SHA256"
  , rOpc "OP_EQUAL"
  ]

/-! ## Codegen bridge

The lowering helper `lowerVerifyRabinSigOpsLive` emits, in order:
the four `loadRefLive` blocks for `msg / sig / padding / pubKey`,
followed by the body defined above. The theorem below pins the
suffix of the emitted op-list to `rabinBodyOps`, which is the
load-bearing fact for any future `runOps`-level reasoning.
-/

/-- The 10-opcode body emitted by `lowerVerifyRabinSigOpsLive` is
byte-identical to `rabinBodyOps`. The four leading `loadRefLive`
blocks are quotiented out by `arg loaders` — they are pure
ref-loads that vary only with the runtime stack map.

This is provable by `rfl` because both sides are constructed by
the same concrete `++` of literal op lists in `Stack/Lower.lean`. -/
theorem lowerVerifyRabinSigOpsLive_body
    (sm : StackMap) (bn : String) (msg sig padding pubKey : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) :
    (lowerVerifyRabinSigOpsLive sm bn msg sig padding pubKey
        currentIndex lastUses outerProtected).fst
      = (loadRefLive sm msg currentIndex lastUses outerProtected).fst
        ++ (loadRefLive
              (loadRefLive sm msg currentIndex lastUses outerProtected).snd
              sig currentIndex lastUses outerProtected).fst
        ++ (loadRefLive
              (loadRefLive
                (loadRefLive sm msg currentIndex lastUses outerProtected).snd
                sig currentIndex lastUses outerProtected).snd
              padding currentIndex lastUses outerProtected).fst
        ++ (loadRefLive
              (loadRefLive
                (loadRefLive
                  (loadRefLive sm msg currentIndex lastUses outerProtected).snd
                  sig currentIndex lastUses outerProtected).snd
                padding currentIndex lastUses outerProtected).snd
              pubKey currentIndex lastUses outerProtected).fst
        ++ rabinBodyOps := by
  rfl

/-- The body is exactly 10 opcodes long. -/
theorem rabinBodyOps_length : rabinBodyOps.length = 10 := rfl

/-! ## Codegen-to-spec equivalence (axiom)

Running `rabinBodyOps` on a stack whose top four elements are
`msg, sig, padding, pubKey` (bottom→top, `pubKey` = TOS) yields
`Crypto.Spec.verifyRabinSig_spec msg sig padding pubKey` on top of
the stack with the other state components untouched.

This axiom abstracts over the bytes-vs-int representation gap in
`Stack.Eval.runOpcode "OP_EQUAL"`: real Bitcoin Script normalises
the `(sig²+padding) mod pubKey` integer to bytes via the implicit
Script-number → bytes coercion (per `encodeMinimalLE`), which the
big-step `runOps` semantics in `Stack.Eval` does not currently
model. The axiom is the contract `runOps` is asserted to satisfy
once that coercion is incorporated, and it is the load-bearing
fact tying the lowering helper `lowerVerifyRabinSigOpsLive`
(`Stack/Lower.lean:1171-1198`) to the algebraic Rabin equation.

Sited here (rather than in `Crypto/Spec.lean`) to avoid an import
cycle through `Stack.Lower → Stack.Wots → Crypto.Spec`. -/
axiom runOps_rabinBodyOps_eq (msg : ByteArray)
    (sig padding pubKey : Int) (s : Stack.Eval.StackState) :
    Stack.Eval.runOps rabinBodyOps
        { s with stack :=
            .vBigint pubKey
              :: .vBigint padding
              :: .vBigint sig
              :: .vBytes msg
              :: s.stack }
      = .ok { s with stack :=
                .vBool (RunarVerification.Crypto.Spec.verifyRabinSig_spec
                          msg sig padding pubKey) :: s.stack }

end Rabin
end RunarVerification.Stack

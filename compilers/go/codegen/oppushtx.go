package codegen

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// OP_PUSH_TX on-chain signature derivation (BUG-100 fix).
//
// The insecure legacy checkPreimage accepted a witness signature over the real
// spending transaction and checked it against pubkey G, never reading the pushed
// preimage — so the preimage was decoupled from the tx. This derives the ECDSA
// signature FROM the preimage on-chain (s = (hash256(preimage) + r)*kinv mod n,
// fixed nonce k=2, privkey d=1, low-S, minimal DER), so OP_CHECKSIG passes only
// when hash256(preimage) equals the real tx sighash.
//
// The construction compiles to a FIXED byte sequence identical across all seven
// tiers; it is the canonical output of the TypeScript reference
// (packages/runar-compiler/src/passes/oppushtx-codegen.ts, validated end-to-end
// against the BSV interpreter in oppushtx-binding.test.ts). Emitted as a single
// opaque raw_bytes op (peephole barrier). The cross-tier conformance suite
// guards that this constant matches every other tier byte-for-byte.
const checkPreimageBindingHex = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad"

// The frozen binding hex above pushes SIGHASH_ALL|FORKID (0x41) as the DER
// signature's appended sighash byte. That push is `0141` (OP_DATA_1 0x41)
// immediately before the fixed G-pubkey tail below. Issue #123 lets a method
// declare a different mode, which only changes that one appended flag byte —
// byte-for-byte matching the TS reference's emitCheckPreimageBinding(flag),
// where the push is `01<flag>`. All valid (FORKID-required) sighash flags
// (0x41/0x42/0x43/0xc1/0xc2/0xc3) minimal-push as OP_DATA_1 + flag, so the tail
// replacement is exact.
const checkPreimageSighashTail = "7e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad"

// checkPreimageBindingBytesWithFlag returns the binding blob with the appended
// DER sighash flag byte set to sighashFlag. For the default 0x41 the frozen
// constant is returned unchanged (zero cross-tier churn); a non-default flag
// swaps the single `0141` push for `01<flag>`.
func checkPreimageBindingBytesWithFlag(sighashFlag int) []byte {
	h := checkPreimageBindingHex
	if sighashFlag != 0x41 {
		suffix := "0141" + checkPreimageSighashTail
		if !strings.HasSuffix(h, suffix) {
			panic("checkPreimageBindingHex does not end with the expected sighash push + G tail")
		}
		h = strings.TrimSuffix(h, suffix) + fmt.Sprintf("01%02x", sighashFlag&0xff) + checkPreimageSighashTail
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("invalid checkPreimageBindingHex: " + err.Error())
	}
	return b
}

// emitCheckPreimageBinding emits the on-chain preimage binding as one opaque
// raw_bytes op. Net stack effect is 0 (preimage in → preimage out), declared as
// in=1/out=1 so the static analyzer keeps the depth consistent. sighashFlag is
// the declared @sighash mode (0 or 0x41 = default ALL|FORKID).
func (ctx *loweringContext) emitCheckPreimageBinding(sighashFlag int) {
	if sighashFlag == 0 {
		sighashFlag = 0x41
	}
	ctx.emitOp(StackOp{Op: "raw_bytes", RawBytes: checkPreimageBindingBytesWithFlag(sighashFlag), InArity: 1, OutArity: 1})
}

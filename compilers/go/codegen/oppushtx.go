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
// signature FROM the preimage on-chain, so OP_CHECKSIG passes only when
// hash256(preimage) equals the real tx sighash.
//
// Any-S construction: nonce k=1, so R = G and r = Gx needs no k-inverse
// multiply and no sign pad; signing key d = Gx^-1 mod n (C = 1), so r*d == 1 and
// the addend s = z + 1 is a single OP_1ADD. Both variants share the C=1 public
// key 038ff83d...9218 = d*G:
//   - lowS (default): s = lowS((z + 1) mod n) — branchless low-S fixup, canonical
//     s ≤ n/2, accepted under the LOW_S rule (nVersion = 1). 421 bytes.
//   - all: s = z + 1 as-is (no mod-n, no low-S) — 376 bytes; valid only for spends
//     with nVersion != 1, where LOW_S is not enforced.
//
// d being public is not a weakness: the binding never depended on key secrecy,
// only on the signature being derived from the PUSHED preimage on-chain.
//
// Each construction compiles to a FIXED byte sequence identical across all seven
// tiers; it is the canonical output of the TypeScript reference
// (packages/runar-compiler/src/passes/oppushtx-codegen.ts, validated end-to-end
// against the BSV interpreter in oppushtx-binding.test.ts). Emitted as a single
// opaque raw_bytes op (peephole barrier). The cross-tier conformance suite
// guards that these constants match every other tier byte-for-byte.
const checkPreimageBindingHex = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

// checkPreimageBindingAllHex is the compact non-low-S ('all') construction:
// s = z + 1 without the mod-n + low-S fixup. ~45 bytes smaller; valid only for
// spends with nVersion != 0x01000000 (the @bindingVariant all directive).
const checkPreimageBindingAllHex = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

// The frozen binding hexes above push SIGHASH_ALL|FORKID (0x41) as the DER
// signature's appended sighash byte. That push is `0141` (OP_DATA_1 0x41)
// immediately before the fixed pubkey tail below (shared by both variants).
// Issue #123 lets a method declare a different mode, which only changes that one
// appended flag byte — byte-for-byte matching the TS reference's
// emitCheckPreimageBinding(flag), where the push is `01<flag>`. All valid
// (FORKID-required) sighash flags (0x41/0x42/0x43/0xc1/0xc2/0xc3) minimal-push as
// OP_DATA_1 + flag, so the tail replacement is exact.
const checkPreimageSighashTail = "7e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

// checkPreimageBindingBytesWithFlag returns the binding blob for the given
// variant with the appended DER sighash flag byte set to sighashFlag. For the
// default 0x41 the frozen constant is returned unchanged (zero cross-tier churn);
// a non-default flag swaps the single `0141` push for `01<flag>`.
func checkPreimageBindingBytesWithFlag(sighashFlag int, variant string) []byte {
	h := checkPreimageBindingHex
	if variant == "all" {
		h = checkPreimageBindingAllHex
	}
	if sighashFlag != 0x41 {
		suffix := "0141" + checkPreimageSighashTail
		if !strings.HasSuffix(h, suffix) {
			panic("checkPreimageBinding hex does not end with the expected sighash push + pubkey tail")
		}
		h = strings.TrimSuffix(h, suffix) + fmt.Sprintf("01%02x", sighashFlag&0xff) + checkPreimageSighashTail
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("invalid checkPreimageBinding hex: " + err.Error())
	}
	return b
}

// emitCheckPreimageBinding emits the on-chain preimage binding as one opaque
// raw_bytes op. Net stack effect is 0 (preimage in → preimage out), declared as
// in=1/out=1 so the static analyzer keeps the depth consistent. sighashFlag is
// the declared @sighash mode (0 or 0x41 = default ALL|FORKID); variant is the
// declared @bindingVariant ("" or "lowS" = default low-S, "all" = compact non-low-S).
func (ctx *loweringContext) emitCheckPreimageBinding(sighashFlag int, variant string) {
	if sighashFlag == 0 {
		sighashFlag = 0x41
	}
	if variant == "" {
		variant = "lowS"
	}
	ctx.emitOp(StackOp{Op: "raw_bytes", RawBytes: checkPreimageBindingBytesWithFlag(sighashFlag, variant), InArity: 1, OutArity: 1})
}

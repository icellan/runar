package codegen

import "encoding/hex"

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
const checkPreimageBindingHex = "76aa007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c7501007e8121e59e705cb909acaba73cef8c4b8e775cd87cc0956e4045306d7ded41947f04c6009320a1201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f9521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e977b7578937c977620a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7fa07821414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007c8d7c949594826b012080007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c756c01207c947f777682775180527c7e7c7e768277012393518023022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50130527a7e7c7e7c7e01417e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad"

func checkPreimageBindingBytes() []byte {
	b, err := hex.DecodeString(checkPreimageBindingHex)
	if err != nil {
		panic("invalid checkPreimageBindingHex: " + err.Error())
	}
	return b
}

// emitCheckPreimageBinding emits the on-chain preimage binding as one opaque
// raw_bytes op. Net stack effect is 0 (preimage in → preimage out), declared as
// in=1/out=1 so the static analyzer keeps the depth consistent.
func (ctx *loweringContext) emitCheckPreimageBinding() {
	ctx.emitOp(StackOp{Op: "raw_bytes", RawBytes: checkPreimageBindingBytes(), InArity: 1, OutArity: 1})
}

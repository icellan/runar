// Package codegen Rabin signature verification codegen for Bitcoin Script.
//
// EmitVerifyRabinSig: [msg, sig, padding, pubKey] → [bool]
//
// Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
// AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
// The emission is a fixed 15-opcode sequence:
//
//	OP_SWAP
//	OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
//	OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
//
// The caller is responsible for bringing the 4 arguments to the top of the
// stack in argument order (msg sig padding pubKey, pubKey on top) before
// invoking EmitVerifyRabinSig.
package codegen

// RabinPaddingLimit is the exclusive upper bound enforced on-chain for the
// Rabin `padding` parameter. The legitimate signer
// (`packages/runar-go/rabin.go::RabinSign`) produces `padding < 1000`; the
// on-chain bound is 65536 (16-bit) for slack. See `_review/BUG-010-rfc.md`.
const RabinPaddingLimit = int64(65536)

// EmitVerifyRabinSig emits the Rabin signature verification opcode sequence.
//
// Stack on entry (bottom→top): msg sig padding pubKey
// Stack on exit:               bool  (1 = valid, 0 = invalid)
func EmitVerifyRabinSig(emit func(StackOp)) {
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})                       // msg sig pubKey padding
	// BUG-010 padding range check: assert 0 <= padding < 65536.
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})                        // msg sig pubKey padding padding
	emit(StackOp{Op: "opcode", Code: "OP_0"})                          // ... padding padding 0
	emit(StackOp{Op: "push", Value: bigIntPush(RabinPaddingLimit)})    // ... padding padding 0 65536
	emit(StackOp{Op: "opcode", Code: "OP_WITHIN"})                     // ... padding (0<=padding<65536)
	emit(StackOp{Op: "opcode", Code: "OP_VERIFY"})                     // msg sig pubKey padding (abort if false)
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})                        // msg pubKey padding sig
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})                        // msg pubKey padding sig sig
	emit(StackOp{Op: "opcode", Code: "OP_MUL"})                        // msg pubKey padding sig^2
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})                        // msg pubKey (sig^2+padding)
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})                       // msg (sig^2+padding) pubKey
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})                        // msg ((sig^2+padding) mod pubKey)
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})                       // ((sig^2+padding) mod pubKey) msg
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"})                     // ((sig^2+padding) mod pubKey) SHA256(msg)
	emit(StackOp{Op: "opcode", Code: "OP_EQUAL"})                      // bool
}

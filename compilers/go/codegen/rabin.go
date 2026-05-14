// Package codegen Rabin signature verification codegen for Bitcoin Script.
//
// EmitVerifyRabinSig: [msg, sig, padding, pubKey] → [bool]
//
// Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg).
// The emission is a fixed 10-opcode sequence:
//
//	OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
//
// The caller is responsible for bringing the 4 arguments to the top of the
// stack in argument order (msg sig padding pubKey, pubKey on top) before
// invoking EmitVerifyRabinSig.
package codegen

// EmitVerifyRabinSig emits the Rabin signature verification opcode sequence.
//
// Stack on entry (bottom→top): msg sig padding pubKey
// Stack on exit:               bool  (1 = valid, 0 = invalid)
func EmitVerifyRabinSig(emit func(StackOp)) {
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})   // msg sig pubKey padding
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})    // msg pubKey padding sig
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})    // msg pubKey padding sig sig
	emit(StackOp{Op: "opcode", Code: "OP_MUL"})    // msg pubKey padding sig^2
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})    // msg pubKey (sig^2+padding)
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})   // msg (sig^2+padding) pubKey
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})    // msg ((sig^2+padding) mod pubKey)
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})   // ((sig^2+padding) mod pubKey) msg
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"}) // ((sig^2+padding) mod pubKey) SHA256(msg)
	emit(StackOp{Op: "opcode", Code: "OP_EQUAL"})  // bool
}

// Package codegen Rabin signature verification codegen for Bitcoin Script.
//
// EmitVerifyRabinSig: [msg, sig, padding, pubKey] → [bool]
//
// Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg) mod pubKey
// AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010)
// AND sig is in [0, pubKey) — also enforced on-chain (F-368).
// The emission is a fixed 34-op sequence:
//
//	<push 0x00> OP_CAT OP_BIN2NUM                   // pubKey as unsigned (F-144)
//	OP_SWAP
//	<push 0x00> OP_CAT OP_BIN2NUM                   // padding as unsigned (F-144)
//	OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
//	OP_ROT
//	<push 0x00> OP_CAT OP_BIN2NUM                   // sig as unsigned (F-144)
//	OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY      // sig < pubKey (F-368)
//	OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
//	OP_ROT OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM
//	OP_ROT OP_MOD OP_NUMEQUAL                       // digest mod pubKey (F-047)
//
// OPERAND SIGN (F-144): off-chain verifiers read padding (and the native
// Go/Rust/Python/Ruby/Zig layers also sig and pubKey) as UNSIGNED
// little-endian bytes; OP_WITHIN / OP_MUL / OP_MOD read a Script number,
// whose last byte's high bit is the sign. Each operand gets an explicit
// 0x00 sign byte and OP_BIN2NUM, so a raw unsigned push keeps its unsigned
// value and a non-negative Script number is unchanged.
//
// CANONICAL SIGNATURE (F-368): (sig + k*n)^2 = sig^2 (mod n), so without a
// range check sig + n is a malleated re-encoding of an honest spend. sig >= 0
// already holds after the F-144 normalization; the script asserts sig < pubKey
// and aborts otherwise. The second root n - sig remains accepted (inherent to
// Rabin). See packages/runar-compiler/src/passes/rabin-codegen.ts.
//
// ENCODING (BUG-011): the final comparison is NUMERIC, not byte-wise.
// OP_MOD leaves a minimal Script number (33 bytes with a trailing 0x00 sign
// byte whenever the digest's top byte has its high bit set — ~50% of
// messages) while OP_SHA256 pushes exactly 32 raw bytes; a bare OP_EQUAL
// refused ~half of all honest signatures on a real VM. The digest gets an
// explicit 0x00 sign byte (OP_CAT), is collapsed to minimal form
// (OP_BIN2NUM) and compared with OP_NUMEQUAL — which never aborts, keeping
// the any-of-N pattern (false from one key's check, not a script kill) intact.
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
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}}) // F-144: pubKey as unsigned
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	emit(StackOp{Op: "opcode", Code: "OP_SWAP"})                       // msg sig pubKey padding
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}}) // F-144: padding as unsigned
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	// BUG-010 padding range check: assert 0 <= padding < 65536.
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})                        // msg sig pubKey padding padding
	emit(StackOp{Op: "opcode", Code: "OP_0"})                          // ... padding padding 0
	emit(StackOp{Op: "push", Value: bigIntPush(RabinPaddingLimit)})    // ... padding padding 0 65536
	emit(StackOp{Op: "opcode", Code: "OP_WITHIN"})                     // ... padding (0<=padding<65536)
	emit(StackOp{Op: "opcode", Code: "OP_VERIFY"})                     // msg sig pubKey padding (abort if false)
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})                        // msg pubKey padding sig
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}}) // F-144: sig as unsigned
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})                        // F-368: msg pubKey padding sig sig
	emit(StackOp{Op: "push", Value: bigIntPush(3)})                    // ... sig sig 3
	emit(StackOp{Op: "opcode", Code: "OP_PICK"})                       // ... sig sig pubKey
	emit(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})                   // ... sig (sig<pubKey)
	emit(StackOp{Op: "opcode", Code: "OP_VERIFY"})                     // msg pubKey padding sig (abort if sig >= pubKey)
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})                        // msg pubKey padding sig sig
	emit(StackOp{Op: "opcode", Code: "OP_MUL"})                        // msg pubKey padding sig^2
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})                        // msg pubKey (sig^2+padding)
	emit(StackOp{Op: "opcode", Code: "OP_OVER"})                       // msg pubKey (sig^2+padding) pubKey  (F-047: keep pubKey)
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})                        // msg pubKey lhs
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})                        // pubKey lhs msg
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"})                     // pubKey lhs SHA256(msg)
	// BUG-011 digest-encoding normalization: raw 32-byte digest -> minimal
	// non-negative Script number, then numeric compare (see doc comment).
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}}) // ... SHA256(msg) 0x00
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})                        // ... SHA256(msg)||0x00
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})                    // pubKey lhs num(SHA256(msg))
	// F-047: reduce the digest mod pubKey, matching every off-chain verifier.
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})                        // lhs num(SHA256(msg)) pubKey
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})                        // lhs (num(SHA256(msg)) mod pubKey)
	emit(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})                   // bool
}

// WOTS+ (Winternitz One-Time Signature, post-quantum) Bitcoin Script
// codegen for the Rúnar Go stack lowerer.
//
// Splice into LoweringContext in stack.go. All helpers self-contained.
// Entry: lowerVerifyWOTS() -> calls EmitVerifyWOTS().
//
// Parameters: w=16, n=32 (SHA-256), len=67 chains (64 message + 3 checksum).
// pubkey is 64 bytes: pubSeed(32) || pkRoot(32).
//
// Entry stack: [..., msg, sig, pubkey] (pubkey on top).
// Exit stack:  [..., bool] (1 = valid, 0 = invalid).
package codegen

// emitWOTSOneChainOp emits one WOTS+ chain verification.
// Entry stack: pubSeed(bottom) sig csum endpt digit(top)
// Exit stack:  pubSeed(bottom) sigRest newCsum newEndpt
func emitWOTSOneChainOp(emit func(StackOp), chainIndex int) {
	// Entry stack: pubSeed(bottom) sig csum endpt digit(top)
	// Save steps_copy = 15 - digit to alt (for checksum accumulation later)
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(15)})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#1: steps_copy

	// Save endpt, csum to alt. Leave pubSeed+sig+digit on main.
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#2: endpt
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#3: csum
	// main: pubSeed sig digit

	// Split 32B sig element
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#4: sigRest
	emit(StackOp{Op: "swap"})
	// main: pubSeed sigElem digit

	// Hash loop: skip first `digit` iterations, then apply F for the rest.
	// When digit > 0: decrement (skip). When digit == 0: hash at step j.
	// Stack: pubSeed(depth2) sigElem(depth1) digit(depth0=top)
	for j := 0; j < 15; j++ {
		adrsBytes := []byte{byte(chainIndex), byte(j)}
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})
		emit(StackOp{Op: "if",
			Then: []StackOp{
				{Op: "opcode", Code: "OP_1SUB"}, // skip: digit--
			},
			Else: []StackOp{
				{Op: "swap"}, // pubSeed digit X
				{Op: "push", Value: bigIntPush(2)},
				{Op: "opcode", Code: "OP_PICK"},                                // copy pubSeed
				{Op: "push", Value: PushValue{Kind: "bytes", Bytes: adrsBytes}}, // ADRS [chainIndex, j]
				{Op: "opcode", Code: "OP_CAT"},                                  // pubSeed || adrs
				{Op: "swap"},                                                    // bring X to top
				{Op: "opcode", Code: "OP_CAT"},                                  // pubSeed || adrs || X
				{Op: "opcode", Code: "OP_SHA256"},                               // F result
				{Op: "swap"},                                                    // pubSeed new_X digit(=0)
			},
		})
	}
	emit(StackOp{Op: "drop"}) // drop digit (now 0)

	// Restore: sigRest, csum, endpt_acc, steps_copy
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})

	// csum += steps_copy
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})

	// Concat endpoint to endpt_acc
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(3)})
	emit(StackOp{Op: "opcode", Code: "OP_ROLL"})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
}

// EmitVerifyWOTS emits the full WOTS+ signature verification script.
// Parameters: w=16, n=32 (SHA-256), len=67 chains.
// pubkey is 64 bytes: pubSeed(32) || pkRoot(32).
//
// Stack on entry: [..., msg, sig, pubkey] (pubkey on top).
// Stack on exit:  [..., bool] (1 = valid, 0 = invalid).
func EmitVerifyWOTS(emit func(StackOp)) {
	// main: msg sig pubkey(64B: pubSeed||pkRoot)

	// Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})       // msg sig pubSeed pkRoot
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // pkRoot → alt

	// Rearrange: put pubSeed at bottom, hash msg
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})    // sig pubSeed msg
	emit(StackOp{Op: "opcode", Code: "OP_ROT"})    // pubSeed msg sig
	emit(StackOp{Op: "swap"})                       // pubSeed sig msg
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"}) // pubSeed sig msgHash

	// Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(0)})
	emit(StackOp{Op: "opcode", Code: "OP_0"})
	emit(StackOp{Op: "push", Value: bigIntPush(3)})
	emit(StackOp{Op: "opcode", Code: "OP_ROLL"})

	// Process 32 bytes → 64 message chains
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		if byteIdx < 31 {
			emit(StackOp{Op: "push", Value: bigIntPush(1)})
			emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			emit(StackOp{Op: "swap"})
		}
		// Unsigned byte conversion
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "push", Value: bigIntPush(1)})
		emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		// Extract nibbles
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "push", Value: bigIntPush(16)})
		emit(StackOp{Op: "opcode", Code: "OP_DIV"})
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "push", Value: bigIntPush(16)})
		emit(StackOp{Op: "opcode", Code: "OP_MOD"})

		if byteIdx < 31 {
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			emit(StackOp{Op: "swap"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		} else {
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		}

		emitWOTSOneChainOp(emit, byteIdx*2) // high nibble chain

		if byteIdx < 31 {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			emit(StackOp{Op: "swap"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		} else {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		}

		emitWOTSOneChainOp(emit, byteIdx*2+1) // low nibble chain

		if byteIdx < 31 {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		}
	}

	// Checksum digits
	emit(StackOp{Op: "swap"})
	// d66
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// d65
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_DIV"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// d64
	emit(StackOp{Op: "push", Value: bigIntPush(256)})
	emit(StackOp{Op: "opcode", Code: "OP_DIV"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})

	// 3 checksum chains (indices 64, 65, 66)
	for ci := 0; ci < 3; ci++ {
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emitWOTSOneChainOp(emit, 64+ci)
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "drop"})
	}

	// Final comparison
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
	// main: pubSeed endptAcc
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"})
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // pkRoot
	emit(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	// Clean up pubSeed
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
}

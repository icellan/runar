//! WOTS+ (Winternitz One-Time Signature, post-quantum) Bitcoin Script
//! codegen for the Rúnar Rust stack lowerer.
//!
//! Splice into LoweringContext in stack.rs. All helpers self-contained.
//! Entry: `lower_verify_wots()` -> calls `emit_verify_wots()`.
//!
//! Parameters: w=16, n=32 (SHA-256), len=67 chains (64 message + 3 checksum).
//! pubkey is 64 bytes: pubSeed(32) || pkRoot(32).
//!
//! Stack on entry: `[..., msg, sig, pubkey]` (pubkey on top).
//! Stack on exit:  `[..., bool]` (1 = valid, 0 = invalid).

use super::stack::{PushValue, StackOp};

/// Emit one WOTS+ chain verification.
///
/// Entry stack: `pubSeed(bottom) sig csum endpt digit(top)`
/// Exit stack:  `pubSeed(bottom) sigRest newCsum newEndpt`
fn emit_wots_one_chain(emit: &mut dyn FnMut(StackOp), chain_index: usize) {
    // Save steps_copy = 15 - digit to alt (for checksum accumulation later)
    emit(StackOp::Opcode("OP_DUP".into()));
    emit(StackOp::Push(PushValue::Int(15)));
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_SUB".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // push#1: steps_copy

    // Save endpt, csum to alt. Leave pubSeed+sig+digit on main.
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // push#2: endpt
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // push#3: csum
    // main: pubSeed sig digit

    // Split 32B sig element
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(32)));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // push#4: sigRest
    emit(StackOp::Swap);
    // main: pubSeed sigElem digit

    // Hash loop: skip first `digit` iterations, then apply F for the rest.
    // When digit > 0: decrement (skip). When digit == 0: hash at step j.
    // Stack: pubSeed(depth2) sigElem(depth1) digit(depth0=top)
    for j in 0..15usize {
        let adrs_bytes = vec![chain_index as u8, j as u8];
        emit(StackOp::Opcode("OP_DUP".into()));
        emit(StackOp::Opcode("OP_0NOTEQUAL".into()));
        emit(StackOp::If {
            then_ops: vec![
                StackOp::Opcode("OP_1SUB".into()),            // skip: digit--
            ],
            else_ops: vec![
                StackOp::Swap,                                  // pubSeed digit X
                StackOp::Push(PushValue::Int(2)),
                StackOp::Opcode("OP_PICK".into()),            // copy pubSeed
                StackOp::Push(PushValue::Bytes(adrs_bytes)),   // ADRS [chainIndex, j]
                StackOp::Opcode("OP_CAT".into()),              // pubSeed || adrs
                StackOp::Swap,                                  // bring X to top
                StackOp::Opcode("OP_CAT".into()),              // pubSeed || adrs || X
                StackOp::Opcode("OP_SHA256".into()),           // F result
                StackOp::Swap,                                  // pubSeed new_X digit(=0)
            ],
        });
    }
    emit(StackOp::Drop); // drop digit (now 0)
    // main: pubSeed endpoint

    // Restore from alt (LIFO): sigRest, csum, endpt_acc, steps_copy
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));

    // csum += steps_copy
    emit(StackOp::Rot);
    emit(StackOp::Opcode("OP_ADD".into()));

    // Concat endpoint to endpt_acc
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(3)));
    emit(StackOp::Opcode("OP_ROLL".into()));
    emit(StackOp::Opcode("OP_CAT".into()));
}

/// Emit the full WOTS+ signature verification script with RFC 8391
/// tweakable hash (post-quantum).
///
/// Parameters: w=16, n=32 (SHA-256), len=67 chains.
/// pubkey is 64 bytes: pubSeed(32) || pkRoot(32).
///
/// Stack on entry: `[..., msg, sig, pubkey]` (pubkey on top).
/// Stack on exit:  `[..., bool]` (1 = valid, 0 = invalid).
pub fn emit_verify_wots(emit: &mut dyn FnMut(StackOp)) {
    // main: msg sig pubkey(64B: pubSeed||pkRoot)

    // Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
    emit(StackOp::Push(PushValue::Int(32)));
    emit(StackOp::Opcode("OP_SPLIT".into()));          // msg sig pubSeed pkRoot
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));    // pkRoot → alt

    // Rearrange: put pubSeed at bottom, hash msg
    emit(StackOp::Rot);                                 // sig pubSeed msg
    emit(StackOp::Rot);                                 // pubSeed msg sig
    emit(StackOp::Swap);                                // pubSeed sig msg
    emit(StackOp::Opcode("OP_SHA256".into()));         // pubSeed sig msgHash

    // Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(0)));
    emit(StackOp::Opcode("OP_0".into()));
    emit(StackOp::Push(PushValue::Int(3)));
    emit(StackOp::Opcode("OP_ROLL".into()));

    // Process 32 bytes → 64 message chains
    for byte_idx in 0..32 {
        if byte_idx < 31 {
            emit(StackOp::Push(PushValue::Int(1)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Swap);
        }
        // Unsigned byte conversion
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Push(PushValue::Int(1)));
        emit(StackOp::Opcode("OP_NUM2BIN".into()));
        emit(StackOp::Opcode("OP_CAT".into()));
        emit(StackOp::Opcode("OP_BIN2NUM".into()));
        // Extract nibbles
        emit(StackOp::Opcode("OP_DUP".into()));
        emit(StackOp::Push(PushValue::Int(16)));
        emit(StackOp::Opcode("OP_DIV".into()));
        emit(StackOp::Swap);
        emit(StackOp::Push(PushValue::Int(16)));
        emit(StackOp::Opcode("OP_MOD".into()));

        if byte_idx < 31 {
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
            emit(StackOp::Swap);
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        } else {
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        }

        emit_wots_one_chain(emit, byte_idx * 2); // high nibble chain

        if byte_idx < 31 {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Swap);
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        } else {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        }

        emit_wots_one_chain(emit, byte_idx * 2 + 1); // low nibble chain

        if byte_idx < 31 {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        }
    }

    // Checksum digits
    emit(StackOp::Swap);
    // d66
    emit(StackOp::Opcode("OP_DUP".into()));
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));
    // d65
    emit(StackOp::Opcode("OP_DUP".into()));
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_DIV".into()));
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));
    // d64
    emit(StackOp::Push(PushValue::Int(256)));
    emit(StackOp::Opcode("OP_DIV".into()));
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));

    // 3 checksum chains (indices 64, 65, 66)
    for ci in 0..3 {
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit_wots_one_chain(emit, 64 + ci);
        emit(StackOp::Swap);
        emit(StackOp::Drop);
    }

    // Final comparison
    emit(StackOp::Swap);
    emit(StackOp::Drop);
    // main: pubSeed endptAcc
    emit(StackOp::Opcode("OP_SHA256".into()));
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // pkRoot
    emit(StackOp::Opcode("OP_EQUAL".into()));
    // Clean up pubSeed
    emit(StackOp::Swap);
    emit(StackOp::Drop);
}

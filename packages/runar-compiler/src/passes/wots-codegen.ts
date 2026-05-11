/**
 * WOTS+ (Winternitz One-Time Signature, w=16) Bitcoin Script codegen.
 *
 * Splice into LoweringContext in 05-stack-lower.ts. All helpers self-contained.
 * Entry: lowerVerifyWOTS() in stack-lower → calls emitVerifyWOTS().
 *
 * Parameters: w=16, n=32 (SHA-256), len1=64, len2=3, len=67.
 * Input stack at entry: msg(0) sig(1) pubkey(2)  (pubkey = pubSeed||pkRoot, 64B)
 * Output: <boolean>
 *
 * Canonical stack between chains: sig_rem(0) csum(1) endpt_acc(2)
 * Alt stack: pubkey only (plus balanced temp saves inside chain processing).
 */

import type { StackOp } from '../ir/index.js';

type Emit = (op: StackOp) => void;

/**
 * Emit one WOTS+ chain with RFC 8391 tweakable hashing.
 * Input:  pubSeed(bottom) sig(1) csum(2) endpt(3) digit(top)
 * Output: pubSeed(bottom) sigRest(1) newCsum(2) newEndpt(top)
 * Alt stack pushes/pops are balanced (4 push, 4 pop).
 *
 * F(pubSeed, chainIdx, stepIdx, X) = SHA-256(pubSeed || byte(chainIdx) || byte(stepIdx) || X)
 */
function emitWOTSOneChain(emit: Emit, chainIndex: number): void {
  // Entry stack: pubSeed sig csum endpt digit
  // Save steps_copy = 15 - digit to alt (for checksum accumulation later)
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 15n });
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_SUB' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#1: steps_copy
  // main: pubSeed sig csum endpt digit

  // Save endpt, csum to alt. Leave pubSeed+sig+digit on main.
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#2: endpt
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#3: csum
  // main: pubSeed sig digit

  // Split 32B sig element
  emit({ op: 'swap' });                            // pubSeed digit sig
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });       // pubSeed digit sigElem sigRest
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#4: sigRest
  emit({ op: 'swap' });                            // pubSeed sigElem digit

  // Hash loop: skip first `digit` iterations, then apply F for the rest.
  // When digit > 0: decrement (skip). When digit == 0: hash at step j.
  // Stack at loop entry: pubSeed(depth2) sigElem(depth1) digit(depth0=top)
  for (let j = 0; j < 15; j++) {
    const adrsBytes = new Uint8Array([chainIndex, j]);
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'opcode', code: 'OP_0NOTEQUAL' });
    emit({
      op: 'if',
      then: [
        { op: 'opcode', code: 'OP_1SUB' },                // skip: digit--
      ],
      else: [
        { op: 'swap' },                                    // pubSeed digit X
        { op: 'push', value: 2n },
        { op: 'opcode', code: 'OP_PICK' },                // copy pubSeed from depth 2
        { op: 'push', value: adrsBytes },                  // push ADRS [chainIndex, j]
        { op: 'opcode', code: 'OP_CAT' },                 // pubSeed || adrs
        { op: 'swap' },                                    // bring X to top
        { op: 'opcode', code: 'OP_CAT' },                 // pubSeed || adrs || X
        { op: 'opcode', code: 'OP_SHA256' },              // F result
        { op: 'swap' },                                    // pubSeed new_X digit(=0)
      ],
    });
  }
  emit({ op: 'drop' }); // drop digit (now 0)
  // main: pubSeed endpoint

  // Restore from alt (LIFO): sigRest, csum, endpt_acc, steps_copy
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#4: sigRest
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#3: csum
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#2: endpt_acc
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#1: steps_copy
  // main b→t: pubSeed endpoint sigRest csum endpt_acc steps_copy

  // csum += steps_copy
  emit({ op: 'opcode', code: 'OP_ROT' });
  emit({ op: 'opcode', code: 'OP_ADD' });

  // Concat endpoint to endpt_acc
  emit({ op: 'swap' });
  emit({ op: 'push', value: 3n });
  emit({ op: 'opcode', code: 'OP_ROLL' });
  emit({ op: 'opcode', code: 'OP_CAT' });
  // pubSeed sigRest newCsum newEndptAcc
}

/**
 * Emit standalone WOTS+ signature verification.
 * Entry stack (top-down): msg(0) sig(1) pubkey(2)  (pubkey 64B = pubSeed||pkRoot)
 * Exit stack: <boolean>
 */
export function emitVerifyWOTS(emit: Emit): void {
  // Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });         // msg sig pubSeed pkRoot
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });   // pkRoot → alt

  // Rearrange: put pubSeed at bottom, hash msg
  // main: msg sig pubSeed
  emit({ op: 'opcode', code: 'OP_ROT' });           // sig pubSeed msg
  emit({ op: 'opcode', code: 'OP_ROT' });           // pubSeed msg sig
  emit({ op: 'swap' });                               // pubSeed sig msg
  emit({ op: 'opcode', code: 'OP_SHA256' });        // pubSeed sig msgHash

  // Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
  emit({ op: 'swap' });                // pubSeed msgHash sig
  emit({ op: 'push', value: 0n });     // pubSeed msgHash sig 0
  emit({ op: 'opcode', code: 'OP_0' }); // pubSeed msgHash sig 0 empty
  emit({ op: 'push', value: 3n });
  emit({ op: 'opcode', code: 'OP_ROLL' }); // pubSeed sig 0 empty msgHash

  // Process 32 bytes → 64 message chains
  // Chain indices: byteIdx*2 for high nibble, byteIdx*2+1 for low nibble
  for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
    // main: pubSeed sig csum endptAcc hashRem
    if (byteIdx < 31) {
      emit({ op: 'push', value: 1n });
      emit({ op: 'opcode', code: 'OP_SPLIT' });
      emit({ op: 'swap' });
    }
    // Convert 1-byte string to unsigned integer.
    emit({ op: 'push', value: 0n });
    emit({ op: 'push', value: 1n });
    emit({ op: 'opcode', code: 'OP_NUM2BIN' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    emit({ op: 'opcode', code: 'OP_BIN2NUM' });
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'push', value: 16n });
    emit({ op: 'opcode', code: 'OP_DIV' });  // high
    emit({ op: 'swap' });
    emit({ op: 'push', value: 16n });
    emit({ op: 'opcode', code: 'OP_MOD' });  // low

    // Save low (and hashRest if present) to alt
    if (byteIdx < 31) {
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // low → alt
      emit({ op: 'swap' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // hashRest → alt
    } else {
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // low → alt
    }
    // main: pubSeed sig csum endptAcc high

    emitWOTSOneChain(emit, byteIdx * 2); // chain index for high nibble

    // Retrieve low from alt (and hashRest)
    if (byteIdx < 31) {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // hashRest
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // low
      emit({ op: 'swap' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // hashRest → alt
    } else {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // low
    }
    // main: pubSeed sigRest csum endptAcc low

    emitWOTSOneChain(emit, byteIdx * 2 + 1); // chain index for low nibble

    if (byteIdx < 31) {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // hashRest
    }
  }

  // main: pubSeed sigRest(96B) totalCsum endptAcc  |  alt: pkRoot

  // Compute 3 checksum digits
  emit({ op: 'swap' }); // pubSeed sigRest endptAcc totalCsum

  // d66 = csum % 16
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });

  // d65 = (csum/16) % 16
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_DIV' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });

  // d64 = (csum/256) % 16
  emit({ op: 'push', value: 256n });
  emit({ op: 'opcode', code: 'OP_DIV' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // main: pubSeed sigRest endptAcc  |  alt: pkRoot, d66, d65, d64

  // Process 3 checksum chains (indices 64, 65, 66)
  for (let ci = 0; ci < 3; ci++) {
    // main: pubSeed sigRest endptAcc
    // Set up: pubSeed sigRest dummyCsum=0 endptAcc digit
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // endptAcc → alt (temp)
    emit({ op: 'push', value: 0n });                // pubSeed sigRest 0
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pubSeed sigRest 0 endptAcc
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pubSeed sigRest 0 endptAcc digit

    emitWOTSOneChain(emit, 64 + ci);
    // main: pubSeed sigRest dummyCsum newEndptAcc

    // Drop dummy csum
    emit({ op: 'swap' }); // pubSeed sigRest newEndptAcc dummyCsum
    emit({ op: 'drop' }); // pubSeed sigRest newEndptAcc
  }

  // main: pubSeed sigRest(empty) endptAcc  |  alt: pkRoot
  emit({ op: 'swap' });
  emit({ op: 'drop' }); // drop empty sigRest
  // main: pubSeed endptAcc

  // Hash concatenated endpoints → computed pkRoot
  emit({ op: 'opcode', code: 'OP_SHA256' });
  // main: pubSeed computedPkRoot

  // Compare to pkRoot from alt
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pkRoot
  emit({ op: 'opcode', code: 'OP_EQUAL' });
  // main: pubSeed bool

  // Clean up pubSeed
  emit({ op: 'swap' });
  emit({ op: 'drop' }); // drop pubSeed
  // main: bool
}

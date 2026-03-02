// ---------------------------------------------------------------------------
// runar-lang/oracle/rabin.ts — Rabin signature oracle verification
// ---------------------------------------------------------------------------
// Rabin signatures provide a simple and cheap-to-verify digital signature
// scheme that can be implemented entirely in Bitcoin Script.  They are
// commonly used to bring external (oracle) data on-chain in a trust-
// minimised way.
//
// The Rúnar compiler inlines the Rabin verification as a sequence of
// arithmetic opcodes (OP_MUL, OP_MOD, OP_EQUAL, etc.).
// ---------------------------------------------------------------------------

import type { ByteString, RabinSig, RabinPubKey } from '../types.js';

/**
 * Verify a Rabin signature on-chain.
 *
 * The Rabin signature scheme works as follows:
 *   sig^2 mod pubkey == SHA-256(msg || padding)  (as a big integer)
 *
 * The `padding` parameter is chosen by the signer to make the hash output a
 * quadratic residue modulo `pubkey`.
 *
 * @param msg     - The message whose authenticity is being verified.
 * @param sig     - The Rabin signature (a large integer).
 * @param padding - Signer-chosen padding appended to `msg` before hashing.
 * @param pubkey  - The Rabin public key (product of two secret primes).
 * @returns `true` if the signature is valid.
 */
export function verifyRabinSig(
  _msg: ByteString,
  _sig: RabinSig,
  _padding: ByteString,
  _pubkey: RabinPubKey,
): boolean {
  throw new Error(
    'verifyRabinSig() cannot be called at runtime — compile this contract with the Rúnar compiler.',
  );
}

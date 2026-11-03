/**
 * Strict DER (BIP66) check for an ECDSA signature — the rule a node applies
 * to every OP_CHECKSIG signature (SCRIPT_VERIFY_DERSIG). F-242.
 *
 * `der` is bare DER, without a trailing sighash type byte. True only for the
 * one canonical encoding of (r, s): the SEQUENCE length covers exactly r and
 * s, both INTEGERs are non-empty, non-negative (top bit clear unless behind a
 * 0x00 pad) and minimally encoded, and nothing follows s.
 *
 * @bsv/sdk's `Signature.fromDER` accepts an INTEGER whose top bit is set
 * without the 0x00 pad, so a second byte string verified as the same
 * signature; every verifier in this SDK checks this first.
 */
export function isStrictDerSignature(der: ArrayLike<number>): boolean {
  const n = der.length;
  if (n < 8 || n > 72) return false;
  if (der[0] !== 0x30 || der[1] !== n - 2) return false;
  const rLen = der[3]!;
  if (der[2] !== 0x02 || rLen === 0 || 5 + rLen >= n) return false;
  const sLen = der[5 + rLen]!;
  if (der[4 + rLen] !== 0x02 || sLen === 0) return false;
  if (rLen + sLen + 6 !== n) return false;
  return isCanonicalDerInteger(der, 4, rLen) && isCanonicalDerInteger(der, 6 + rLen, sLen);
}

function isCanonicalDerInteger(der: ArrayLike<number>, at: number, len: number): boolean {
  if ((der[at]! & 0x80) !== 0) return false;
  if (len > 1 && der[at] === 0x00 && (der[at + 1]! & 0x80) === 0) return false;
  return true;
}

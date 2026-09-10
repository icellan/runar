/**
 * R-044 — the README's description of `prepared.sighash` must match what
 * `prepareCall()` actually stores.
 *
 * The value is `hash256(preimage)` = `sha256(sha256(preimage))` (deep-review
 * finding C19, pinned at runtime by `c19-multisig-sighash-digest.test.ts`).
 * The README kept the PRE-C19 wording — "`SHA256(prepared.preimage)` — the
 * inner SHA-256 of the BIP-143 double-hash" — long after the code moved. A
 * wallet integrator who believes the doc hashes the value once more before
 * signing produces a signature over the wrong digest: `OP_CHECKSIG` rejects
 * the spend, and for a covenant spend the UTXO can be left stuck.
 *
 * A doc claim about a wire-level digest is load-bearing, so it gets a test.
 * This one fails if the README ever again describes `sighash` as a single /
 * inner SHA-256, or stops naming the double hash.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const README = readFileSync(
  fileURLToPath(new URL('../../README.md', import.meta.url)),
  'utf8',
);

/** The paragraph(s) of the README that describe what `prepared.sighash` is. */
function sighashClaims(): string[] {
  return README.split('\n').filter((line) => /`?prepared\.sighash`?/.test(line));
}

describe('R-044 — README `prepared.sighash` documentation matches the code', () => {
  it('documents the DOUBLE hash — hash256(preimage)', () => {
    const claims = sighashClaims();
    expect(claims.length).toBeGreaterThan(0);
    const definition = claims.filter((line) => /hash256|double/i.test(line));
    expect(
      definition.length,
      `README must state that prepared.sighash is hash256(prepared.preimage) ` +
        `(sha256(sha256(...))) — the digest an external signer ECDSA-signs directly. ` +
        `Found:\n${claims.join('\n')}`,
    ).toBeGreaterThan(0);
  });

  it('never describes it as a single / inner SHA-256', () => {
    const offenders = sighashClaims().filter((line) =>
      /(inner|single)\s+SHA-?256/i.test(line) ||
      /`?prepared\.sighash`? is `?SHA256\(/i.test(line),
    );
    expect(
      offenders,
      'prepared.sighash is the DOUBLE SHA-256 (hash256) BIP-143 digest, not the ' +
        'inner single hash — a signer that re-hashes it signs the wrong message.',
    ).toEqual([]);
  });
});

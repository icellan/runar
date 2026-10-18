/**
 * F-299 (CL-GAP-086): conformance/sdk-bip143 never exercised a non-zero
 * nLockTime. `generate-fixtures.ts` hard-coded `lockTime: 0` in selfValidate, so
 * a fixture with a real locktime could not even be generated, and a tier that
 * hard-codes nLockTime=0 in its preimage builder passed every scenario.
 *
 * Proves: the committed fixture contains at least one scenario whose raw tx has
 * a non-zero nLockTime, and for EVERY scenario the nLockTime field inside the
 * (TS-reference, @bsv/sdk-built) preimage equals the nLockTime serialized at
 * the tail of unsignedTxHex, so the locktime a consumer parses from the tx is
 * the one the independent oracle committed to.
 * Does not prove: that any tier parses the locktime correctly (the per-tier
 * bip143 interop runners do that by recomputing the preimage), nor that the
 * lockTime scenario is accepted by a node.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'sdk-bip143', 'fixtures.json');

interface Scenario {
  scenario: string;
  unsignedTxHex: string;
  preimageHex: string;
}

const scenarios: Scenario[] = JSON.parse(readFileSync(FIXTURE, 'utf8')).scenarios;

/** nLockTime = last 4 bytes of a raw tx (little-endian). */
function txLockTime(txHex: string): number {
  return Buffer.from(txHex.slice(-8), 'hex').readUInt32LE(0);
}

/** BIP-143 preimage ends with nLockTime(4, LE) || sighashType(4, LE). */
function preimageLockTime(preimageHex: string): number {
  return Buffer.from(preimageHex.slice(-16, -8), 'hex').readUInt32LE(0);
}

describe('F-299: sdk-bip143 fixture covers a non-zero nLockTime', () => {
  it('has at least one scenario with a non-zero tx nLockTime', () => {
    const nonZero = scenarios.filter((s) => txLockTime(s.unsignedTxHex) !== 0);
    expect(nonZero.map((s) => s.scenario)).not.toEqual([]);
  });

  it('every preimage commits to the nLockTime serialized in its unsignedTxHex', () => {
    for (const s of scenarios) {
      expect(preimageLockTime(s.preimageHex), s.scenario).toBe(txLockTime(s.unsignedTxHex));
    }
  });
});

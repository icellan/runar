/**
 * Tier 3 — hand-rolled Script not produced by Rúnar.
 *
 * The decompiler must not crash; unrecovered regions are emitted as
 * /* RAW: ... *\/ blocks. We assert no exception and a non-empty source.
 */

import { describe, it, expect } from 'vitest';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';

const FIXTURES: { name: string; hex: string }[] = [
  // Minimal P2PKH locking script (real Bitcoin convention, not Rúnar output).
  {
    name: 'p2pkh-minimal',
    hex: '76a914' + '00'.repeat(20) + '88ac',
  },
  // OP_HASH160 <20-byte> OP_EQUAL — generic hashlock.
  {
    name: 'hashlock',
    hex: 'a914' + '11'.repeat(20) + '87',
  },
  // OP_CHECKSIG only.
  {
    name: 'checksig-only',
    hex: 'ac',
  },
  // OP_TRUE.
  {
    name: 'anyone-can-spend',
    hex: '51',
  },
  // Two-pubkey multisig (1-of-2) — manual.
  {
    name: 'multisig-1of2',
    hex: '51' + '21' + '02'.repeat(33) + '21' + '03'.repeat(33) + '52ae',
  },
];

describe('Tier 3: hand-rolled non-Rúnar scripts', () => {
  for (const f of FIXTURES) {
    it(`${f.name}: decompiles without crashing`, () => {
      const bytes = hexToBytes(f.hex);
      const result = decompile(bytes);
      expect(typeof result.source).toBe('string');
      expect(result.source.length).toBeGreaterThan(0);
      // No round-trip guarantee for non-Rúnar input; just confirm it ran.
    });
  }
});

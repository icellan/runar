// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/terminal-varlen-read.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-106 — `terminal-varlen-read` had no test in any of the nine formats.
 *
 * Two methods, deliberately asymmetric: `post` WRITES the variable-length
 * field, `reveal` only READS it and mutates nothing — a terminal method. The
 * reader has to recover the field's width from the serialized state, and the
 * terminal path is the one where a writer/reader width disagreement shows up as
 * an unspendable UTXO rather than a compile error (the R-071 family).
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'TerminalVarlenRead.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const hex = (b: unknown) =>
  b instanceof Uint8Array ? Buffer.from(b).toString('hex') : String(b);

describe('TerminalVarlenRead (a terminal read of a variable-length field)', () => {
  it('post replaces the message', () => {
    const c = TestContract.fromSource(source, { message: '00' }, FILE);
    const r = c.call('post', { newMessage: new Uint8Array([0xaa, 0xbb]) });
    expect(r.success, r.error).toBe(true);
    expect(hex(c.state.message)).toBe('aabb');
  });

  it('post accepts a longer message than it started with', () => {
    const c = TestContract.fromSource(source, { message: '00' }, FILE);
    const long = new Uint8Array(40).fill(0x7f);
    expect(c.call('post', { newMessage: long }).success).toBe(true);
    expect(hex(c.state.message)).toBe('7f'.repeat(40));
  });

  it('reveal passes when the message is longer than the bound', () => {
    const c = TestContract.fromSource(source, { message: 'aabbcc' }, FILE);
    const r = c.call('reveal', { minLen: 2n });
    expect(r.success, r.error).toBe(true);
  });

  it('reveal FAILS at the boundary — the length is a real check, not decoration', () => {
    const c = TestContract.fromSource(source, { message: 'aabbcc' }, FILE);
    expect(c.call('reveal', { minLen: 3n }).success).toBe(false);
    expect(c.call('reveal', { minLen: 99n }).success).toBe(false);
  });

  it('reveal mutates nothing', () => {
    const c = TestContract.fromSource(source, { message: 'aabbcc' }, FILE);
    c.call('reveal', { minLen: 1n });
    expect(hex(c.state.message)).toBe('aabbcc');
  });
});

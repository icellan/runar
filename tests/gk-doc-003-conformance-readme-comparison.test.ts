/**
 * GK-DOC-003: conformance/README.md said expected-ir.json is "Canonical JSON
 * (RFC 8785, no whitespace, sorted keys)" and that the runner compares
 * "SHA-256(compiler_output) with SHA-256(expected-ir.json)". The runner does
 * neither: `canonicalizeJson` in runner/runner.ts key-sorts, strips sourceLoc,
 * normalises bigints and pretty-prints with 2-space indent, then compares
 * strings. No hash is taken. Step 1 ("Read the .runar.ts source file") was also
 * stale: sources resolve through source.json.
 *
 * Proves: the README no longer describes a hash comparison or RFC 8785 output,
 * and describes the string comparison and source.json resolution instead.
 * Does not prove: anything about runner behaviour (the runner's own tests do).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README = readFileSync(join(ROOT, 'conformance', 'README.md'), 'utf8');
const RUNNER = readFileSync(join(ROOT, 'conformance', 'runner', 'runner.ts'), 'utf8');

describe('GK-DOC-003: the conformance README describes the comparison the runner performs', () => {
  it('the runner still compares 2-space JSON strings, not hashes', () => {
    expect(RUNNER).toContain('JSON.stringify(sortKeys(parsed), null, 2)');
    expect(RUNNER).not.toMatch(/createHash\(/);
  });

  it('does not claim a SHA-256 comparison or RFC 8785 output', () => {
    for (const stale of [
      'SHA-256(compiler_output)',
      'RFC 8785, no whitespace',
      'The SHA-256 of this file is the conformance check',
      'canonical JSON (RFC 8785)',
      'serialized via RFC 8785',
      '1. Read the .runar.ts source file.',
    ]) {
      expect(README, `stale: "${stale}"`).not.toContain(stale);
    }
  });

  it('describes source.json resolution, the string compare, and the separate sha256 gate', () => {
    const section = README.slice(README.indexOf('## How the Test Runner Works'));
    expect(section).toMatch(/source\.json/);
    expect(section).toMatch(/sourceLoc/);
    expect(section).toMatch(/string/i);
    expect(README).toMatch(/scripts\/check-golden-provenance\.mjs/);
  });
});

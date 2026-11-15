/**
 * GK-DOC-008: the four SLH-DSA 192/256 builtins hash with SHA-256 only, in
 * all seven emitters and SDKs, because FIPS 205 needs SHA-512 for those
 * parameter sets and Bitcoin Script has no OP_SHA512 (#137, a standing
 * limit). They are self-consistent but NOT FIPS 205: a standard
 * SLH-DSA-SHA2-192/256 signature will not verify. User-facing docs still
 * labelled them "NIST FIPS 205, 192-bit/256-bit security".
 *
 * Proves: no user-facing doc puts a 192-bit/256-bit security label or an
 * unqualified "FIPS 205" next to the 192/256 functions, and each doc that
 * lists them carries the SHA-512 / #137 caveat.
 * Does not prove: anything about the codegen (unchanged on purpose).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p: string) => readFileSync(join(ROOT, p), 'utf8');

const SET = /SHA2[_-]?(192|256)[sf]|sha2_(192|256)[sf]/i;
const BIT = /\b(192|256)-bit\b/;

const DOCS = [
  'docs/language-reference.md',
  'docs/formats/solidity.md',
  'docs/post-quantum-analysis.md',
  'packages/runar-lang/README.md',
  'packages/runar-rs/src/prelude.rs',
  'packages/runar-rb/lib/ruby_lsp/runar/hover.rb',
  'packages/runar-testing/README.md',
];

describe('GK-DOC-008: SLH-DSA 192/256 is documented as SHA-256-only, not FIPS 205', () => {
  for (const doc of DOCS) {
    it(`${doc}: no 192/256-bit label or bare FIPS 205 on a 192/256 line, and the #137 caveat is present`, () => {
      const text = read(doc);
      const bad = text
        .split('\n')
        .map((l, i) => ({ l, n: i + 1 }))
        .filter(({ l }) => SET.test(l))
        .filter(({ l }) => BIT.test(l) || (/FIPS 205/.test(l) && !/not FIPS 205/i.test(l)));
      expect(bad.map(({ l, n }) => `${doc}:${n}: ${l.trim()}`)).toEqual([]);
      expect(text, `${doc}: no SHA-512 / #137 caveat`).toMatch(/SHA-512/);
      expect(text, `${doc}: no SHA-512 / #137 caveat`).toMatch(/#137/);
    });
  }

  it('builtins.ts: the 192/256 JSDoc blocks drop the security label and cite #137', () => {
    const src = read('packages/runar-lang/src/builtins.ts');
    for (const fn of ['192s', '192f', '256s', '256f']) {
      const at = src.indexOf(`export function verifySLHDSA_SHA2_${fn}(`);
      expect(at, fn).toBeGreaterThan(-1);
      const doc = src.slice(src.lastIndexOf('/**', at), at);
      expect(doc, fn).not.toMatch(BIT);
      expect(doc, fn).not.toMatch(/NIST FIPS 205,/);
      expect(doc, fn).toMatch(/#137/);
      expect(doc, fn).toMatch(/SHA-256-only/);
    }
  });

  // Review follow-up: the Go and Rust SDK section headers called all six sets
  // "real FIPS 205 verification", and the 192/256 example comments repeated it
  // (Go tests) or named the wrong set (Java: "FIPS 205 SLH-DSA (SHA2-128s)").
  it('Go/Rust SDK SLH-DSA headers do not call every set real FIPS 205', () => {
    for (const p of ['packages/runar-go/runar.go', 'packages/runar-rs/src/prelude.rs']) {
      const text = read(p);
      expect(text, p).not.toMatch(/SHA-256 variants — real FIPS 205 verification/);
      expect(text, p).toMatch(/#137/);
    }
    const go = read('packages/runar-go/runar.go');
    for (const fn of ['192s', '192f', '256s', '256f']) {
      const at = go.indexOf(`func VerifySLHDSA_SHA2_${fn}(`);
      expect(at, fn).toBeGreaterThan(-1);
      const prev = go.slice(go.lastIndexOf('\n}\n', at), at);
      expect(prev, `runar.go VerifySLHDSA_SHA2_${fn} doc`).toMatch(/not FIPS 205/);
    }
  });

  for (const fn of ['192s', '192f', '256s', '256f']) {
    it(`post-quantum-slhdsa-naive-INSECURE-${fn}: Go and Java comments do not claim FIPS 205 or name 128s`, () => {
      const dir = `post-quantum-slhdsa-naive-INSECURE-${fn}`;
      const goTest = read(`examples/go/${dir}/PostQuantumSLHDSANaiveInsecure${fn}_test.go`);
      expect(goTest).not.toMatch(/is real FIPS 205 verification/);
      const java = read(`examples/java/src/main/java/runar/examples/${dir}/PostQuantumSLHDSANaiveInsecure${fn}.runar.java`);
      expect(java).not.toMatch(/FIPS 205 SLH-DSA \(SHA2-128s\)/);
      expect(java).toMatch(/not FIPS 205/);
    });
  }

  it('README.md: the post-quantum bullet carries the 192/256 caveat', () => {
    const bullet = read('README.md').split('\n').find((l) => l.startsWith('- **Post-quantum'));
    expect(bullet).toBeDefined();
    expect(bullet).toMatch(/SHA-256-only/);
    expect(bullet).toMatch(/#137/);
  });
});

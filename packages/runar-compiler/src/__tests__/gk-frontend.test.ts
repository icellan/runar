import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import { typecheck } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';

/**
 * Grok v1 frontend findings, TypeScript reference tier. The corpora are the
 * cross-tier ones in conformance/negatives/, shared with the other six tiers'
 * unit tests and the conformance negatives gates.
 *
 * Proves, for this tier:
 *  - GK-BUG-015: a repeated method name is a validate error with the shared
 *    message; each renamed twin compiles.
 *  - GK-GAP-013: lowerToANF throws on each malformed intent-intrinsic shape
 *    instead of lowering it to `load_const ''`; typecheck still refuses first.
 *  - GK-GAP-010: each refused shape fails the compile with the shared
 *    diagnostic; each accepted shape compiles.
 *  - D10: a stateless Rust-DSL contract declaring tx_preimage is refused by
 *    the parser with the shared diagnostic; a stateful one keeps it as the
 *    implicit, auto-checked txPreimage.
 *  - GK-GAP-005/006: suffixes match ignoring ASCII case (same hex), an unknown
 *    suffix is refused with the shared message, no file name means TypeScript.
 * Does not prove: anything about the other six tiers.
 */

const REPO = resolve(__dirname, '../../../..');
const corpus = <T>(name: string): T =>
  JSON.parse(readFileSync(join(REPO, 'conformance/negatives', name), 'utf8')) as T;
const messages = (r: { diagnostics: Array<{ message: string; severity: string }> }): string[] =>
  r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);

describe('GK-BUG-015: duplicate method names', () => {
  const { cases } = corpus<{ cases: Array<{ name: string; file: string; src: string; twin: string; error: string }> }>(
    'duplicate-method-cases.json',
  );
  for (const c of cases) {
    it(`refuses ${c.name}`, () => {
      const parsed = parse(c.src, c.file);
      expect(parsed.contract).not.toBeNull();
      expect(validate(parsed.contract!).errors.map((e) => e.message)).toContain(c.error);
      const r = compile(c.src, { fileName: c.file });
      expect(r.success).toBe(false);
      expect(messages(r)).toContain(c.error);
    });
    it(`compiles the renamed twin of ${c.name}`, () => {
      const r = compile(c.twin, { fileName: c.file });
      expect(messages(r)).toEqual([]);
      expect(r.success).toBe(true);
    });
  }
});

describe('GK-GAP-013: the lowerer refuses malformed intent intrinsics', () => {
  const { cases } = corpus<{ cases: Array<{ name: string; src: string; lowerError: string }> }>(
    'intent-shape-cases.json',
  );
  for (const c of cases) {
    it(`${c.name}: throws instead of emitting load_const ''`, () => {
      const parsed = parse(c.src, 'Bad.runar.ts');
      expect(parsed.errors).toEqual([]);
      expect(typecheck(parsed.contract!).errors.length).toBeGreaterThan(0);
      expect(() => lowerToANF(parsed.contract!)).toThrow(c.lowerError);
    });
  }
});

describe('GK-GAP-010: SigHashPreimage parameter checked on every path', () => {
  const corpusData = corpus<{
    refuse: Array<{ name: string; file: string; src: string; error: string }>;
    accept: Array<{ name: string; file: string; src: string }>;
  }>('preimage-checked-cases.json');
  // The corpus pins only a substring where the tiers word a diagnostic
  // differently (fixedarray-parameter: "FixedArray"); this tier's exact text.
  const exactHere: Record<string, string> = {
    'fixedarray-parameter':
      "Parameter 'ps' in method 'spend' cannot be a FixedArray. Arrays are only allowed as contract properties.",
  };
  for (const c of corpusData.refuse) {
    it(`refuses ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(r.success).toBe(false);
      const want = exactHere[c.name] ?? c.error;
      expect(want).toContain(c.error);
      expect(messages(r)).toContain(want);
    });
  }
  for (const c of corpusData.accept) {
    it(`accepts ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(messages(r)).toEqual([]);
      expect(r.success).toBe(true);
    });
  }
});

describe('D10: a stateless Rust-DSL contract cannot declare tx_preimage', () => {
  const corpusData = corpus<{
    refuse: Array<{ name: string; file: string; src: string; error: string }>;
    accept: Array<{ name: string; file: string; src: string }>;
  }>('rust-tx-preimage-cases.json');
  for (const c of corpusData.refuse) {
    it(`refuses ${c.name} in the parser`, () => {
      const parsed = parse(c.src, c.file);
      expect(parsed.errors.map((e) => e.message)).toContain(c.error);
      const r = compile(c.src, { fileName: c.file });
      expect(r.success).toBe(false);
      expect(messages(r)).toContain(c.error);
    });
  }
  for (const c of corpusData.accept) {
    it(`accepts ${c.name} as stateful, tx_preimage the implicit preimage`, () => {
      const parsed = parse(c.src, c.file);
      expect(parsed.errors).toEqual([]);
      expect(parsed.contract!.parentClass).toBe('StatefulSmartContract');
      expect(parsed.contract!.properties.map((p) => p.name)).not.toContain('txPreimage');
      const r = compile(c.src, { fileName: c.file });
      expect(messages(r)).toEqual([]);
      expect(r.success).toBe(true);
    });
  }
});

describe('GK-GAP-005/006: file-extension dispatch', () => {
  const ts = readFileSync(join(REPO, 'examples/ts/p2pkh/P2PKH.runar.ts'), 'utf8');
  const py = readFileSync(join(REPO, 'examples/python/p2pkh/P2PKH.runar.py'), 'utf8');
  const hex = (src: string, fileName: string): string => {
    const r = compile(src, { fileName });
    expect(messages(r), fileName).toEqual([]);
    return r.scriptHex!;
  };

  it('upper-case suffixes compile to the same hex as lower-case ones', () => {
    expect(hex(ts, 'P2PKH.RUNAR.TS')).toBe(hex(ts, 'P2PKH.runar.ts'));
    expect(hex(py, 'P2PKH.RUNAR.PY')).toBe(hex(py, 'P2PKH.runar.py'));
  });

  it('an unknown suffix is refused even when the source is valid TypeScript', () => {
    const r = parse(ts, 'P2PKH.runar.xyz');
    expect(r.contract).toBeNull();
    expect(r.errors.map((e) => e.message)).toEqual([
      'unsupported file extension: P2PKH.runar.xyz (expected .runar.ts, .runar.sol, .runar.move, ' +
        '.runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java)',
    ]);
  });

  it('no file name means TypeScript', () => {
    for (const name of [undefined, '']) {
      const r = parse(ts, name);
      expect(r.errors).toEqual([]);
      expect(r.contract?.name).toBe('P2PKH');
    }
  });
});

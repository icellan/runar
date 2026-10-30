/**
 * N-351 (F-193 in the TS tier) -- the SHA-256 / BLAKE3 compression op caches
 * must not carry one call site's source location into another compilation.
 *
 * sha256-codegen.ts / blake3-codegen.ts build their compression bodies once per
 * process and hand the SAME StackOp objects to emitOp, which used to stamp
 * `sourceLoc` on the object it was given. The first call site compiled in the
 * process therefore pinned its location on the cache for good. Emitted bytes
 * were never affected -- only the source map.
 *
 * What this proves: compiling contract A then contract B (different files and
 * call lines) in one process, every compression-body source-map entry of B
 * names B's file and call line, none names A, and recompiling A still maps to A.
 *
 * What this does not prove: the Ruby tier (own test), other caches in the
 * compiler, or that the hex is unchanged (the conformance goldens gate that).
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const CASES: Record<string, { body: string; minOps: number }> = {
  sha256Compress: {
    body: 'const result = sha256Compress(state, block);',
    minOps: 15000,
  },
  sha256Finalize: {
    body: 'const result = sha256Finalize(state, remaining, n);',
    minOps: 15000,
  },
  blake3Compress: {
    body: 'const result = blake3Compress(state, block);',
    minOps: 5000,
  },
};

function source(name: string, body: string, pad: number): string {
  return `${'\n'.repeat(pad)}class ${name} extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, block: ByteString, remaining: ByteString, n: bigint) {
    ${body}
    assert(result === this.expected);
  }
}
`;
}

function build(body: string, name: string, pad: number, fileName: string) {
  const src = source(name, body, pad);
  const callLine = src.split('\n').findIndex(l => l.includes('const result =')) + 1;
  const result = compile(src, { fileName, disableConstantFolding: true });
  expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
  return { callLine, mappings: result.artifact!.sourceMap!.mappings };
}

describe('N-351: crypto op caches do not leak sourceLoc across compilations', () => {
  for (const [intrinsic, { body, minOps }] of Object.entries(CASES)) {
    it(intrinsic, () => {
      const a = build(body, 'ContractA', 0, 'A.runar.ts');
      const b = build(body, 'ContractB', 7, 'B.runar.ts');
      expect(a.callLine).not.toBe(b.callLine);

      expect(a.mappings.filter(m => m.sourceFile === 'A.runar.ts' && m.line === a.callLine).length)
        .toBeGreaterThanOrEqual(minOps);

      const leaked = b.mappings.filter(m => m.sourceFile !== 'B.runar.ts');
      expect(leaked.length).toBe(0);
      expect(b.mappings.filter(m => m.line === b.callLine).length).toBeGreaterThanOrEqual(minOps);

      const a2 = build(body, 'ContractA', 0, 'A.runar.ts');
      expect(a2.mappings.every(m => m.sourceFile === 'A.runar.ts')).toBe(true);
      expect(a2.mappings.filter(m => m.line === a2.callLine).length).toBeGreaterThanOrEqual(minOps);
    });
  }
});

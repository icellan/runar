/**
 * GK-DOC-005 / GK-DOC-006 — two stale TS comments.
 *
 * DOC-005: 05-stack-lower.ts said the script-level OP_CODESEPARATOR is "the
 * first byte of the locking script" and scriptCode is the script "minus that
 * leading byte"; 06-emit.ts said "with the separator at offset 0, scriptCode
 * == lockingScript[1:]". The emitter writes OP_NOP OP_CODESEPARATOR, so the
 * separator is at offset 1 and scriptCode is lockingScript[2:].
 *
 * DOC-006: anf-ir.ts said the TS tier "has no ANF-input mode, so it is the one
 * tier that need not emit" syntheticArrayChain. Pass 4 does emit it, and
 * compileFromANF consumes it (validated per N-096).
 *
 * Proves: the behaviour the comments must describe (61ab prologue, separator
 * index 1, chain present on FixedArray leaves) and that the stale sentences
 * are gone. Does not prove: anything about the other tiers' comments.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from '../index.js';

const REPO = join(__dirname, '../../../..');
const SRC = join(__dirname, '..');
const read = (p: string) => readFileSync(p, 'utf8');

describe('GK-DOC-005: the code-separator comments match the emitted layout', () => {
  it('a stateful contract that authenticates _codePart starts with OP_NOP OP_CODESEPARATOR', () => {
    const file = join(REPO, 'examples/ts/stateful-counter/Counter.runar.ts');
    const r = compile(read(file), { fileName: 'Counter.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    expect((r.scriptHex as string).slice(0, 4)).toBe('61ab');
    expect(r.artifact?.codeSeparatorIndex).toBe(1);
  });

  it('neither pass comment places the separator at offset 0', () => {
    const stack = read(join(SRC, 'passes/05-stack-lower.ts'));
    const emit = read(join(SRC, 'passes/06-emit.ts'));
    expect(stack).not.toContain('as the first byte of the locking');
    expect(stack).not.toContain('minus that leading byte');
    expect(emit).not.toContain('`scriptCode == lockingScript[1:]`');
    expect(stack).toContain('lockingScript[2:]');
    expect(emit).toContain('lockingScript[2:]');
  });
});

describe('GK-DOC-006: the syntheticArrayChain comment matches what pass 4 emits', () => {
  it('TS pass 4 emits syntheticArrayChain on FixedArray leaf properties', () => {
    const file = join(REPO, 'examples/ts/fixed-array-index/ArrayIndex.runar.ts');
    const r = compile(read(file), { fileName: 'ArrayIndex.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const chained = (r.anf?.properties ?? []).filter((p) => p.syntheticArrayChain);
    expect(chained.length).toBeGreaterThan(0);
  });

  it('the comment no longer says TS need not emit it', () => {
    const anf = read(join(SRC, 'ir/anf-ir.ts'));
    expect(anf).not.toContain('one tier that need not emit it');
    expect(anf).not.toContain('has no ANF-input mode');
    expect(anf).toMatch(/compileFromANF/);
  });
});

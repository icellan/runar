import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const __dirname = dirname(fileURLToPath(import.meta.url));
const v1Source = readFileSync(join(__dirname, 'TicTacToe.runar.ts'), 'utf8');
const v2Source = readFileSync(join(__dirname, 'TicTacToe.v2.runar.ts'), 'utf8');

describe('TicTacToe v2 (FixedArray) — byte equality', () => {
  it('compiles the hand-rolled v1 contract', () => {
    const result = compile(v1Source, { fileName: 'TicTacToe.runar.ts' });
    if (!result.success) {
      console.error('v1 compile errors:', result.diagnostics);
    }
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(0);
  });

  it('compiles the FixedArray v2 contract', () => {
    const result = compile(v2Source, { fileName: 'TicTacToe.v2.runar.ts' });
    if (!result.success) {
      console.error('v2 compile errors:', result.diagnostics);
    }
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(0);
  });

  it('produces byte-identical script for v1 and v2', () => {
    const v1 = compile(v1Source, { fileName: 'TicTacToe.runar.ts' });
    const v2 = compile(v2Source, { fileName: 'TicTacToe.v2.runar.ts' });
    expect(v1.success).toBe(true);
    expect(v2.success).toBe(true);
    const v1Hex = v1.artifact!.script;
    const v2Hex = v2.artifact!.script;
    // If these diverge, emit a small diff hint.
    if (v1Hex !== v2Hex) {
      const firstDiff = findFirstHexDiff(v1Hex, v2Hex);
      const window = 40;
      const ctx1 = v1Hex.slice(Math.max(0, firstDiff - window), firstDiff + window);
      const ctx2 = v2Hex.slice(Math.max(0, firstDiff - window), firstDiff + window);
      console.error(`first diff at hex offset ${firstDiff}`);
      console.error(`v1: ...${ctx1}...`);
      console.error(`v2: ...${ctx2}...`);
      console.error(`v1 length=${v1Hex.length}  v2 length=${v2Hex.length}`);
    }
    expect(v2Hex).toBe(v1Hex);
  });

  it('v2 ABI exposes Board as a FixedArray state field', () => {
    const v2 = compile(v2Source, { fileName: 'TicTacToe.v2.runar.ts' });
    expect(v2.success).toBe(true);
    const artifact = v2.artifact!;
    const stateFields = artifact.stateFields ?? [];
    const board = stateFields.find(f => f.name === 'board');
    expect(board).toBeDefined();
    expect(board!.fixedArray).toBeDefined();
    expect(board!.fixedArray!.length).toBe(9);
    expect(board!.fixedArray!.elementType).toBe('bigint');
    expect(board!.fixedArray!.syntheticNames).toEqual([
      'board__0', 'board__1', 'board__2',
      'board__3', 'board__4', 'board__5',
      'board__6', 'board__7', 'board__8',
    ]);
  });
});

function findFirstHexDiff(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return i;
  }
  return n;
}

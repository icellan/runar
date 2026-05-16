import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const v1Source = readFileSync(join(__dirname, 'TicTacToe.runar.ts'), 'utf8');
const v2Source = readFileSync(join(__dirname, 'TicTacToe.v2.runar.ts'), 'utf8');

const PLAYER_X = ALICE.pubKey;
const PLAYER_O = BOB.pubKey;
const SIG_X = signTestMessage(ALICE.privKey);
const SIG_O = signTestMessage(BOB.privKey);

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

describe('TicTacToe v2 (FixedArray) — interpreter execution', () => {
  it('move writes this.board[position] and regroups state.board as an array', () => {
    const game = TestContract.fromSource(v2Source, {
      playerX: PLAYER_X,
      betAmount: 1000n,
      playerO: PLAYER_O,
      board: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
      turn: 1n,
      status: 1n,
    }, 'TicTacToe.v2.runar.ts');

    const result = game.call('move', { position: 4n, player: PLAYER_X, sig: SIG_X });
    if (!result.success) console.error('move error:', result.error);
    expect(result.success).toBe(true);

    const board = game.state.board as bigint[];
    expect(Array.isArray(board)).toBe(true);
    expect(board.length).toBe(9);
    expect(board[4]).toBe(1n);
    expect(board[0]).toBe(0n);
    expect(game.state.turn).toBe(2n);
  });

  it('accepts a pre-seeded board and rejects a move on an occupied cell', () => {
    const game = TestContract.fromSource(v2Source, {
      playerX: PLAYER_X,
      betAmount: 1000n,
      playerO: PLAYER_O,
      board: [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
      turn: 2n,
      status: 1n,
    }, 'TicTacToe.v2.runar.ts');

    const occupied = game.call('move', { position: 0n, player: PLAYER_O, sig: SIG_O });
    expect(occupied.success).toBe(false);

    const ok = game.call('move', { position: 1n, player: PLAYER_O, sig: SIG_O });
    expect(ok.success).toBe(true);
    const board = game.state.board as bigint[];
    expect(board[0]).toBe(1n);
    expect(board[1]).toBe(2n);
    expect(game.state.turn).toBe(1n);
  });
});

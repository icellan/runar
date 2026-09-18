// R-208: TicTacToe v2 (the dynamic FixedArray WRITE example) shipped in six
// surfaces and not in this one. This suite pins the new `.runar.sol` file to
// the property that makes a surface port meaningful: it must compile to the
// SAME bytes as the v1 contract beside it and as the TypeScript v2 reference.
//
// INTERPRETER-ONLY, like its TS peer: spendability is covered by
// integration/ts/tic-tac-toe.test.ts, which spends v1 on regtest. Byte equality
// is what carries that coverage over to v2.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const __dirname = dirname(fileURLToPath(import.meta.url));
const here = (f: string) => readFileSync(join(__dirname, f), 'utf8');
const tsDir = join(__dirname, '..', '..', 'ts', 'tic-tac-toe');

const v1Sol = here('TicTacToe.runar.sol');
const v2Sol = here('TicTacToe.v2.runar.sol');
const v2Ts = readFileSync(join(tsDir, 'TicTacToe.v2.runar.ts'), 'utf8');

function scriptOf(source: string, fileName: string): string {
  const result = compile(source, { fileName });
  expect(
    result.success,
    result.diagnostics.map((d) => d.message).join('\n'),
  ).toBe(true);
  return result.artifact!.script;
}

describe('TicTacToe v2 (FixedArray) — Solidity-like surface', () => {
  it('compiles', () => {
    expect(scriptOf(v2Sol, 'TicTacToe.v2.runar.sol').length).toBeGreaterThan(0);
  });

  it('is byte-identical to the hand-rolled v1 contract on the same surface', () => {
    expect(scriptOf(v2Sol, 'TicTacToe.v2.runar.sol')).toBe(
      scriptOf(v1Sol, 'TicTacToe.runar.sol'),
    );
  });

  it('is byte-identical to the TypeScript v2 reference', () => {
    expect(scriptOf(v2Sol, 'TicTacToe.v2.runar.sol')).toBe(
      scriptOf(v2Ts, 'TicTacToe.v2.runar.ts'),
    );
  });
});

/**
 * N-138 — constant folding no longer leaves the folded-away operand behind.
 *
 * With folding ON (the default) `assert(a > -1n)` lowers to
 *   t0 = 1; t1 = -t0; ...; t3 = a > t1
 * The folder rewrites t1 to the constant -1 but t0, now referenced by nothing,
 * survived into stack lowering, which pushed it and then spent ROT/SWAP/NIP
 * dropping it: 51 4f 7b 7c a0 77 instead of 4f a0. Every tier did the same.
 *
 * Each case is one assert whose operands fold, in all seven tiers, in both fold
 * modes. Fold-OFF bytes are pinned to what they were before the fix (the
 * checked-in goldens depend on them); fold-ON bytes are pinned to the hand-
 * decoded minimal script with no dead push:
 *   M1  4f a0                 push -1; GREATERTHAN
 *   M2  01 82 93 00 9c        push -2; ADD; push 0 (this.x placeholder); NUMEQUAL
 *   M3  51 9c 00 9c           a == 1; push false; NUMEQUAL
 *
 * What this proves: for these shapes every tier's fold-ON output has no
 * orphaned operand push and all seven agree byte for byte; fold-OFF output did
 * not move. What it does NOT prove: that no other shape leaves dead bindings
 * behind (folded `if` arms and loop bodies are not pruned; fold-ON scripts
 * that are longer than fold-OFF for other reasons are N-397).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n138-'));

const contract = (name: string, expr: string): string => `import { SmartContract, assert } from 'runar-lang';

class ${name} extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public check(a: bigint) {
    assert(${expr});
  }
}
`;

const CASES = [
  { name: 'M1', expr: 'a > -1n', foldOff: '518fa0', foldOn: '4fa0' },
  { name: 'M2', expr: 'a + -(2n) === this.x', foldOff: '528f93009c', foldOn: '018293009c' },
  { name: 'M3', expr: '(a === 1n) === !true', foldOff: '519c51919c', foldOn: '519c009c' },
];

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

const NATIVE: Record<string, () => { cmd: string; pre: string[]; cwd?: string }> = {
  go: () => ({ cmd: requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'), pre: [] }),
  rust: () => ({ cmd: requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'), pre: [] }),
  python: () => ({ cmd: 'python3', pre: ['-m', 'runar_compiler'], cwd: join(REPO, 'compilers', 'python') }),
  zig: () => ({ cmd: requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'), pre: [] }),
  ruby: () => ({ cmd: 'ruby', pre: ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')] }),
  java: () => ({ cmd: 'java', pre: ['-jar', javaJar()] }),
};

function nativeHex(tier: string, name: string, src: string, fold: boolean): string {
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const dir = mkdtempSync(join(TMP, `${tier}-`));
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${name}.runar.ts`);
  writeFileSync(file, src);
  const r = spawnSync(cmd, [...pre, '--source', file, '--hex', ...(fold ? [] : ['--disable-constant-folding'])], {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  expect(r.status, `${tier} ${name}: ${r.stderr}`).toBe(0);
  return (r.stdout ?? '').trim().split('\n')[0]!.trim();
}

describe('N-138 — folded-away operand bindings are pruned, in every tier', () => {
  for (const c of CASES) {
    const src = contract(c.name, c.expr);

    it(`ts ${c.name} fold-ON has no orphaned push`, () => {
      const r = compile(src, { fileName: `${c.name}.runar.ts` });
      expect(r.artifact?.script).toBe(c.foldOn);
    });
    it(`ts ${c.name} fold-OFF is unchanged`, () => {
      const r = compile(src, { fileName: `${c.name}.runar.ts`, disableConstantFolding: true });
      expect(r.artifact?.script).toBe(c.foldOff);
    });

    for (const tier of Object.keys(NATIVE)) {
      it(`${tier} ${c.name} fold-ON has no orphaned push`, () => {
        expect(nativeHex(tier, c.name, src, true)).toBe(c.foldOn);
      });
      it(`${tier} ${c.name} fold-OFF is unchanged`, () => {
        expect(nativeHex(tier, c.name, src, false)).toBe(c.foldOff);
      });
    }
  }
});

/**
 * N-005 — execution proof, all seven tiers: an assert() that is followed by a
 * terminal asm() is enforced on chain.
 *
 *     class AssertThenAsm extends UnsafeSmartContract {
 *       public unlock(x: bigint) {
 *         assert(x === 42n);
 *         asm({ body: '51', in_arity: 0, out_arity: 1 });
 *       }
 *     }
 *
 * Stack lowering treated the LAST assert of a public method as the terminal
 * one (no OP_VERIFY, its value is the script's result) even when bindings
 * followed it. Here the asm pushed OP_1 on top and the end-of-method cleanup
 * NIPped the comparison away, so every tier emitted
 *
 *     012a9c5177   <42> OP_NUMEQUAL OP_1 OP_NIP
 *
 * and ANY x unlocked the coins. The fix: only an assert that is the last
 * binding may leave its value; any other assert is lowered with OP_VERIFY.
 * The expected script is derived by hand from the source:
 *
 *     012a9d51     <42> OP_NUMEQUALVERIFY OP_1
 *
 * (OP_NUMEQUAL OP_VERIFY fused by the peephole pass every tier ships.)
 *
 * Oracle: the real `@bsv/sdk` Spend engine — never TestContract or the ANF
 * interpreter, which share the compiler's model. Verdicts are derived by hand.
 *
 * What this proves: for each of the seven tiers, in both constant-folding
 * modes, the compiled script rejects the crafted x = 7 (which the pre-fix
 * script accepted) and accepts x = 42, and every tier emits the same bytes.
 * The if-arm variant (assert then asm inside both arms of a terminal `if`) is
 * pinned the same way for the TS tier.
 * What it does NOT prove: anything about asm bodies with in_arity > 0 that
 * reach below the stack slots the compiler tracks — the asm contract makes
 * those the author's responsibility.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { LockingScript, UnlockingScript, Spend } from '@bsv/sdk';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n005-'));
const FILE = 'AssertThenAsm.runar.ts';

const SOURCE = `import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AssertThenAsm extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === 42n);
    asm({ body: '51', in_arity: 0, out_arity: 1 });
  }
}
`;

// Both arms end assert-then-asm; the `if` is the method's terminal binding,
// so each arm is lowered in terminal mode and hits the same rule.
const IF_SOURCE = `import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AssertThenAsmIf extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint, y: bigint) {
    if (y > 0n) {
      assert(x === 42n);
      asm({ body: '51', in_arity: 0, out_arity: 1 });
    } else {
      assert(x === 43n);
      asm({ body: '51', in_arity: 0, out_arity: 1 });
    }
  }
}
`;

const PRE_FIX_HEX = '012a9c5177';
const EXPECTED_HEX = '012a9d51';

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

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

const FOLD_OFF = ['--disable-constant-folding'];

/** Each tier's locking-script hex for SOURCE; `fold` selects the folding mode. */
const TIERS: { name: string; script: (fold: boolean) => string }[] = [
  {
    name: 'ts',
    script: (fold) => {
      const r = compile(SOURCE, { fileName: FILE, disableConstantFolding: !fold });
      if (!r.success || !r.scriptHex) throw new Error(JSON.stringify(r.diagnostics));
      return r.scriptHex;
    },
  },
  {
    name: 'go',
    script: (fold) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(FILE, SOURCE), ...(fold ? [] : FOLD_OFF)],
    )).script,
  },
  {
    name: 'rust',
    script: (fold) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(FILE, SOURCE), ...(fold ? [] : FOLD_OFF)],
    )).script,
  },
  {
    name: 'python',
    script: (fold) => JSON.parse(run(
      'python3',
      ['-m', 'runar_compiler', '--source', writeTmp(FILE, SOURCE), ...(fold ? [] : FOLD_OFF)],
      join(REPO, 'compilers', 'python'),
    )).script,
  },
  {
    name: 'zig',
    script: (fold) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', writeTmp(FILE, SOURCE), ...(fold ? [] : FOLD_OFF)],
    )).script,
  },
  {
    name: 'ruby',
    script: (fold) => JSON.parse(run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(FILE, SOURCE), ...(fold ? [] : FOLD_OFF),
    ])).script,
  },
  {
    name: 'java',
    script: (fold) => {
      const out = writeTmp('artifact.json', '');
      run('java', ['-jar', javaJar(), '--source', writeTmp(FILE, SOURCE), '--emit-artifact', out, ...(fold ? [] : FOLD_OFF)]);
      return JSON.parse(readFileSync(out, 'utf8')).script;
    },
  },
];

/** Run `unlockingHex` against `lockingHex` on the real Spend engine. */
function spends(lockingHex: string, unlockingHex: string): boolean {
  try {
    const spend = new Spend({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: 100000,
      lockingScript: LockingScript.fromHex(lockingHex),
      transactionVersion: 2,
      otherInputs: [],
      outputs: [],
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      inputIndex: 0,
      inputSequence: 0xffffffff,
      lockTime: 0,
    });
    return spend.validate();
  } catch {
    return false;
  }
}

// Minimal pushes: 42 = PUSH1 0x2a, 7 = OP_7, 43 = PUSH1 0x2b, 1 = OP_1, 0 = OP_0.
const X42 = '012a';
const X7 = '57';

describe('N-005 — assert followed by a terminal asm() is enforced', () => {
  it('the harness itself distinguishes: the pre-fix bytes accept the crafted x = 7', () => {
    // Non-vacuity control: the engine really does accept the attack against
    // the pre-fix script, so a reject below is the fix, not the harness.
    expect(spends(PRE_FIX_HEX, X7)).toBe(true);
    expect(spends(PRE_FIX_HEX, X42)).toBe(true);
  });

  for (const tier of TIERS) {
    for (const fold of [false, true]) {
      it(`${tier.name} (fold ${fold ? 'ON' : 'OFF'}): rejects x = 7, accepts x = 42`, () => {
        const hex = tier.script(fold);
        expect(hex).not.toBe(PRE_FIX_HEX);
        expect(spends(hex, X7)).toBe(false);
        expect(spends(hex, X42)).toBe(true);
        expect(hex).toBe(EXPECTED_HEX);
      });
    }
  }

  it('ts: assert-then-asm inside the arms of a terminal if is enforced per arm', () => {
    const r = compile(IF_SOURCE, { fileName: 'AssertThenAsmIf.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const hex = r.scriptHex!;
    // Unlocking pushes params in declaration order: x then y.
    expect(spends(hex, X7 + '51')).toBe(false); // then-arm, wrong x
    expect(spends(hex, X42 + '51')).toBe(true); // then-arm, right x
    expect(spends(hex, X7 + '00')).toBe(false); // else-arm, wrong x
    expect(spends(hex, '012b' + '00')).toBe(true); // else-arm, right x
    expect(spends(hex, X42 + '00')).toBe(false); // else-arm demands 43
  });
});

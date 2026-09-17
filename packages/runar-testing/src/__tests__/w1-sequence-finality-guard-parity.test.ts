/**
 * W1 / FinalCountdown, validator half — `02-validate.ts` #131 named, in its own
 * warning text, the check an author should write, and named the one the
 * unpadded `OP_BIN2NUM` decode made TRUE for the finality sentinel:
 *
 *     assert(extractSequence(this.txPreimage) < 0xffffffffn)
 *
 * It also accepted `<= 0xffffffff` as a finality guard. That one is a tautology
 * under ANY decode — nSequence cannot exceed 0xffffffff — so it silenced the
 * warning on a contract with no guard at all.
 *
 * Seven compilers ship that diagnostic. This file drives every one of them
 * through its real CLI and requires the same verdict and the same text, so a
 * tier left on the old rule fails here rather than diverging unnoticed. A
 * missing toolchain FAILS rather than skips.
 *
 * The lowering half — that `extractSequence` of `ffffffff` is 4294967295 and
 * that the report's vault PoC is rejected by `@bsv/sdk`'s `Spend.validate()` —
 * lives in `w1-unsigned-preimage-fields.test.ts`.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';

/**
 * The lowering half of W1 is only half the bug. `02-validate.ts` #131 named,
 * in its own warning text, the check an author should write — and named the
 * one the unpadded decode made true for the finality sentinel. It also
 * accepted `<= 0xffffffff` as a finality guard, which is a tautology under
 * ANY decode (nSequence cannot exceed it) and so silenced the warning on a
 * contract with no guard at all.
 *
 * Seven compilers ship that diagnostic. This block drives every one of them
 * through the real CLI and requires the same verdict and the same text, so a
 * tier left on the old rule is a failure rather than an unnoticed divergence.
 * A missing toolchain FAILS rather than skips.
 */

const NEEDLE = 'reads extractLocktime but does not assert';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-w1-'));

function writeTmp(name: string, src: string): string {
  const p = join(TMP, name);
  writeFileSync(p, src);
  return p;
}

/** Run a compiler CLI and return stdout+stderr together. A warning is not an
 *  error, so a non-zero exit is still captured rather than thrown away. */
function runCombined(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, {
    cwd,
    timeout: 120_000,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `./gradlew jar` in compilers/java');
  return join(libs, jar);
}

let diagSeq = 0;
const FILE = 'W1Warn.runar.ts';

const DIAG_TIERS: { name: string; diagnostics: (src: string) => string }[] = [
  {
    name: 'ts',
    diagnostics: (src) =>
      compile(src, { fileName: FILE })
        .diagnostics.map((d) => `${d.severity}: ${d.message}`)
        .join('\n'),
  },
  {
    name: 'go',
    diagnostics: (src) =>
      runCombined(
        requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
        ['--source', writeTmp(`go-${diagSeq++}-${FILE}`, src), '--hex'],
      ),
  },
  {
    name: 'rust',
    diagnostics: (src) =>
      runCombined(
        requireBin(
          join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
          'cd compilers/rust && cargo build --release',
        ),
        ['--source', writeTmp(`rs-${diagSeq++}-${FILE}`, src), '--hex'],
      ),
  },
  {
    name: 'python',
    diagnostics: (src) =>
      runCombined(
        'python3',
        ['-m', 'runar_compiler', '--source', writeTmp(`py-${diagSeq++}-${FILE}`, src), '--hex'],
        join(REPO, 'compilers', 'python'),
      ),
  },
  {
    name: 'zig',
    diagnostics: (src) =>
      runCombined(
        requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
        ['--source', writeTmp(`zig-${diagSeq++}-${FILE}`, src), '--hex'],
      ),
  },
  {
    name: 'ruby',
    diagnostics: (src) =>
      runCombined('ruby', [
        '-I',
        join(REPO, 'compilers', 'ruby', 'lib'),
        join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
        '--source',
        writeTmp(`rb-${diagSeq++}-${FILE}`, src),
        '--hex',
      ]),
  },
  {
    name: 'java',
    diagnostics: (src) =>
      runCombined('java', ['-jar', javaJar(), '--source', writeTmp(`java-${diagSeq++}-${FILE}`, src), '--hex']),
  },
];

/** A stateful timelock whose `unlock` body is `guard` plus the locktime gate. */
function warnSource(guard: string): string {
  return `import { StatefulSmartContract, assert, extractLocktime, extractSequence } from 'runar-lang';

export class W1Warn extends StatefulSmartContract {
  count: bigint;
  readonly deadline: bigint;
  constructor(count: bigint, deadline: bigint) {
    super(count, deadline);
    this.count = count;
    this.deadline = deadline;
  }
  public unlock() {
    ${guard}
    assert(extractLocktime(this.txPreimage) >= this.deadline);
    this.count = this.count + 1n;
  }
}
`;
}

const NO_GUARD = warnSource('');
const REAL_GUARD = warnSource('assert(extractSequence(this.txPreimage) !== 0xffffffffn);');
const TAUTOLOGY = warnSource('assert(extractSequence(this.txPreimage) <= 0xffffffffn);');

describe('W1 — #131 stops recommending (and accepting) the broken guard', () => {
  it('the TypeScript diagnostic recommends `!==` and never `< 0xffffffffn`', () => {
    const d = compile(NO_GUARD, { fileName: 'W1Warn.runar.ts' }).diagnostics;
    const w = d.find((x) => x.message.includes(NEEDLE));
    expect(w, 'no #131 warning was emitted at all').toBeDefined();
    expect(w!.message).not.toContain('< 0xffffffffn');
    expect(w!.message).toContain('!== 0xffffffffn');
  });

  it('a real `!==` guard silences it; the `<=` tautology does NOT', () => {
    const warns = (src: string) =>
      compile(src, { fileName: 'W1Warn.runar.ts' }).diagnostics.some((x) =>
        x.message.includes(NEEDLE),
      );
    expect(warns(REAL_GUARD), '`!== 0xffffffffn` should be accepted as a guard').toBe(false);
    expect(warns(TAUTOLOGY), '`<= 0xffffffffn` is a tautology, not a guard').toBe(true);
  });

  it('all seven tiers agree on the verdict and on the text', () => {
    const cases: { label: string; src: string; warns: boolean }[] = [
      { label: 'no guard', src: NO_GUARD, warns: true },
      { label: '!== sentinel', src: REAL_GUARD, warns: false },
      { label: '<= sentinel (tautology)', src: TAUTOLOGY, warns: true },
    ];
    for (const c of cases) {
      for (const tier of DIAG_TIERS) {
        const out = tier.diagnostics(c.src);
        const warned = out.includes(NEEDLE);
        expect(warned, `${tier.name} disagrees on "${c.label}":\n${out}`).toBe(c.warns);
        if (warned) {
          expect(out, `${tier.name} still recommends the pre-W1 guard`).not.toContain(
            '< 0xffffffffn',
          );
          expect(out, `${tier.name} does not recommend the new guard`).toContain(
            '!== 0xffffffffn',
          );
        }
      }
    }
  });
});
